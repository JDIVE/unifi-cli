from __future__ import annotations

import argparse
import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from unifi_cli.cli import build_parser, main
from unifi_cli.config import Config, build_config
from unifi_cli.core import (
    REDACTED,
    UniFiClient,
    UniFiError,
    count_collection,
    exit_code_for_error,
    scrub_sensitive,
    strip_read_only,
)


def clear_unifi_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in [
        "UNIFI_API_KEY",
        "UNIFI_NETWORK_API_KEY",
        "UNIFI_BASE_URL",
        "UNIFI_NETWORK_BASE_URL",
        "UNIFI_SITE",
        "UNIFI_SITE_ID",
        "UNIFI_VERIFY_TLS",
        "UNIFI_TIMEOUT_SECONDS",
    ]:
        monkeypatch.delenv(env_name, raising=False)


def test_help_mentions_core_commands() -> None:
    help_text = build_parser().format_help()
    assert "doctor" in help_text
    assert "summary" in help_text
    assert "request" in help_text


def test_doctor_json_without_config_reports_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    clear_unifi_env(monkeypatch)

    exit_code = main(["--json", "doctor"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["missing"] == ["UNIFI_BASE_URL", "UNIFI_API_KEY"]


def test_build_config_accepts_legacy_env_aliases(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    clear_unifi_env(monkeypatch)
    monkeypatch.setenv("UNIFI_NETWORK_BASE_URL", "https://legacy-controller.local/")
    monkeypatch.setenv("UNIFI_NETWORK_API_KEY", "secret")

    args = argparse.Namespace(
        api_key=None,
        base_url=None,
        config=None,
        insecure=False,
        site=None,
        site_id=None,
        timeout_seconds=None,
    )
    config = build_config(args)

    assert config.base_url == "https://legacy-controller.local"
    assert config.api_key == "secret"
    assert config.sources["base_url"] == "env:UNIFI_NETWORK_BASE_URL"
    assert config.sources["api_key"] == "env:UNIFI_NETWORK_API_KEY"


def test_raw_post_without_yes_returns_dry_run_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "raw",
            "--method",
            "POST",
            "/proxy/network/api/s/default/rest/wlanconf",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"


def test_device_adopt_without_yes_returns_official_dry_run_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "device-adopt",
            "--mac-address",
            "00:11:22:33:44:55",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["path"] == "/proxy/network/integration/v1/sites/site-1/devices"
    assert payload["request"]["payload"] == {
        "ignoreDeviceLimit": False,
        "macAddress": "00:11:22:33:44:55",
    }


def test_vouchers_delete_requires_filter_and_returns_dry_run_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "vouchers-delete",
            "--filter",
            "name.eq('guest')",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "DELETE"
    assert (
        payload["request"]["path"] == "/proxy/network/integration/v1/sites/site-1/hotspot/vouchers?"
        "filter=name.eq%28%27guest%27%29"
    )
    assert payload["request"]["payload"] is None


def test_connector_write_without_yes_returns_cloud_dry_run_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--api-key",
            "secret",
            "connector-post",
            "console-1",
            "network/integration/v1/sites",
            "--data-json",
            "{}",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    assert (
        payload["request"]["path"]
        == "https://api.ui.com/v1/connector/consoles/console-1/network/integration/v1/sites"
    )
    assert payload["request"]["payload"] == {}


def test_firewall_policy_reorder_includes_required_zone_query(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_find_official(
        self: UniFiClient,
        resource: str,
        selector: str,
        *,
        record_type: str | None = None,
    ) -> dict[str, str]:
        del self, resource, record_type
        return {"id": f"{selector}-id"}

    monkeypatch.setattr(UniFiClient, "find_official", fake_find_official)

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "firewall-policy-reorder",
            "--source-zone",
            "internal",
            "--destination-zone",
            "external",
            "--data-json",
            '{"orderedFirewallPolicyIds":[]}',
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "PUT"
    assert (
        payload["request"]["path"]
        == "/proxy/network/integration/v1/sites/site-1/firewall/policies/ordering?"
        "sourceFirewallZoneId=internal-id&destinationFirewallZoneId=external-id"
    )


def test_network_delete_force_is_reflected_in_dry_run_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: {"id": "network-1", "name": selector},
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "network-delete",
            "Home",
            "--force",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert (
        payload["request"]["path"]
        == "/proxy/network/integration/v1/sites/site-1/networks/network-1?force=true"
    )


def test_network_references_falls_back_after_official_500(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    network = {"id": "network-1", "name": "Home", "vlanId": 40}

    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: network,
    )

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs):
        del self, method, kwargs
        if suffix.endswith("/references"):
            raise UniFiError(
                "official references failed",
                code="http_error",
                details={"status": 500, "body": "Unexpected error"},
            )
        if suffix.endswith("/wifi/broadcasts"):
            return {
                "data": [
                    {
                        "enabled": True,
                        "id": "wifi-1",
                        "name": "Downies",
                        "network": {"networkId": "network-1"},
                    }
                ]
            }
        raise AssertionError(f"unexpected official suffix {suffix}")

    def fake_legacy(self: UniFiClient, method: str, suffix: str, **kwargs):
        del self, method, kwargs
        if suffix == "/rest/networkconf":
            return {"data": [{"_id": "legacy-network-1", "name": "Home", "vlan": 40}]}
        if suffix == "/stat/device":
            return {
                "data": [
                    {
                        "_id": "device-1",
                        "name": "Switch",
                        "port_table": [
                            {
                                "name": "Port 1",
                                "port_idx": 1,
                                "portconf_id": "port-profile-1",
                            }
                        ],
                    }
                ]
            }
        raise AssertionError(f"unexpected legacy suffix {suffix}")

    monkeypatch.setattr(UniFiClient, "official", fake_official)
    monkeypatch.setattr(UniFiClient, "legacy", fake_legacy)
    monkeypatch.setattr(
        UniFiClient,
        "list_legacy_fallback",
        lambda self, resource: {
            "data": [
                {
                    "_id": "port-profile-1",
                    "name": "Downies",
                    "native_networkconf_id": "legacy-network-1",
                }
            ]
        },
    )
    monkeypatch.setattr(
        UniFiClient,
        "remembered_clients",
        lambda self: [
            {
                "_id": "client-1",
                "fixed_ip": "10.1.40.22",
                "last_connection_network_id": "legacy-network-1",
                "local_dns_record": "laptop.example",
                "local_dns_record_enabled": True,
                "mac": "00:11:22:33:44:55",
                "name": "Laptop",
                "use_fixedip": True,
            }
        ],
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "network-references",
            "Home",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["fallback"]["reason"] == "official_network_references_failed"
    assert payload["network"]["legacyNetworkconfId"] == "legacy-network-1"
    assert [item["resourceType"] for item in payload["referenceResources"]] == [
        "WIFI",
        "LEGACY_PORT_PROFILE",
        "LEGACY_SWITCH_PORT",
        "CLIENT",
    ]


def test_doctor_json_with_mocked_live_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    clear_unifi_env(monkeypatch)
    monkeypatch.setattr(
        UniFiClient,
        "official",
        lambda self, method, suffix, **kwargs: (
            {"applicationVersion": "10.3.58"}
            if suffix == "/info"
            else {"data": [{"id": "site-1", "name": "default"}]}
        ),
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "doctor",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["live_check"]["ok"] is True
    assert payload["live_check"]["resolved_site_id"] == "site-1"


def test_json_error_shape_for_missing_live_config(
    capsys: pytest.CaptureFixture[str], tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    clear_unifi_env(monkeypatch)
    exit_code = main(["--json", "sites"])
    payload = json.loads(capsys.readouterr().out)

    # config_missing maps to the configuration/auth exit code (3) under the
    # exit-code contract.
    assert exit_code == 3
    assert payload["ok"] is False
    assert payload["error"]["code"] == "config_missing"


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FakeResponse:
    """Minimal stand-in for the urllib response context manager."""

    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def make_client(**overrides: object) -> UniFiClient:
    base = {
        "base_url": "https://controller.example",
        "site": "default",
        "site_id": "site-1",
        "api_key": "controller-key",
        "cloud_api_key": None,
        "verify_tls": True,
        "timeout_seconds": 5,
        "allow_foreign_host": False,
        "config_path": Path("/nonexistent/config.toml"),
        "config_exists": False,
        "sources": {},
    }
    base.update(overrides)
    return UniFiClient(Config(**base))  # type: ignore[arg-type]


def envelope(data: list[dict[str, object]], total_count: int) -> dict[str, object]:
    return {
        "offset": 0,
        "limit": len(data),
        "count": len(data),
        "totalCount": total_count,
        "data": data,
    }


# ---------------------------------------------------------------------------
# (a) merge dry-run strips read-only fields, and --set id=x is rejected
# ---------------------------------------------------------------------------


def test_merge_dry_run_strips_read_only_fields(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: {
            "id": "net-1",
            "metadata": {"origin": "USER_DEFINED"},
            "revision": 7,
            "createdAt": "2026-01-01",
            "name": "Home",
            "enabled": True,
        },
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "network-merge",
            "Home",
            "--set",
            "enabled=false",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    body = payload["request"]["payload"]
    assert body == {"name": "Home", "enabled": False}
    for read_only in ("id", "metadata", "revision", "createdAt"):
        assert read_only not in body


def test_merge_rejects_set_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: {"id": "net-1", "name": "Home"},
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "network-merge",
            "Home",
            "--set",
            "id=hacked",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["error"]["code"] == "invalid_argument"


def test_merge_rejects_set_metadata_prefix(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: {"id": "net-1", "name": "Home"},
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "network-merge",
            "Home",
            "--set",
            "metadata.origin=SYSTEM",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["error"]["code"] == "invalid_argument"


def test_strip_read_only_helper() -> None:
    stripped = strip_read_only(
        {
            "id": "x",
            "metadata": {},
            "statistics": {},
            "createdAt": "a",
            "updatedAt": "b",
            "revision": 1,
            "name": "keep",
        }
    )
    assert stripped == {"name": "keep"}


# ---------------------------------------------------------------------------
# (b) dns-upsert update path strips id
# ---------------------------------------------------------------------------


def test_dns_upsert_update_strips_read_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_official",
        lambda self, resource, selector, **kwargs: {
            "id": "dns-1",
            "metadata": {"origin": "USER_DEFINED"},
            "domain": "nas.example",
            "type": "A_RECORD",
            "ipv4Address": "10.0.0.9",
        },
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "dns-upsert",
            "--domain",
            "nas.example",
            "--record-type",
            "A_RECORD",
            "--value",
            "10.0.0.10",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    body = payload["request"]["payload"]
    assert "id" not in body
    assert "metadata" not in body
    assert body["ipv4Address"] == "10.0.0.10"
    assert payload["request"]["method"] == "PUT"


# ---------------------------------------------------------------------------
# (c) find_official resolves across two pages, exact match on page 2 wins
# ---------------------------------------------------------------------------


def test_find_official_resolves_across_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        envelope([{"id": "a", "name": "home-lab"}], total_count=2),
        envelope([{"id": "b", "name": "home"}], total_count=2),
    ]

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, suffix
        offset = kwargs["query"]["offset"]
        return pages[0] if offset == 0 else pages[1]

    monkeypatch.setattr(UniFiClient, "official", fake_official)
    client = make_client()
    match = client.find_official("network", "home")
    # Exact match ("home" on page 2) wins over partial match ("home-lab").
    assert match["id"] == "b"


# ---------------------------------------------------------------------------
# (d) list --all aggregates pages into a synthetic envelope
# ---------------------------------------------------------------------------


def test_list_all_aggregates_pages(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pages = [
        envelope([{"id": "n1"}], total_count=3),
        envelope([{"id": "n2"}], total_count=3),
        envelope([{"id": "n3"}], total_count=3),
    ]

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, suffix
        offset = kwargs["query"]["offset"]
        index = min(offset, len(pages) - 1)
        return pages[index]

    monkeypatch.setattr(UniFiClient, "official", fake_official)

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "networks",
            "--all",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["count"] == 3
    assert payload["totalCount"] == 3
    assert payload["offset"] == 0
    assert payload["limit"] == 3
    assert [item["id"] for item in payload["data"]] == ["n1", "n2", "n3"]


def test_list_all_raw_path_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # clients is a raw-path list command (not a resource collection).
    pages = [
        envelope([{"id": "c1"}, {"id": "c2"}], total_count=2),
    ]

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, kwargs
        assert suffix.endswith("/clients")
        return pages[0]

    monkeypatch.setattr(UniFiClient, "official", fake_official)

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "clients",
            "--all",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["count"] == 2
    assert [item["id"] for item in payload["data"]] == ["c1", "c2"]


# ---------------------------------------------------------------------------
# (e) count_collection prefers totalCount
# ---------------------------------------------------------------------------


def test_count_collection_prefers_total_count() -> None:
    assert count_collection(envelope([{"id": "a"}], total_count=42)) == 42
    # Falls back to len(data) when totalCount is absent.
    assert count_collection({"data": [{"id": "a"}, {"id": "b"}]}) == 2
    # Ignores a bool masquerading as an int totalCount.
    assert count_collection({"data": [{"id": "a"}], "totalCount": True}) == 1
    # Falls back to count when there is no data list.
    assert count_collection({"count": 5}) == 5


# ---------------------------------------------------------------------------
# (f) exit_code_for_error table-driven test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "status", "expected"),
    [
        ("config_missing", None, 3),
        ("http_error", 401, 3),
        ("http_error", 403, 3),
        ("not_found", None, 4),
        ("ambiguous_selector", None, 4),
        ("http_error", 500, 5),
        ("http_error", 503, 5),
        ("network_error", None, 6),
        ("timeout", None, 6),
        ("http_error", 404, 1),
        ("response_shape", None, 1),
        ("invalid_argument", None, 1),
        ("foreign_host_blocked", None, 1),
    ],
)
def test_exit_code_for_error(code: str, status: int | None, expected: int) -> None:
    details = {"status": status} if status is not None else None
    assert exit_code_for_error(UniFiError("boom", code=code, details=details)) == expected


# ---------------------------------------------------------------------------
# (g) TimeoutError -> timeout -> exit 6; unexpected exception -> exit 70
# ---------------------------------------------------------------------------


def test_request_timeout_maps_to_exit_6(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_urlopen(*args: object, **kwargs: object) -> object:
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "app-info",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 6
    assert payload["error"]["code"] == "timeout"
    assert payload["error"]["details"]["timeout_seconds"] == 30


def test_unexpected_exception_maps_to_exit_70(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(self: UniFiClient, _args: argparse.Namespace) -> object:
        raise ValueError("kaboom")

    # A command handler raising a non-UniFiError surfaces as unexpected_error.
    monkeypatch.setattr(UniFiClient, "summary", lambda self: boom(self, None))

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "summary",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 70
    assert payload["error"]["code"] == "unexpected_error"
    assert payload["error"]["details"]["exception"] == "ValueError"


# ---------------------------------------------------------------------------
# (h) scrub_sensitive redaction + HTTPError JSON body scrubbing
# ---------------------------------------------------------------------------


def test_scrub_sensitive_substring_and_nested() -> None:
    scrubbed = scrub_sensitive(
        {
            "preSharedKey": "abc",
            "sharedSecret": "def",
            "radiusSecret": "ghi",
            "wpaPassphrase": "jkl",
            "name": "keep",
            "nested": [{"apiKey": "zzz", "value": "keep"}],
        }
    )
    assert scrubbed["preSharedKey"] == REDACTED
    assert scrubbed["sharedSecret"] == REDACTED
    assert scrubbed["radiusSecret"] == REDACTED
    assert scrubbed["wpaPassphrase"] == REDACTED
    assert scrubbed["name"] == "keep"
    assert scrubbed["nested"][0]["apiKey"] == REDACTED
    assert scrubbed["nested"][0]["value"] == "keep"


def test_http_error_json_body_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    error_body = json.dumps({"message": "bad", "token": "leak-me"}).encode("utf-8")

    def fake_urlopen(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError(
            url="https://controller.example/x",
            code=400,
            msg="Bad Request",
            hdrs={},  # type: ignore[arg-type]
            fp=io.BytesIO(error_body),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client()

    with pytest.raises(UniFiError) as excinfo:
        client.official("GET", "/info")

    details = excinfo.value.details or {}
    assert details["status"] == 400
    assert isinstance(details["body"], dict)
    assert details["body"]["token"] == REDACTED
    assert details["body"]["message"] == "bad"


def test_http_error_non_json_body_is_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    long_body = ("x" * 5000).encode("utf-8")

    def fake_urlopen(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError(
            url="https://controller.example/x",
            code=500,
            msg="Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=io.BytesIO(long_body),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client()

    with pytest.raises(UniFiError) as excinfo:
        client.official("GET", "/info")

    details = excinfo.value.details or {}
    assert isinstance(details["body"], str)
    assert len(details["body"]) == 2000


# ---------------------------------------------------------------------------
# (i) foreign-host block, --allow-foreign-host override, cloud key selection
# ---------------------------------------------------------------------------


def test_foreign_host_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_urlopen(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        return FakeResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client()

    with pytest.raises(UniFiError) as excinfo:
        client.request("GET", "https://evil.example/steal")

    assert excinfo.value.code == "foreign_host_blocked"
    assert called is False


def test_allow_foreign_host_override(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, **kwargs: object) -> object:
        captured["key"] = request.headers.get("X-api-key")  # type: ignore[attr-defined]
        return FakeResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client(allow_foreign_host=True)

    client.request("GET", "https://evil.example/ok")
    assert captured["key"] == "controller-key"


def test_cloud_key_used_for_cloud_host(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, **kwargs: object) -> object:
        captured["key"] = request.headers.get("X-api-key")  # type: ignore[attr-defined]
        return FakeResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client(cloud_api_key="cloud-key")

    client.request("GET", "https://api.ui.com/v1/connector/consoles")
    assert captured["key"] == "cloud-key"


def test_controller_key_used_when_no_cloud_key(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, **kwargs: object) -> object:
        captured["key"] = request.headers.get("X-api-key")  # type: ignore[attr-defined]
        return FakeResponse(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client(cloud_api_key=None)

    client.request("GET", "https://api.ui.com/v1/connector/consoles")
    assert captured["key"] == "controller-key"


def test_connector_command_reaches_cloud_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, **kwargs: object) -> object:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["key"] = request.headers.get("X-api-key")  # type: ignore[attr-defined]
        return FakeResponse(b'{"data": []}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    exit_code = main(
        [
            "--json",
            "--api-key",
            "controller-key",
            "connector-get",
            "console-1",
            "network/integration/v1/sites",
        ]
    )

    assert exit_code == 0
    assert str(captured["url"]).startswith("https://api.ui.com/")
    assert captured["key"] == "controller-key"


# ---------------------------------------------------------------------------
# (j) legacy merge with missing _id/id raises response_shape
# ---------------------------------------------------------------------------


def test_legacy_merge_missing_id_raises_response_shape(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        UniFiClient,
        "find_legacy_fallback",
        lambda self, resource, selector: {"name": "orphan"},
    )

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "legacy-fallback-merge",
            "port-forward",
            "orphan",
            "--set",
            "enabled=false",
            "--yes",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["error"]["code"] == "response_shape"


# ---------------------------------------------------------------------------
# (k) --version prints the version
# ---------------------------------------------------------------------------


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    from unifi_cli import __version__

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


# ---------------------------------------------------------------------------
# (l) doctor reports permissions_ok false for a 0644 config file
# ---------------------------------------------------------------------------


def test_doctor_reports_bad_config_permissions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    clear_unifi_env(monkeypatch)
    config_file = tmp_path / "config.toml"
    config_file.write_text('base_url = "https://controller.example"\napi_key = "secret"\n')
    config_file.chmod(0o644)

    # Avoid a live check by leaving the network unreachable through a mocked official().
    monkeypatch.setattr(
        UniFiClient,
        "official",
        lambda self, method, suffix, **kwargs: (
            {"applicationVersion": "10.4.57"}
            if suffix == "/info"
            else {"data": [{"id": "site-1", "name": "default"}]}
        ),
    )

    exit_code = main(["--json", "--config", str(config_file), "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["config_file"]["permissions_ok"] is False
    assert payload["config_file"]["mode"] == "0644"
    # A bad-permissions warning must not flip overall ok to false on its own.
    assert exit_code == 0
    assert payload["ok"] is True
