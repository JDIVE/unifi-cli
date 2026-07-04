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
    TABLE_SPECS,
    TableColumn,
    UniFiClient,
    UniFiError,
    build_schema,
    count_collection,
    exit_code_for_error,
    format_list_table,
    render_table,
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


# ---------------------------------------------------------------------------
# (m) schema command: valid JSON, exit codes, write flags, offline
# ---------------------------------------------------------------------------


def test_schema_command_emits_valid_json(
    capsys: pytest.CaptureFixture[str], tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # schema is fully offline: no config, no base URL, no API key required.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    clear_unifi_env(monkeypatch)

    exit_code = main(["schema"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["name"] == "unifi"
    assert set(payload["exit_codes"]) == {"0", "1", "2", "3", "4", "5", "6", "70"}
    assert payload["exit_codes"]["0"].startswith("success")
    assert payload["exit_codes"]["2"] == "usage error"
    assert "error" in payload["error_shape"]
    assert payload["dry_run_shape"]["status"] == "dry-run"

    commands = {command["name"]: command for command in payload["commands"]}
    # A read command has write=false; a write command has write=true.
    assert commands["networks"]["write"] is False
    assert commands["network-merge"]["write"] is True
    assert commands["schema"]["write"] is False
    # Aliases are surfaced without duplicating them as separate commands.
    assert commands["wifi-broadcasts"]["aliases"] == ["wlans"]
    assert "wlans" not in commands


def test_schema_build_directly_marks_writes_via_yes_guard() -> None:
    schema = build_schema(build_parser())
    commands = {command["name"]: command for command in schema["commands"]}
    # Newly-added commands report the expected write classification.
    assert commands["dns-merge"]["write"] is True
    assert commands["reservation-create"]["write"] is True
    assert commands["legacy-fallback-create"]["write"] is True
    assert commands["switch-lags"]["write"] is False
    assert commands["switch-lag-show"]["write"] is False
    # The --yes guard argument is folded into `write`, not exposed as an argument.
    merge_args = {arg["name"] for arg in commands["network-merge"]["arguments"]}
    assert "yes" not in merge_args


# ---------------------------------------------------------------------------
# (n) new item shows resolve by name through find_official
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "resource_name", "collection_suffix"),
    [
        ("wan-show", "wan", "/wans"),
        ("radius-profile-show", "radius-profile", "/radius/profiles"),
        ("device-tag-show", "device-tag", "/device-tags"),
        ("vpn-server-show", "vpn-server", "/vpn/servers"),
        ("site-to-site-vpn-show", "site-to-site-vpn", "/vpn/site-to-site-tunnels"),
        ("switch-lag-show", "switch-lag", "/switching/lags"),
        ("mc-lag-domain-show", "mc-lag-domain", "/switching/mc-lag-domains"),
        ("switch-stack-show", "switch-stack", "/switching/switch-stacks"),
    ],
)
def test_new_show_commands_resolve_by_name(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    resource_name: str,
    collection_suffix: str,
) -> None:
    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, kwargs
        assert suffix.endswith(collection_suffix)
        return envelope([{"id": "obj-1", "name": "target"}], total_count=1)

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
            command,
            "target",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["id"] == "obj-1"
    assert payload["name"] == "target"


# ---------------------------------------------------------------------------
# (o) switch-lags list hits the right path
# ---------------------------------------------------------------------------


def test_switch_lags_list_hits_right_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, str] = {}

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, kwargs
        seen["suffix"] = suffix
        return envelope([{"id": "lag-1", "name": "core"}], total_count=1)

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
            "switch-lags",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen["suffix"] == "/sites/site-1/switching/lags"
    assert [item["id"] for item in payload["data"]] == ["lag-1"]


# ---------------------------------------------------------------------------
# (p) summary tolerates 404 on the new switching counts
# ---------------------------------------------------------------------------


def test_summary_tolerates_404_on_switching_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> object:
        del method, kwargs
        if suffix == "/info":
            return {"applicationVersion": "10.1.0"}
        if suffix == "/sites":
            return {"data": [{"id": "site-1", "name": "default"}]}
        if "/switching/" in suffix:
            raise UniFiError(
                "not found",
                code="http_error",
                details={"status": 404, "body": "not found"},
            )
        return envelope([], total_count=0)

    monkeypatch.setattr(UniFiClient, "official", fake_official)
    monkeypatch.setattr(UniFiClient, "list_legacy_fallback", lambda self, resource: {"data": []})

    client = make_client()
    summary = client.summary()

    counts = summary["counts"]
    for key in ("switch_lags", "mc_lag_domains", "switch_stacks"):
        assert counts[key] == -1
        assert counts[f"{key}_error"] == "http_error"


# ---------------------------------------------------------------------------
# (q) dns-merge strips id and honours record-type disambiguation
# ---------------------------------------------------------------------------


def test_dns_merge_strips_id_and_honours_record_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    def fake_find_official(
        self: UniFiClient,
        resource,
        selector: str,
        *,
        record_type: str | None = None,
    ) -> dict:
        del self, resource, selector
        captured["record_type"] = record_type
        return {
            "id": "dns-1",
            "metadata": {"origin": "USER_DEFINED"},
            "domain": "foo.internal",
            "type": "A_RECORD",
            "ipv4Address": "10.0.0.9",
            "enabled": True,
        }

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
            "dns-merge",
            "foo.internal",
            "--record-type",
            "A",
            "--set",
            "enabled=false",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    # --record-type A normalises to A_RECORD before find_official.
    assert captured["record_type"] == "A_RECORD"
    body = payload["request"]["payload"]
    assert body["enabled"] is False
    assert "id" not in body
    assert "metadata" not in body
    assert payload["request"]["method"] == "PUT"
    assert payload["request"]["path"].endswith("/dns/policies/dns-1")


# ---------------------------------------------------------------------------
# (r) legacy-fallback-create dry-run: POST to collection, v2 vs rest selection
# ---------------------------------------------------------------------------


def test_legacy_fallback_create_rest_path_dry_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "legacy-fallback-create",
            "port-forward",
            "--data-json",
            '{"name": "web", "dst_port": "443"}',
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    # /rest/* legacy resources POST to the s/<site> base collection path.
    assert payload["request"]["path"] == "/proxy/network/api/s/default/rest/portforward"
    assert payload["request"]["payload"] == {"name": "web", "dst_port": "443"}


def test_legacy_fallback_create_v2_path_dry_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "legacy-fallback-create",
            "traffic-route",
            "--data-json",
            '{"name": "vpn-route"}',
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    # Non-/rest legacy resources POST to the v2 site collection path.
    assert payload["request"]["path"] == "/proxy/network/v2/api/site/default/trafficroutes"


# ---------------------------------------------------------------------------
# (s) reservation-create dry-run payload
# ---------------------------------------------------------------------------


def test_reservation_create_dry_run_payload(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "reservation-create",
            "--mac",
            "00:11:22:33:44:55",
            "--ip",
            "10.1.40.50",
            "--name",
            "printer",
            "--network-id",
            "net-legacy-1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["path"] == "/proxy/network/api/s/default/rest/user"
    assert payload["request"]["payload"] == {
        "mac": "00:11:22:33:44:55",
        "use_fixedip": True,
        "fixed_ip": "10.1.40.50",
        "name": "printer",
        "network_id": "net-legacy-1",
    }


def test_reservation_create_minimal_payload_omits_optional_fields(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "reservation-create",
            "--mac",
            "aa:bb:cc:dd:ee:ff",
            "--ip",
            "10.1.40.51",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["request"]["payload"] == {
        "mac": "aa:bb:cc:dd:ee:ff",
        "use_fixedip": True,
        "fixed_ip": "10.1.40.51",
    }


# ---------------------------------------------------------------------------
# (t) table formatter: aligned columns + footer, and TTY/non-TTY switch
# ---------------------------------------------------------------------------


def test_render_table_aligns_columns_and_footer() -> None:
    columns = [
        TableColumn("name", lambda row: row.get("name")),
        TableColumn("enabled", lambda row: row.get("enabled")),
    ]
    rows = [
        {"name": "Home", "enabled": True},
        {"name": "Guest-Network", "enabled": False},
    ]
    rendered = render_table(rows, columns, total_count=5)
    lines = rendered.splitlines()

    assert lines[0] == "name           enabled"
    # Separator row width matches the widest cell in each column.
    assert lines[1].startswith("-------------")
    # Bool values are normalised to true/false.
    assert "true" in lines[2]
    assert "false" in lines[3]
    # Footer reports shown-of-total using the provided total_count.
    assert lines[-1] == "2 of 5"


def test_render_table_truncates_long_cells() -> None:
    columns = [TableColumn("value", lambda row: row.get("value"))]
    long_value = "x" * 100
    rendered = render_table([{"value": long_value}], columns)
    data_line = rendered.splitlines()[2]
    # Long cells are truncated to the cell max with an ellipsis marker.
    assert data_line.endswith("…")
    assert len(data_line.rstrip()) == 40


def test_format_list_table_returns_none_without_spec() -> None:
    assert format_list_table("sites", {"data": []}) is None
    assert "devices" in TABLE_SPECS


def test_tty_renders_table_without_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, suffix, kwargs
        return envelope(
            [
                {
                    "name": "AP",
                    "model": "U6",
                    "macAddress": "aa:bb:cc:dd:ee:ff",
                    "ipAddress": "10.1.40.5",
                    "state": "ONLINE",
                }
            ],
            total_count=1,
        )

    monkeypatch.setattr(UniFiClient, "official", fake_official)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    exit_code = main(
        [
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "devices",
        ]
    )
    out = capsys.readouterr().out

    assert exit_code == 0
    # Human table output, not JSON, on a TTY without --json.
    assert out.startswith("name")
    assert "macAddress" in out
    assert "1 of 1" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_non_tty_emits_json_without_json_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs) -> dict:
        del self, method, suffix, kwargs
        return envelope([{"name": "AP", "model": "U6", "state": "ONLINE"}], total_count=1)

    monkeypatch.setattr(UniFiClient, "official", fake_official)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)

    exit_code = main(
        [
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "devices",
        ]
    )
    out = capsys.readouterr().out

    assert exit_code == 0
    # Piped (non-TTY) output stays JSON even without --json, preserving agent behaviour.
    payload = json.loads(out)
    assert [item["name"] for item in payload["data"]] == ["AP"]
