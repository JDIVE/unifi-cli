from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from unifi_cli import __version__
from unifi_cli.cli import main
from unifi_cli.config import Config
from unifi_cli.core import UniFiClient, UniFiError
from unifi_cli.snapshot import LEGACY_COLLECTIONS, OFFICIAL_COLLECTIONS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SUFFIX_TO_COLLECTION = {suffix: name for name, suffix in OFFICIAL_COLLECTIONS.items()}

BASE_ARGS = [
    "--json",
    "--base-url",
    "https://controller.example",
    "--api-key",
    "secret",
    "--site-id",
    "site-1",
]


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


def patch_live(
    monkeypatch: pytest.MonkeyPatch,
    official_data: dict[str, list[dict[str, Any]]],
    legacy_data: dict[str, list[dict[str, Any]]] | None = None,
    fail: set[str] | None = None,
) -> None:
    """Patch the client so snapshot/diff read from in-memory collections.

    ``official_data`` and ``legacy_data`` are mutable: tests can change them
    between a snapshot and a diff to simulate drift.
    """
    legacy_data = {} if legacy_data is None else legacy_data
    fail = set() if fail is None else fail

    def fake_paginate(self: UniFiClient, path: str, *, extra_query=None, limit=200):
        del self, extra_query, limit
        suffix = path.removeprefix("/sites/site-1/")
        collection = SUFFIX_TO_COLLECTION.get(suffix)
        if collection is None:
            raise AssertionError(f"unexpected paginate path {path}")
        if collection in fail:
            raise UniFiError(
                "not found", code="http_error", details={"status": 404, "body": "missing"}
            )
        return official_data.get(collection, [])

    def fake_legacy_fallback(self: UniFiClient, resource: str):
        del self
        if resource in fail:
            raise UniFiError("legacy boom", code="http_error", details={"status": 500})
        return {"data": legacy_data.get(resource, [])}

    def fake_official(self: UniFiClient, method: str, suffix: str, **kwargs):
        del self, method, kwargs
        if suffix == "/info":
            return {"applicationVersion": "10.4.57"}
        raise AssertionError(f"unexpected official suffix {suffix}")

    monkeypatch.setattr(UniFiClient, "paginate_path", fake_paginate)
    monkeypatch.setattr(UniFiClient, "list_legacy_fallback", fake_legacy_fallback)
    monkeypatch.setattr(UniFiClient, "official", fake_official)


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def test_snapshot_writes_files_meta_and_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    official_data = {
        "networks": [
            {"id": "n2", "name": "b", "statistics": {"txBytes": 5}},
            {"id": "n1", "name": "a"},
        ],
        "clients": [
            {"id": "c1", "name": "zeta", "uptimeSec": 5, "lastSeen": 123, "latency": 9},
            {"id": "c2", "name": "alpha"},
        ],
    }
    legacy_data = {"port-forward": [{"_id": "pf1", "name": "web"}]}
    patch_live(monkeypatch, official_data, legacy_data, fail={"switch-lags"})

    snap_dir = tmp_path / "snap"
    exit_code = main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["dir"] == str(snap_dir)

    # One file per collection, legacy files prefixed, failing collection absent.
    assert (snap_dir / "networks.json").exists()
    assert (snap_dir / "clients.json").exists()
    assert (snap_dir / "legacy-port-forward.json").exists()
    assert not (snap_dir / "switch-lags.json").exists()

    # Volatile fields stripped from clients, and items sorted by name.
    clients = json.loads((snap_dir / "clients.json").read_text())
    assert [client["name"] for client in clients] == ["alpha", "zeta"]
    for client in clients:
        for volatile in ("uptimeSec", "lastSeen", "latency"):
            assert volatile not in client

    # Config collections keep every field (statistics is volatile only for
    # clients/devices) and are sorted by name.
    networks = json.loads((snap_dir / "networks.json").read_text())
    assert [network["name"] for network in networks] == ["a", "b"]
    assert networks[1]["statistics"] == {"txBytes": 5}

    meta = json.loads((snap_dir / "_meta.json").read_text())
    assert meta["controller_host"] == "controller.example"
    assert meta["application_version"] == "10.4.57"
    assert meta["cli_version"] == __version__
    assert meta["counts"]["networks"] == 2
    assert "networks" in meta["collections"]
    assert "secret" not in (snap_dir / "_meta.json").read_text()

    errors = json.loads((snap_dir / "_errors.json").read_text())
    assert errors["switch-lags"]["code"] == "http_error"


def test_snapshot_covers_expected_collection_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    patch_live(monkeypatch, {}, {})
    snap_dir = tmp_path / "snap"

    exit_code = main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)])
    capsys.readouterr()

    assert exit_code == 0
    written = {path.name for path in snap_dir.glob("*.json")}
    expected = {f"{name}.json" for name in OFFICIAL_COLLECTIONS}
    expected |= {f"legacy-{name}.json" for name in LEGACY_COLLECTIONS}
    expected |= {"_meta.json"}
    assert written == expected


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def snapshot_then_diff_args(snap_dir: Path, *extra: str) -> list[str]:
    return [*BASE_ARGS, "diff", "--dir", str(snap_dir), *extra]


def test_diff_identical_reports_identical_and_exit_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    official_data = {"networks": [{"id": "n1", "name": "a", "enabled": True}]}
    legacy_data = {"port-forward": [{"_id": "pf1", "name": "web"}]}
    patch_live(monkeypatch, official_data, legacy_data)

    snap_dir = tmp_path / "snap"
    assert main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)]) == 0
    capsys.readouterr()

    exit_code = main(snapshot_then_diff_args(snap_dir))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["identical"] is True
    assert all(
        not (result["added"] or result["removed"] or result["changed"])
        for result in payload["collections"].values()
    )

    # --exit-code still exits 0 when nothing changed.
    assert main(snapshot_then_diff_args(snap_dir, "--exit-code")) == 0
    capsys.readouterr()


def test_diff_reports_added_removed_and_changed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    official_data = {
        "networks": [
            {"id": "n1", "name": "a", "enabled": True},
            {"id": "n2", "name": "b", "enabled": True},
        ]
    }
    patch_live(monkeypatch, official_data)

    snap_dir = tmp_path / "snap"
    assert main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)]) == 0
    capsys.readouterr()

    # Simulate drift: n1 changed, n2 removed, n3 added.
    official_data["networks"] = [
        {"id": "n1", "name": "a", "enabled": False},
        {"id": "n3", "name": "c", "enabled": True},
    ]

    exit_code = main(snapshot_then_diff_args(snap_dir))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0  # without --exit-code the diff always exits 0
    assert payload["identical"] is False
    networks = payload["collections"]["networks"]
    assert networks["added"] == ["c"]
    assert networks["removed"] == ["b"]
    assert networks["changed"] == [{"label": "a", "fields": ["enabled"]}]


def test_diff_exit_code_flag_returns_one_on_difference(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    official_data = {"networks": [{"id": "n1", "name": "a", "enabled": True}]}
    patch_live(monkeypatch, official_data)

    snap_dir = tmp_path / "snap"
    assert main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)]) == 0
    capsys.readouterr()

    official_data["networks"] = [{"id": "n1", "name": "a", "enabled": False}]

    assert main(snapshot_then_diff_args(snap_dir)) == 0
    capsys.readouterr()
    assert main(snapshot_then_diff_args(snap_dir, "--exit-code")) == 1
    capsys.readouterr()


def test_diff_collection_filter_and_human_format(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    official_data = {
        "networks": [{"id": "n1", "name": "a", "enabled": True}],
        "devices": [{"id": "d1", "name": "Switch", "state": "ONLINE"}],
    }
    patch_live(monkeypatch, official_data)

    snap_dir = tmp_path / "snap"
    assert main([*BASE_ARGS, "snapshot", "--dir", str(snap_dir)]) == 0
    capsys.readouterr()

    official_data["networks"] = [{"id": "n1", "name": "a", "enabled": False}]

    exit_code = main(snapshot_then_diff_args(snap_dir, "--collection", "networks"))
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert set(payload["collections"]) == {"networks"}

    # Human format renders a git-status-like summary instead of JSON.
    exit_code = main(
        [
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "diff",
            "--dir",
            str(snap_dir),
            "--collection",
            "networks",
            "--format",
            "human",
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Differences from snapshot:" in out
    assert "M  a (enabled)" in out


def test_diff_missing_directory_maps_to_not_found(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    patch_live(monkeypatch, {})
    exit_code = main(snapshot_then_diff_args(tmp_path / "missing"))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 4
    assert payload["error"]["code"] == "not_found"


# ---------------------------------------------------------------------------
# backups
# ---------------------------------------------------------------------------


def test_backup_list_posts_correct_cmd_payload(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    def fake_legacy(self: UniFiClient, method: str, suffix: str, **kwargs):
        del self
        captured["method"] = method
        captured["suffix"] = suffix
        captured["payload"] = kwargs.get("payload")
        return {"data": [{"filename": "autobackup_1.unf", "time": 100}]}

    monkeypatch.setattr(UniFiClient, "legacy", fake_legacy)

    exit_code = main([*BASE_ARGS, "backup-list"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert captured["method"] == "POST"
    assert captured["suffix"] == "/cmd/backup"
    assert captured["payload"] == {"cmd": "list-backups"}
    assert payload == [{"filename": "autobackup_1.unf", "time": 100}]


def test_backup_generate_dry_runs_without_yes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main([*BASE_ARGS, "backup-generate"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["status"] == "dry-run"
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["path"] == "/proxy/network/api/s/default/cmd/backup"
    assert payload["request"]["payload"] == {"cmd": "backup", "days": -1}


def test_backup_generate_days_flag_in_payload(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main([*BASE_ARGS, "backup-generate", "--days", "0"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["request"]["payload"] == {"cmd": "backup", "days": 0}


def test_backup_download_picks_newest_and_writes_bytes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def fake_legacy(self: UniFiClient, method: str, suffix: str, **kwargs):
        del self, method, suffix, kwargs
        return {
            "data": [
                {"filename": "autobackup_old.unf", "time": 100},
                {"filename": "autobackup_new.unf", "time": 200},
            ]
        }

    captured: dict[str, Any] = {}

    def fake_request_bytes(self: UniFiClient, method: str, path: str, **kwargs) -> bytes:
        del self, kwargs
        captured["method"] = method
        captured["path"] = path
        return b"UNF-BYTES"

    monkeypatch.setattr(UniFiClient, "legacy", fake_legacy)
    monkeypatch.setattr(UniFiClient, "request_bytes", fake_request_bytes)

    output = tmp_path / "backup.unf"
    exit_code = main([*BASE_ARGS, "backup-download", "--output", str(output)])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert captured["method"] == "GET"
    assert captured["path"] == "/proxy/network/dl/autobackup/autobackup_new.unf"
    assert output.read_bytes() == b"UNF-BYTES"
    assert payload["bytes"] == len(b"UNF-BYTES")
    assert payload["output"] == str(output)


def test_backup_download_path_override_used_verbatim(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_request_bytes(self: UniFiClient, method: str, path: str, **kwargs) -> bytes:
        del self, method, kwargs
        captured["path"] = path
        return b"X"

    monkeypatch.setattr(UniFiClient, "request_bytes", fake_request_bytes)

    output = tmp_path / "backup.unf"
    exit_code = main(
        [
            *BASE_ARGS,
            "backup-download",
            "--output",
            str(output),
            "--path",
            "/proxy/network/dl/autobackup/explicit.unf",
        ]
    )
    capsys.readouterr()

    assert exit_code == 0
    assert captured["path"] == "/proxy/network/dl/autobackup/explicit.unf"
    assert output.read_bytes() == b"X"


def test_request_bytes_returns_raw_body_with_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeBinaryResponse:
        headers = {"Content-Type": "application/octet-stream"}

        def __enter__(self) -> FakeBinaryResponse:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return b"\x00\x01BINARY"

    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, **kwargs: object) -> FakeBinaryResponse:
        captured["url"] = request.full_url
        captured["key"] = request.headers.get("X-api-key")
        return FakeBinaryResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client()

    data = client.request_bytes("GET", "/proxy/network/dl/autobackup/x.unf")

    assert data == b"\x00\x01BINARY"
    assert captured["url"] == "https://controller.example/proxy/network/dl/autobackup/x.unf"
    assert captured["key"] == "controller-key"


def test_request_bytes_blocks_foreign_host(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_urlopen(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("must not be reached")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = make_client()

    with pytest.raises(UniFiError) as excinfo:
        client.request_bytes("GET", "https://evil.example/steal.unf")

    assert excinfo.value.code == "foreign_host_blocked"
    assert called is False
