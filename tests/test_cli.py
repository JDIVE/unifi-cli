from __future__ import annotations

import argparse
import json

import pytest

from unifi_cli.cli import build_parser, main
from unifi_cli.config import build_config
from unifi_cli.core import UniFiClient


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


def test_doctor_json_with_mocked_live_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
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

    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["error"]["code"] == "config_missing"
