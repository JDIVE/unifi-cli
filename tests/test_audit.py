from __future__ import annotations

import json
from pathlib import Path

import pytest

import unifi_cli.audit
import unifi_cli.core
from unifi_cli.audit import (
    build_firewall_audit_report,
    build_firewall_matrix,
    format_firewall_audit_human,
    format_firewall_matrix_human,
    score_label,
)
from unifi_cli.cli import main
from unifi_cli.config import Config
from unifi_cli.core import UniFiClient

# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


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


ZONES = [
    {"id": "zone-a", "name": "Internal", "networkIds": ["net-1"]},
    {"id": "zone-b", "name": "IoT", "networkIds": ["net-2"]},
]

NETWORKS = [
    {"id": "net-1", "name": "Home", "zoneId": "zone-a"},
    {"id": "net-2", "name": "IoT-Net", "zoneId": "zone-b"},
    {"id": "net-3", "name": "Orphan"},
]

POLICY_ALLOW_BROAD = {
    "id": "pol-1",
    "name": "Allow Home to IoT",
    "action": "ALLOW",
    "enabled": True,
    "source": {"zoneId": "zone-a"},
    "destination": {"zoneId": "zone-b"},
    "metadata": {"origin": "USER_DEFINED"},
}

POLICY_UNKNOWN_ZONE = {
    "id": "pol-2",
    "name": "Ghost policy",
    "action": "BLOCK",
    "enabled": True,
    "sourceZoneId": "zone-x",
    "destinationZoneId": "zone-b",
    "metadata": {"origin": "USER_DEFINED"},
}

POLICY_STALE_NETWORK = {
    "id": "pol-3",
    "name": "Old NAS rule",
    "action": "ALLOW",
    "enabled": True,
    "source": {"zoneId": "zone-a"},
    "destination": {"zoneId": "zone-b"},
    "trafficFilter": {"matchType": "NETWORK", "networkIds": ["net-dead"]},
    "metadata": {"origin": "USER_DEFINED"},
}

POLICY_DNS = {
    "id": "pol-4",
    "name": "DNS control",
    "action": "ALLOW",
    "enabled": True,
    "source": {"zoneId": "zone-a"},
    "destination": {"zoneId": "zone-b"},
    "portFilter": {"ports": [53]},
    "metadata": {"origin": "USER_DEFINED"},
}

# The old audit used a '"53" in json.dumps(policy)' hack; this policy's UUID
# contains "53" but nothing DNS-related, so the structural check must skip it.
POLICY_UUID_CONTAINS_53 = {
    "id": "aaaa53bb-0000-0000-0000-000000000000",
    "name": "Innocent",
    "action": "BLOCK",
    "enabled": True,
    "source": {"zoneId": "zone-b"},
    "destination": {"zoneId": "zone-a"},
    "trafficFilter": {"matchType": "APP", "appIds": ["app-1"]},
    "metadata": {"origin": "USER_DEFINED"},
}

POLICY_DISABLED = {
    "id": "pol-5",
    "name": "Retired rule for printer",
    "action": "BLOCK",
    "enabled": False,
    "source": {"zoneId": "zone-a"},
    "destination": {"zoneId": "zone-b"},
    "metadata": {"origin": "USER_DEFINED"},
}

POLICY_PLACEHOLDER = {
    "id": "pol-6",
    "name": "Rule 3",
    "action": "BLOCK",
    "enabled": True,
    "source": {"zoneId": "zone-b"},
    "destination": {"zoneId": "zone-a"},
    "trafficFilter": {"matchType": "APP", "appIds": ["app-2"]},
    "metadata": {"origin": "USER_DEFINED"},
}

ALL_POLICIES = [
    POLICY_ALLOW_BROAD,
    POLICY_UNKNOWN_ZONE,
    POLICY_STALE_NETWORK,
    POLICY_DNS,
    POLICY_UUID_CONTAINS_53,
    POLICY_DISABLED,
    POLICY_PLACEHOLDER,
]

DEVICES = [
    {"id": "dev-1", "name": "Switch", "state": "ONLINE"},
    {"id": "dev-2", "name": "AP", "state": "OFFLINE"},
]


def patch_paginate(monkeypatch: pytest.MonkeyPatch, data_by_path: dict[str, list[dict]]) -> None:
    def fake_paginate(self: UniFiClient, path: str, *, extra_query=None, limit=200):
        del self, extra_query, limit
        if path in data_by_path:
            return data_by_path[path]
        raise AssertionError(f"unexpected paginate path {path}")

    monkeypatch.setattr(UniFiClient, "paginate_path", fake_paginate)


def audit_paths(
    *,
    policies: list[dict] | None = None,
    zones: list[dict] | None = None,
    networks: list[dict] | None = None,
    devices: list[dict] | None = None,
    acl_rules: list[dict] | None = None,
) -> dict[str, list[dict]]:
    return {
        "/sites/site-1/networks": NETWORKS if networks is None else networks,
        "/sites/site-1/firewall/policies": ALL_POLICIES if policies is None else policies,
        "/sites/site-1/firewall/zones": ZONES if zones is None else zones,
        "/sites/site-1/devices": DEVICES if devices is None else devices,
        "/sites/site-1/acl-rules": [] if acl_rules is None else acl_rules,
    }


def find_finding(report: dict, benchmark_id: str) -> dict | None:
    for category in report["categories"].values():
        for finding in category["findings"]:
            if finding["benchmark_id"] == benchmark_id:
                return finding
    return None


# ---------------------------------------------------------------------------
# firewall-matrix
# ---------------------------------------------------------------------------


def test_matrix_pairs_counts_unzoned_and_unknown() -> None:
    matrix = build_firewall_matrix(ZONES, [POLICY_ALLOW_BROAD, POLICY_UNKNOWN_ZONE], NETWORKS)

    zones_by_name = {zone["name"]: zone for zone in matrix["zones"]}
    assert set(zones_by_name) == {"Internal", "IoT"}
    assert zones_by_name["Internal"]["networkNames"] == ["Home"]
    assert zones_by_name["IoT"]["networkNames"] == ["IoT-Net"]

    pairs = {(entry["sourceZone"], entry["destinationZone"]): entry for entry in matrix["matrix"]}
    assert set(pairs) == {("Internal", "IoT"), ("IoT", "Internal")}

    forward = pairs[("Internal", "IoT")]
    assert forward["policyCount"] == 1
    assert forward["enabledUserPolicyCount"] == 1
    assert forward["actions"] == {"ALLOW": 1, "BLOCK": 0, "REJECT": 0}
    assert forward["hasExplicitPolicy"] is True

    # The reverse pair has networks on both sides but no policy: visible as an
    # explicit empty entry so default-deny reliance is auditable.
    reverse = pairs[("IoT", "Internal")]
    assert reverse["policyCount"] == 0
    assert reverse["enabledUserPolicyCount"] == 0
    assert reverse["hasExplicitPolicy"] is False

    assert matrix["unzonedNetworks"] == ["Orphan"]
    assert matrix["policiesWithUnknownZones"] == ["Ghost policy"]


def test_matrix_tolerates_flat_zone_id_variant() -> None:
    flat_policy = {
        "id": "pol-flat",
        "name": "Flat shape",
        "action": "BLOCK",
        "enabled": True,
        "sourceZoneId": "zone-b",
        "destinationZoneId": "zone-a",
        "metadata": {"origin": "USER_DEFINED"},
    }
    matrix = build_firewall_matrix(ZONES, [flat_policy], NETWORKS)
    pairs = {(entry["sourceZone"], entry["destinationZone"]): entry for entry in matrix["matrix"]}
    assert pairs[("IoT", "Internal")]["policyCount"] == 1
    assert pairs[("IoT", "Internal")]["actions"]["BLOCK"] == 1
    assert matrix["policiesWithUnknownZones"] == []


def test_matrix_human_grid_renders() -> None:
    matrix = build_firewall_matrix(ZONES, [POLICY_ALLOW_BROAD, POLICY_UNKNOWN_ZONE], NETWORKS)
    rendered = format_firewall_matrix_human(matrix)

    assert "src \\ dst" in rendered
    assert "Internal" in rendered
    assert "IoT" in rendered
    # Empty pair shows "-", populated pair shows the count.
    assert "-" in rendered
    assert "1" in rendered
    assert "Unzoned networks: Orphan" in rendered
    assert "Ghost policy" in rendered


def test_matrix_command_json_via_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_paginate(monkeypatch, audit_paths())

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "firewall-matrix",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert {"zones", "matrix", "unzonedNetworks", "policiesWithUnknownZones"} <= set(payload)


def test_matrix_command_human_via_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_paginate(monkeypatch, audit_paths())

    exit_code = main(
        [
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "firewall-matrix",
            "--format",
            "human",
        ]
    )
    out = capsys.readouterr().out

    assert exit_code == 0
    assert out.startswith("Firewall zone matrix")
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


# ---------------------------------------------------------------------------
# firewall-audit
# ---------------------------------------------------------------------------


def test_audit_stale01_fires_for_missing_zone_and_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    finding = find_finding(report, "STALE-01")
    assert finding is not None
    assert finding["severity"] == "critical"
    assert finding["category"] == "staleness"
    assert "Ghost policy" in finding["evidence"]["policies_with_missing_zone"]
    assert "Old NAS rule" in finding["evidence"]["policies_with_missing_network"]
    assert finding in report["critical_findings"]


def test_audit_stale02_counts_disabled_policies(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    finding = find_finding(report, "STALE-02")
    assert finding is not None
    assert finding["severity"] == "warning"
    assert finding["evidence"]["disabled_policy_count"] == 1
    assert finding["evidence"]["disabled_policy_names"] == ["Retired rule for printer"]


def test_audit_zone01_reports_default_deny_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Zones with networks on both sides but zero policies at all.
    patch_paginate(monkeypatch, audit_paths(policies=[]))
    report = build_firewall_audit_report(make_client())

    finding = find_finding(report, "ZONE-01")
    assert finding is not None
    assert finding["severity"] == "informational"
    pairs = finding["evidence"]["default_deny_pairs"]
    assert {"sourceZone": "Internal", "destinationZone": "IoT"} in pairs
    assert {"sourceZone": "IoT", "destinationZone": "Internal"} in pairs


def test_audit_zone02_fires_for_unconstrained_interzone_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    finding = find_finding(report, "ZONE-02")
    assert finding is not None
    assert finding["severity"] == "warning"
    assert finding["evidence"]["broad_allow_policies"] == ["Allow Home to IoT"]
    # Constrained policies (trafficFilter / portFilter present) are not flagged.
    assert "Old NAS rule" not in finding["evidence"]["broad_allow_policies"]
    assert "DNS control" not in finding["evidence"]["broad_allow_policies"]


def test_audit_dns01_structural_detection_no_uuid_false_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    finding = find_finding(report, "DNS-01")
    assert finding is not None
    assert finding["severity"] == "informational"
    # Only the structural port-53 policy is counted; the policy whose UUID
    # merely contains "53" is not.
    assert finding["evidence"]["dns_policy_count"] == 1
    assert finding["evidence"]["dns_policies_without_protocol_filter"] == ["DNS control"]


def test_audit_hyg01_and_top01_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    hygiene = find_finding(report, "HYG-01")
    assert hygiene is not None
    assert hygiene["evidence"]["placeholder_names"] == ["Rule 3"]

    topology = find_finding(report, "TOP-01")
    assert topology is not None
    assert topology["severity"] == "critical"
    assert topology["evidence"]["offline_devices"] == ["AP"]


def test_audit_score_categories_and_summary_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())

    assert set(report["categories"]) == {"segmentation", "hygiene", "topology", "staleness"}
    for category in report["categories"].values():
        assert 0 <= category["score"] <= category["max"] == 25
    assert report["overall_score"] == sum(
        category["score"] for category in report["categories"].values()
    )
    assert report["overall_status"] == score_label(report["overall_score"])
    assert report["recommendations"]

    summary = report["summary"]
    assert summary["firewall_zones"] == 2
    assert summary["firewall_policies"] == len(ALL_POLICIES)
    assert summary["user_defined_firewall_policies"] == len(ALL_POLICIES)
    assert summary["unzoned_networks"] == ["Orphan"]
    assert 0 <= summary["matrix_coverage_percent"] <= 100
    assert summary["zone_matrix"]["policiesWithUnknownZones"] == ["Ghost policy"]

    # The VLAN-role heuristics and old finding ids are gone.
    dumped = json.dumps(report)
    assert "SEG-01" not in dumped
    assert "SEG-02" not in dumped
    assert "EGR-01" not in dumped
    assert "egress_control" not in report["categories"]


def test_no_vlan_role_heuristics_remain() -> None:
    assert not hasattr(unifi_cli.core, "network_role")
    assert not hasattr(unifi_cli.audit, "network_role")
    audit_source = Path(unifi_cli.audit.__file__).read_text()
    core_source = Path(unifi_cli.core.__file__).read_text()
    assert "network_role" not in audit_source
    assert "network_role" not in core_source


def test_audit_human_formatter(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_paginate(monkeypatch, audit_paths())
    report = build_firewall_audit_report(make_client())
    rendered = format_firewall_audit_human(report)

    assert rendered.startswith("Firewall audit score:")
    assert "Category scores:" in rendered
    assert "Staleness" in rendered
    assert "Matrix coverage" in rendered
    assert "Unzoned networks: Orphan" in rendered
    assert "[STALE-01]" in rendered
    assert "[TOP-01]" in rendered


def test_audit_command_json_via_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_paginate(monkeypatch, audit_paths())

    exit_code = main(
        [
            "--json",
            "--base-url",
            "https://controller.example",
            "--api-key",
            "secret",
            "--site-id",
            "site-1",
            "firewall-audit",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert {
        "overall_score",
        "overall_status",
        "categories",
        "critical_findings",
        "recommendations",
        "summary",
    } <= set(payload)
    assert "zone_matrix" in payload["summary"]
