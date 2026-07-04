"""Firewall matrix and scored firewall audit built on fully-paginated official data.

The zone-based firewall model (UniFi Network 10.4+) replaces the old VLAN-role
heuristics. Both the ``firewall-matrix`` and ``firewall-audit`` commands read
every page of the relevant official collections and reason purely about zones,
policies, networks, ACL rules, and devices.
"""

from __future__ import annotations

import argparse
import re
from datetime import UTC, datetime
from typing import Any

from unifi_cli.core import UniFiClient, wants_human_format

FIREWALL_ACTIONS = ("ALLOW", "BLOCK", "REJECT")
PLACEHOLDER_NAME_RE = re.compile(r"(rule|new rule|untitled)( \d+)?")
DIGITS_ONLY_RE = re.compile(r"\d+")


# ---------------------------------------------------------------------------
# Shared extractors
# ---------------------------------------------------------------------------


def policy_is_user_defined(policy: dict[str, Any]) -> bool:
    metadata = policy.get("metadata")
    if isinstance(metadata, dict):
        return metadata.get("origin") == "USER_DEFINED"
    return bool(policy.get("predefined") is False)


def _endpoint_zone_id(policy: dict[str, Any], *, source: bool) -> str | None:
    """Extract a policy's source/destination zone id, tolerating shape variants.

    Handles both the nested ``source: {"zoneId": ...}`` shape and the flat
    ``sourceZoneId`` / ``destinationZoneId`` variants seen across firmware.
    """
    nested_key = "source" if source else "destination"
    endpoint = policy.get(nested_key)
    if isinstance(endpoint, dict):
        zone_id = endpoint.get("zoneId") or endpoint.get("firewallZoneId")
        if zone_id:
            return str(zone_id)
        zone = endpoint.get("zone")
        if isinstance(zone, dict) and zone.get("id"):
            return str(zone["id"])
    flat_key = "sourceZoneId" if source else "destinationZoneId"
    flat = policy.get(flat_key)
    if flat:
        return str(flat)
    return None


def _policy_zone_pair(policy: dict[str, Any]) -> tuple[str | None, str | None]:
    return _endpoint_zone_id(policy, source=True), _endpoint_zone_id(policy, source=False)


def _policy_action(policy: dict[str, Any]) -> str:
    return str(policy.get("action", "")).upper()


def _iter_dicts(container: Any) -> list[dict[str, Any]]:
    if isinstance(container, list):
        return [item for item in container if isinstance(item, dict)]
    return []


def _policy_has_traffic_constraint(policy: dict[str, Any]) -> bool:
    """Return True when a policy narrows traffic beyond "all traffic".

    A broad allow specifies no trafficFilter/ipAddressFilter/portFilter that
    would restrict what it matches.
    """
    for key in ("trafficFilter", "ipAddressFilter", "portFilter", "protocolFilter"):
        value = policy.get(key)
        if isinstance(value, dict) and value:
            # A filter dict that only says "match everything" is not a constraint.
            match_type = str(value.get("matchType") or value.get("type") or "").upper()
            if match_type in {"ALL", "ANY", "MATCH_ALL"}:
                continue
            return True
        if isinstance(value, list) and value:
            return True
    return False


def _walk_for_port(node: Any, port: int) -> bool:
    """Structurally walk a nested structure looking for an explicit port value.

    Only inspects keys that plausibly carry ports so an unrelated field (or a
    UUID string that happens to contain the digits) never triggers a match.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            if "port" in lowered and _port_value_matches(value, port):
                return True
            if _walk_for_port(value, port):
                return True
        return False
    if isinstance(node, list):
        return any(_walk_for_port(item, port) for item in node)
    return False


def _port_value_matches(value: Any, port: int) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == port
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped) == port
        # Support "53" inside a port list string like "53,853" or a range "53-53".
        for token in re.split(r"[,\s]+", stripped):
            token = token.strip()
            if "-" in token:
                bounds = token.split("-", 1)
                if all(bound.strip().isdigit() for bound in bounds):
                    low, high = int(bounds[0]), int(bounds[1])
                    if low <= port <= high:
                        return True
            elif token.isdigit() and int(token) == port:
                return True
        return False
    if isinstance(value, list):
        return any(_port_value_matches(item, port) for item in value)
    if isinstance(value, dict):
        return any(_port_value_matches(item, port) for item in value.values())
    return False


def _policy_targets_port(policy: dict[str, Any], port: int) -> bool:
    for key in ("trafficFilter", "portFilter", "matchCriteria"):
        node = policy.get(key)
        if node is not None and _walk_for_port(node, port):
            return True
    return False


def _policy_specifies_protocol(policy: dict[str, Any]) -> bool:
    for key in ("protocolFilter", "protocol", "trafficFilter"):
        value = policy.get(key)
        if key == "trafficFilter" and isinstance(value, dict):
            if value.get("protocol") or value.get("protocolFilter"):
                return True
            continue
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, dict) and value:
            return True
        if isinstance(value, list) and value:
            return True
    return False


def _zone_network_names(
    zone: dict[str, Any],
    networks_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    names: list[str] = []
    ids = zone.get("networkIds")
    if isinstance(ids, list):
        for network_id in ids:
            network = networks_by_id.get(str(network_id))
            if network is not None:
                names.append(str(network.get("name") or network_id))
            else:
                names.append(str(network_id))
    return names


# ---------------------------------------------------------------------------
# Matrix builder (item 1)
# ---------------------------------------------------------------------------


def build_firewall_matrix(
    zones: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    networks: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the zone x zone matrix from official zones, policies, and networks."""
    zones = _iter_dicts(zones)
    policies = _iter_dicts(policies)
    networks = _iter_dicts(networks)

    networks_by_id: dict[str, dict[str, Any]] = {}
    for network in networks:
        network_id = network.get("id")
        if network_id:
            networks_by_id[str(network_id)] = network

    zone_by_id: dict[str, dict[str, Any]] = {}
    zone_name: dict[str, str] = {}
    # Which zones contain at least one network, derived from both the zone's own
    # networkIds and each network's zoneId back-reference.
    zone_network_names: dict[str, list[str]] = {}
    for zone in zones:
        zone_id = zone.get("id")
        if not zone_id:
            continue
        zone_id = str(zone_id)
        zone_by_id[zone_id] = zone
        zone_name[zone_id] = str(zone.get("name") or zone_id)
        zone_network_names[zone_id] = _zone_network_names(zone, networks_by_id)

    unzoned_networks: list[str] = []
    for network in networks:
        zone_id = network.get("zoneId")
        name = str(network.get("name") or network.get("id") or "")
        if zone_id and str(zone_id) in zone_by_id:
            zone_key = str(zone_id)
            if name and name not in zone_network_names.setdefault(zone_key, []):
                zone_network_names[zone_key].append(name)
        else:
            if name:
                unzoned_networks.append(name)

    zones_with_networks = {zone_id for zone_id, members in zone_network_names.items() if members}

    # Aggregate policies per ordered (source, destination) zone pair.
    pair_stats: dict[tuple[str, str], dict[str, Any]] = {}
    unknown_zone_policies: list[str] = []

    def stats_for(pair: tuple[str, str]) -> dict[str, Any]:
        return pair_stats.setdefault(
            pair,
            {
                "policyCount": 0,
                "enabledUserPolicyCount": 0,
                "actions": dict.fromkeys(FIREWALL_ACTIONS, 0),
                "hasExplicitPolicy": True,
            },
        )

    for policy in policies:
        source_id, dest_id = _policy_zone_pair(policy)
        name = str(policy.get("name") or policy.get("id") or "")
        if (
            source_id is None
            or dest_id is None
            or source_id not in zone_by_id
            or dest_id not in zone_by_id
        ):
            if name:
                unknown_zone_policies.append(name)
            continue
        stats = stats_for((source_id, dest_id))
        stats["policyCount"] += 1
        action = _policy_action(policy)
        if action in stats["actions"]:
            stats["actions"][action] += 1
        if policy_is_user_defined(policy) and policy.get("enabled", True):
            stats["enabledUserPolicyCount"] += 1

    # Add empty pairs for every ordered pair of distinct zones that both hold
    # networks, so default-deny gaps are visible with policyCount 0.
    for source_id in zones_with_networks:
        for dest_id in zones_with_networks:
            if source_id == dest_id:
                continue
            if (source_id, dest_id) not in pair_stats:
                pair_stats[(source_id, dest_id)] = {
                    "policyCount": 0,
                    "enabledUserPolicyCount": 0,
                    "actions": dict.fromkeys(FIREWALL_ACTIONS, 0),
                    "hasExplicitPolicy": False,
                }

    matrix: list[dict[str, Any]] = []
    for (source_id, dest_id), stats in pair_stats.items():
        matrix.append(
            {
                "sourceZone": zone_name.get(source_id, source_id),
                "destinationZone": zone_name.get(dest_id, dest_id),
                "policyCount": stats["policyCount"],
                "enabledUserPolicyCount": stats["enabledUserPolicyCount"],
                "actions": dict(stats["actions"]),
                "hasExplicitPolicy": stats["hasExplicitPolicy"],
            }
        )
    matrix.sort(key=lambda entry: (entry["sourceZone"], entry["destinationZone"]))

    zone_entries = [
        {
            "id": zone_id,
            "name": zone_name[zone_id],
            "networkNames": zone_network_names.get(zone_id, []),
        }
        for zone_id in sorted(zone_by_id, key=lambda zid: zone_name[zid])
    ]

    return {
        "zones": zone_entries,
        "matrix": matrix,
        "unzonedNetworks": sorted(set(unzoned_networks)),
        "policiesWithUnknownZones": sorted(set(unknown_zone_policies)),
    }


def command_firewall_matrix(client: UniFiClient, args: argparse.Namespace) -> Any:
    site_id = client.site_id()
    zones = client.paginate_path(f"/sites/{site_id}/firewall/zones")
    policies = client.paginate_path(f"/sites/{site_id}/firewall/policies")
    networks = client.paginate_path(f"/sites/{site_id}/networks")
    matrix = build_firewall_matrix(zones, policies, networks)
    if wants_human_format(args):
        return format_firewall_matrix_human(matrix)
    return matrix


def _abbreviate(name: str, width: int) -> str:
    if len(name) <= width:
        return name
    if width <= 1:
        return name[:width]
    return name[: width - 1] + "…"


def format_firewall_matrix_human(matrix: dict[str, Any]) -> str:
    zones = matrix["zones"]
    zone_names = [zone["name"] for zone in zones]
    # Look up enabled-user-policy count per ordered pair for the grid cells.
    cell_by_pair: dict[tuple[str, str], int] = {}
    for entry in matrix["matrix"]:
        cell_by_pair[(entry["sourceZone"], entry["destinationZone"])] = entry[
            "enabledUserPolicyCount"
        ]

    col_width = 6
    headers = [_abbreviate(name, col_width) for name in zone_names]
    row_label_width = max([len("src \\ dst")] + [len(name) for name in zone_names] + [3])

    lines = ["Firewall zone matrix (cell = enabled user-policy count, - = none):", ""]
    header_row = (
        "src \\ dst".ljust(row_label_width)
        + "  "
        + "  ".join(header.rjust(col_width) for header in headers)
    )
    lines.append(header_row)
    for source in zone_names:
        cells: list[str] = []
        for dest in zone_names:
            if source == dest:
                cells.append("·".rjust(col_width))
                continue
            count = cell_by_pair.get((source, dest))
            text = str(count) if count else "-"
            cells.append(text.rjust(col_width))
        lines.append(source.ljust(row_label_width) + "  " + "  ".join(cells))

    lines.append("")
    lines.append("Legend: · = same zone, - = no enabled user policy, digit = policy count")
    if matrix["unzonedNetworks"]:
        lines.append("Unzoned networks: " + ", ".join(matrix["unzonedNetworks"]))
    else:
        lines.append("Unzoned networks: none")
    if matrix["policiesWithUnknownZones"]:
        lines.append(
            "Policies referencing unknown zones: " + ", ".join(matrix["policiesWithUnknownZones"])
        )
    else:
        lines.append("Policies referencing unknown zones: none")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scored audit (item 2)
# ---------------------------------------------------------------------------


def severity_score(severity: str) -> int:
    return {"critical": 5, "warning": 2, "informational": 1}.get(severity, 0)


def score_label(score: int) -> str:
    if score >= 80:
        return "healthy"
    if score >= 60:
        return "needs_attention"
    return "critical"


def _matrix_coverage(matrix: dict[str, Any]) -> tuple[int, int, float]:
    """Return (pairs_with_policy, total_pairs, coverage_percent)."""
    entries = matrix["matrix"]
    total = len(entries)
    covered = sum(1 for entry in entries if entry["hasExplicitPolicy"])
    percent = round((covered / total) * 100, 1) if total else 100.0
    return covered, total, percent


def build_firewall_audit_report(client: UniFiClient) -> dict[str, Any]:
    site_id = client.site_id()
    networks = _iter_dicts(client.paginate_path(f"/sites/{site_id}/networks"))
    policies = _iter_dicts(client.paginate_path(f"/sites/{site_id}/firewall/policies"))
    zones = _iter_dicts(client.paginate_path(f"/sites/{site_id}/firewall/zones"))
    devices = _iter_dicts(client.paginate_path(f"/sites/{site_id}/devices"))
    acl_rules = _iter_dicts(client.paginate_path(f"/sites/{site_id}/acl-rules"))

    matrix = build_firewall_matrix(zones, policies, networks)

    zone_ids = {str(zone["id"]) for zone in zones if zone.get("id")}
    network_ids = {str(network["id"]) for network in networks if network.get("id")}
    user_policies = [policy for policy in policies if policy_is_user_defined(policy)]
    enabled_user_policies = [p for p in user_policies if p.get("enabled", True)]
    disabled_user_policies = [p for p in user_policies if not p.get("enabled", True)]
    offline_devices = [
        device for device in devices if str(device.get("state", "")).upper() != "ONLINE"
    ]
    online_devices = [
        device for device in devices if str(device.get("state", "")).upper() == "ONLINE"
    ]

    findings: list[dict[str, Any]] = []

    def add_finding(
        benchmark_id: str,
        category: str,
        severity: str,
        message: str,
        *,
        evidence: dict[str, Any] | None = None,
        recommendation: str | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "benchmark_id": benchmark_id,
            "category": category,
            "message": message,
            "severity": severity,
        }
        if evidence:
            item["evidence"] = evidence
        if recommendation:
            item["recommendation"] = recommendation
        findings.append(item)

    # STALE-01 (critical): policies referencing missing zones or missing networks.
    stale_zone_policies: list[str] = []
    for policy in policies:
        source_id, dest_id = _policy_zone_pair(policy)
        name = str(policy.get("name") or policy.get("id") or "")
        missing_zone = (source_id is not None and source_id not in zone_ids) or (
            dest_id is not None and dest_id not in zone_ids
        )
        if missing_zone and name:
            stale_zone_policies.append(name)

    stale_network_policies: list[str] = []
    for policy in policies:
        name = str(policy.get("name") or policy.get("id") or "")
        for referenced in _referenced_network_ids(policy):
            if referenced not in network_ids:
                if name:
                    stale_network_policies.append(name)
                break

    if stale_zone_policies or stale_network_policies:
        add_finding(
            "STALE-01",
            "staleness",
            "critical",
            "Firewall policies reference zones or networks that no longer exist.",
            evidence={
                "policies_with_missing_zone": sorted(set(stale_zone_policies)),
                "policies_with_missing_network": sorted(set(stale_network_policies)),
            },
            recommendation=(
                "Repair or delete policies that point at deleted zones or networks; "
                "they no longer match as intended."
            ),
        )

    # STALE-02 (warning): disabled user policies as clutter.
    if disabled_user_policies:
        add_finding(
            "STALE-02",
            "staleness",
            "warning",
            "Disabled user-defined firewall policies remain in the ruleset.",
            evidence={
                "disabled_policy_count": len(disabled_user_policies),
                "disabled_policy_names": sorted(
                    str(p.get("name") or p.get("id") or "") for p in disabled_user_policies
                ),
            },
            recommendation="Remove disabled policies you no longer need to keep the ruleset clean.",
        )

    # ZONE-01 (informational): zone pairs with networks on both sides but no explicit policy.
    default_deny_pairs = [
        (entry["sourceZone"], entry["destinationZone"])
        for entry in matrix["matrix"]
        if not entry["hasExplicitPolicy"]
    ]
    if default_deny_pairs:
        add_finding(
            "ZONE-01",
            "segmentation",
            "informational",
            "Some zone pairs rely on default-deny with no explicit policy.",
            evidence={
                "default_deny_pairs": [
                    {"sourceZone": src, "destinationZone": dst}
                    for src, dst in sorted(default_deny_pairs)
                ]
            },
            recommendation=(
                "Zone default-deny is a valid design; add explicit policies only where "
                "you want intentional allows to be documented."
            ),
        )

    # ZONE-02 (warning): unconstrained inter-zone ALLOW policies.
    broad_allows: list[str] = []
    for policy in enabled_user_policies:
        if _policy_action(policy) != "ALLOW":
            continue
        source_id, dest_id = _policy_zone_pair(policy)
        if source_id is None or dest_id is None or source_id == dest_id:
            continue
        if not _policy_has_traffic_constraint(policy):
            name = str(policy.get("name") or policy.get("id") or "")
            if name:
                broad_allows.append(name)
    if broad_allows:
        add_finding(
            "ZONE-02",
            "segmentation",
            "warning",
            "Broad ALLOW policies match all traffic between two different zones.",
            evidence={"broad_allow_policies": sorted(set(broad_allows))},
            recommendation=(
                "Constrain inter-zone allows with a trafficFilter, port, or address filter "
                "so they only permit what is intended."
            ),
        )

    # DNS-01 (structural, informational): DNS-control policies and protocol coverage.
    dns_policies = [policy for policy in policies if _policy_targets_port(policy, 53)]
    dns_without_protocol = [
        str(policy.get("name") or policy.get("id") or "")
        for policy in dns_policies
        if not _policy_specifies_protocol(policy)
    ]
    if dns_policies:
        add_finding(
            "DNS-01",
            "hygiene",
            "informational",
            "DNS-control firewall policies (port 53) were detected.",
            evidence={
                "dns_policy_count": len(dns_policies),
                "dns_policies_without_protocol_filter": sorted(
                    name for name in dns_without_protocol if name
                ),
                "note": ("Absent protocolFilter means tcp+udp, which is broader but usually fine."),
            },
            recommendation=(
                "If you meant to pin DNS to a single transport, set an explicit protocolFilter; "
                "otherwise tcp+udp coverage is expected."
            ),
        )

    # HYG-01 (warning): placeholder-style names.
    placeholder_named_policies = [
        str(policy.get("name"))
        for policy in user_policies
        if _is_placeholder_name(str(policy.get("name", "")))
    ]
    if placeholder_named_policies:
        add_finding(
            "HYG-01",
            "hygiene",
            "warning",
            "Some user-defined firewall policies have placeholder-style names.",
            evidence={"placeholder_names": sorted(placeholder_named_policies)},
            recommendation="Rename policies so future audits and changes are easier to review.",
        )

    # TOP-01 (critical): offline devices.
    if offline_devices:
        add_finding(
            "TOP-01",
            "topology",
            "critical",
            "One or more UniFi devices are offline during the audit.",
            evidence={"offline_devices": [device.get("name") for device in offline_devices]},
            recommendation="Bring offline network devices back before trusting topology checks.",
        )

    categories: dict[str, dict[str, Any]] = {}
    for category in ("segmentation", "hygiene", "topology", "staleness"):
        category_findings = [finding for finding in findings if finding["category"] == category]
        deduction = sum(severity_score(finding["severity"]) for finding in category_findings)
        categories[category] = {
            "findings": category_findings,
            "max": 25,
            "score": max(0, 25 - deduction),
        }

    overall_score = sum(item["score"] for item in categories.values())
    recommendations = [
        finding["recommendation"] for finding in findings if finding.get("recommendation")
    ]

    _covered, total_pairs, coverage_percent = _matrix_coverage(matrix)

    return {
        "api_surface": "official_network_integration_v1",
        "categories": categories,
        "critical_findings": [finding for finding in findings if finding["severity"] == "critical"],
        "ok": True,
        "overall_score": overall_score,
        "overall_status": score_label(overall_score),
        "recommendations": recommendations,
        "summary": {
            "acl_rules": len(acl_rules),
            "devices_offline": len(offline_devices),
            "devices_online": len(online_devices),
            "firewall_policies": len(policies),
            "firewall_zones": len(zones),
            "matrix_coverage_percent": coverage_percent,
            "matrix_pairs": total_pairs,
            "networks": len(networks),
            "unzoned_networks": matrix["unzonedNetworks"],
            "user_defined_firewall_policies": len(user_policies),
            "zone_matrix": matrix,
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _is_placeholder_name(name: str) -> bool:
    lowered = name.strip().lower()
    if PLACEHOLDER_NAME_RE.fullmatch(lowered):
        return True
    return bool(DIGITS_ONLY_RE.fullmatch(name.strip()))


def _referenced_network_ids(policy: dict[str, Any]) -> set[str]:
    """Collect network ids a policy's trafficFilter references (NETWORK type).

    Walks trafficFilter/source/destination structures for a NETWORK match and
    returns any network ids it points at, tolerant of shape variants.
    """
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            match_type = str(node.get("matchType") or node.get("type") or "").upper()
            if match_type == "NETWORK":
                for key in ("networkId", "networkIds", "id", "ids", "value", "values"):
                    value = node.get(key)
                    if isinstance(value, str) and value:
                        found.add(value)
                    elif isinstance(value, list):
                        found.update(str(item) for item in value if item)
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    for key in ("trafficFilter", "source", "destination"):
        visit(policy.get(key))
    return found


def format_firewall_audit_human(report: dict[str, Any]) -> str:
    lines = [
        f"Firewall audit score: {report['overall_score']}/100 ({report['overall_status']})",
        f"API surface: {report['api_surface']}",
        "",
        "Category scores:",
    ]
    labels = {
        "segmentation": "Segmentation",
        "hygiene": "Hygiene",
        "topology": "Topology",
        "staleness": "Staleness",
    }
    for key in ("segmentation", "hygiene", "topology", "staleness"):
        category = report["categories"][key]
        lines.append(f"- {labels[key]}: {category['score']}/{category['max']}")

    summary = report["summary"]
    unzoned = summary["unzoned_networks"]
    lines.extend(
        [
            "",
            "Summary:",
            f"- Networks: {summary['networks']}",
            f"- Firewall zones: {summary['firewall_zones']}",
            "- Firewall policies: "
            f"{summary['firewall_policies']} "
            f"({summary['user_defined_firewall_policies']} user-defined)",
            f"- ACL rules: {summary['acl_rules']}",
            f"- Devices online/offline: {summary['devices_online']}/{summary['devices_offline']}",
            f"- Matrix coverage: {summary['matrix_coverage_percent']}% "
            f"of {summary['matrix_pairs']} zone pairs",
            f"- Unzoned networks: {', '.join(unzoned) if unzoned else 'none'}",
        ]
    )

    lines.append("")
    lines.append("Critical findings:")
    if report["critical_findings"]:
        for finding in report["critical_findings"]:
            lines.append(f"- [{finding['benchmark_id']}] {finding['message']}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Other findings:")
    non_critical = [
        finding
        for finding in sum((cat["findings"] for cat in report["categories"].values()), [])
        if finding["severity"] != "critical"
    ]
    if non_critical:
        for finding in non_critical:
            lines.append(
                f"- [{finding['benchmark_id']}] ({finding['severity']}) {finding['message']}"
            )
    else:
        lines.append("- None")

    if report["recommendations"]:
        lines.append("")
        lines.append("Recommendations:")
        for recommendation in report["recommendations"]:
            lines.append(f"- {recommendation}")

    return "\n".join(lines)


def command_firewall_audit(client: UniFiClient, args: argparse.Namespace) -> Any:
    report = build_firewall_audit_report(client)
    if args.format == "human" and not args.json:
        return format_firewall_audit_human(report)
    return report
