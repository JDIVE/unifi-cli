"""Command-line entrypoint for the UniFi CLI."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from unifi_cli.config import build_config, default_config_path
from unifi_cli.core import (
    RESOURCE_COLLECTIONS,
    UniFiClient,
    UniFiError,
    add_query_args,
    add_write_guard,
    command_client_forget,
    command_client_show,
    command_clients,
    command_content_filtering,
    command_devices,
    command_dns_delete,
    command_dns_policies,
    command_dns_static,
    command_dns_upsert,
    command_firewall_audit,
    command_firewall_policies,
    command_firewall_zones,
    command_local_dns_clear,
    command_local_dns_set,
    command_network_merge,
    command_network_show,
    command_networks,
    command_request,
    command_reservation_clear,
    command_reservation_set,
    command_resource_create,
    command_resource_delete,
    command_resource_list,
    command_resource_merge,
    command_resource_show,
    command_resource_types,
    command_sites,
    command_summary,
    command_traffic_routes,
    command_wans,
    command_wlans,
    doctor,
    format_doctor_human,
    scrub_sensitive,
)


def emit_json(value: Any) -> None:
    json.dump(scrub_sensitive(value), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unifi",
        description="Safe UniFi Network CLI for inventory, DNS, reservations, and raw API access.",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--config",
        help=f"optional config file override (default: {default_config_path()})",
    )
    parser.add_argument("--base-url", help="controller base URL, for example https://192.168.1.1")
    parser.add_argument(
        "--api-key", help="one-off API key override; prefer env or config for normal use"
    )
    parser.add_argument("--site", help="UniFi site name or slug")
    parser.add_argument("--site-id", help="UniFi site UUID if auto-resolution is unreliable")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        help="HTTP timeout for controller requests",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser(
        "doctor", help="check config, auth, and live controller reachability"
    )
    doctor_parser.set_defaults(func=None)

    summary = subparsers.add_parser("summary", help="show a high-level controller summary")
    summary.set_defaults(func=command_summary)

    sites = subparsers.add_parser("sites", help="list sites")
    sites.set_defaults(func=command_sites)

    devices = subparsers.add_parser("devices", help="list devices via integration/v1")
    devices.set_defaults(func=command_devices)

    clients = subparsers.add_parser("clients", help="list clients")
    clients.add_argument("--online", action="store_true", help="use stat/sta instead of rest/user")
    clients.set_defaults(func=command_clients)

    client_show = subparsers.add_parser(
        "client-show",
        help="show one client by id, MAC, hostname, name, or local DNS record",
    )
    client_show.add_argument("selector")
    client_show.set_defaults(func=command_client_show)

    reservation_set = subparsers.add_parser(
        "reservation-set", help="set a DHCP reservation on a client"
    )
    reservation_set.add_argument("selector")
    reservation_set.add_argument("--ip", required=True, help="reserved IP address")
    reservation_set.add_argument("--network-id", help="optional network_id override")
    add_write_guard(reservation_set)
    reservation_set.set_defaults(func=command_reservation_set)

    reservation_clear = subparsers.add_parser(
        "reservation-clear",
        help="remove a DHCP reservation from a client",
    )
    reservation_clear.add_argument("selector")
    add_write_guard(reservation_clear)
    reservation_clear.set_defaults(func=command_reservation_clear)

    local_dns_set = subparsers.add_parser("local-dns-set", help="set a per-client local DNS record")
    local_dns_set.add_argument("selector")
    local_dns_set.add_argument("--record", required=True, help="local DNS hostname")
    add_write_guard(local_dns_set)
    local_dns_set.set_defaults(func=command_local_dns_set)

    local_dns_clear = subparsers.add_parser(
        "local-dns-clear",
        help="clear a per-client local DNS record",
    )
    local_dns_clear.add_argument("selector")
    add_write_guard(local_dns_clear)
    local_dns_clear.set_defaults(func=command_local_dns_clear)

    client_forget = subparsers.add_parser("client-forget", help="forget a client via stamgr")
    client_forget.add_argument("selector")
    add_write_guard(client_forget)
    client_forget.set_defaults(func=command_client_forget)

    networks = subparsers.add_parser("networks", help="list networks / VLAN configs")
    networks.set_defaults(func=command_networks)

    network_show = subparsers.add_parser(
        "network-show",
        help="show one network by id, external_id, or name",
    )
    network_show.add_argument("selector")
    network_show.set_defaults(func=command_network_show)

    network_merge = subparsers.add_parser(
        "network-merge",
        help="fetch-merge-update a network using repeatable dotted --set assignments",
    )
    network_merge.add_argument("selector")
    network_merge.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="repeatable dotted assignment such as dhcpd_start=10.0.0.10",
    )
    add_write_guard(network_merge)
    network_merge.set_defaults(func=command_network_merge)

    wlans = subparsers.add_parser("wlans", help="list Wi-Fi broadcasts from wlanconf")
    wlans.set_defaults(func=command_wlans)

    wans = subparsers.add_parser("wans", help="list WANs")
    wans.set_defaults(func=command_wans)

    dns_static = subparsers.add_parser("dns-static", help="list static DNS records from v2")
    dns_static.set_defaults(func=command_dns_static)

    dns_policies = subparsers.add_parser(
        "dns-policies", help="list DNS policies from integration/v1"
    )
    dns_policies.add_argument("--limit", type=int, default=200)
    dns_policies.add_argument("--filter", help="official API filter string")
    dns_policies.set_defaults(func=command_dns_policies)

    dns_upsert = subparsers.add_parser("dns-upsert", help="create or update a static DNS record")
    dns_upsert.add_argument("--key", required=True)
    dns_upsert.add_argument("--record-type", required=True)
    dns_upsert.add_argument("--value", required=True)
    dns_upsert.add_argument("--ttl", type=int, default=0)
    dns_upsert.add_argument("--priority", type=int)
    dns_upsert.add_argument("--weight", type=int)
    dns_upsert.add_argument("--port", type=int)
    dns_upsert.add_argument("--disabled", action="store_true")
    add_write_guard(dns_upsert)
    dns_upsert.set_defaults(func=command_dns_upsert)

    dns_delete = subparsers.add_parser("dns-delete", help="delete a static DNS record by key or id")
    dns_delete.add_argument("selector")
    dns_delete.add_argument("--record-type", help="optional record type when key is ambiguous")
    add_write_guard(dns_delete)
    dns_delete.set_defaults(func=command_dns_delete)

    firewall_zones = subparsers.add_parser("firewall-zones", help="list firewall zones")
    firewall_zones.set_defaults(func=command_firewall_zones)

    firewall_policies = subparsers.add_parser(
        "firewall-policies",
        help="list firewall policies from v2",
    )
    firewall_policies.set_defaults(func=command_firewall_policies)

    firewall_audit = subparsers.add_parser(
        "firewall-audit",
        help="run a scored local firewall audit using live UniFi policy data",
    )
    firewall_audit.add_argument("--format", choices=["json", "human"], default="json")
    firewall_audit.set_defaults(func=command_firewall_audit)

    traffic_routes = subparsers.add_parser("traffic-routes", help="list traffic routes from v2")
    traffic_routes.set_defaults(func=command_traffic_routes)

    content_filtering = subparsers.add_parser(
        "content-filtering",
        help="list content filtering profiles from v2",
    )
    content_filtering.set_defaults(func=command_content_filtering)

    resource_types = subparsers.add_parser(
        "resource-types",
        help="list the generic legacy resource collections supported by the CLI",
    )
    resource_types.set_defaults(func=command_resource_types)

    resource_list = subparsers.add_parser(
        "resource-list",
        help="list one of the generic legacy UniFi resource collections",
    )
    resource_list.add_argument("resource", choices=sorted(RESOURCE_COLLECTIONS))
    resource_list.set_defaults(func=command_resource_list)

    resource_show = subparsers.add_parser(
        "resource-show",
        help="show one object from a generic legacy resource collection",
    )
    resource_show.add_argument("resource", choices=sorted(RESOURCE_COLLECTIONS))
    resource_show.add_argument("selector")
    resource_show.set_defaults(func=command_resource_show)

    resource_create = subparsers.add_parser(
        "resource-create",
        help="create one object in a generic legacy resource collection using --data-json",
    )
    resource_create.add_argument("resource", choices=sorted(RESOURCE_COLLECTIONS))
    resource_create.add_argument("--data-json", required=True, help="full JSON object to POST")
    add_write_guard(resource_create)
    resource_create.set_defaults(func=command_resource_create)

    resource_merge = subparsers.add_parser(
        "resource-merge",
        help="fetch-merge-update one object in a generic legacy resource collection",
    )
    resource_merge.add_argument("resource", choices=sorted(RESOURCE_COLLECTIONS))
    resource_merge.add_argument("selector")
    resource_merge.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="repeatable dotted assignment such as enabled=false",
    )
    add_write_guard(resource_merge)
    resource_merge.set_defaults(func=command_resource_merge)

    resource_delete = subparsers.add_parser(
        "resource-delete",
        help="delete one object from a generic legacy resource collection",
    )
    resource_delete.add_argument("resource", choices=sorted(RESOURCE_COLLECTIONS))
    resource_delete.add_argument("selector")
    add_write_guard(resource_delete)
    resource_delete.set_defaults(func=command_resource_delete)

    request_parser = subparsers.add_parser(
        "request",
        aliases=["raw"],
        help="send a raw request to the controller",
    )
    request_parser.add_argument("--method", default="GET")
    request_parser.add_argument("path", help="absolute URL or controller-relative path")
    request_parser.add_argument("--data-json", help="JSON body for POST, PUT, or PATCH requests")
    add_query_args(request_parser)
    add_write_guard(request_parser)
    request_parser.set_defaults(func=command_request)

    return parser


def emit_error(error: UniFiError, *, as_json: bool) -> None:
    if as_json:
        emit_json(
            {
                "error": {
                    "code": error.code,
                    "details": scrub_sensitive(error.details or {}),
                    "message": str(error),
                },
                "ok": False,
            }
        )
    else:
        print(str(error), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = build_config(args)
        if args.command == "doctor":
            report, ok = doctor(config)
            if args.json:
                emit_json(report)
            else:
                print(format_doctor_human(report))
            return 0 if ok else 1

        client = UniFiClient(config)
        if args.func is None:
            raise UniFiError("No command selected.", code="invalid_argument")

        result = args.func(client, args)
        if args.json or not isinstance(result, str):
            emit_json(result)
        else:
            print(result)
        return 0
    except UniFiError as error:
        if error.code == "dry_run":
            details = error.details or {}
            emit_json(
                {
                    "message": details.get("message", "Write not applied."),
                    "ok": True,
                    "request": details.get("request"),
                    "status": "dry-run",
                }
            )
            return 0
        emit_error(error, as_json=args.json)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
