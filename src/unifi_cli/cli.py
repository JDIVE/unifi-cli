"""Command-line entrypoint for the UniFi CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Any

from unifi_cli.config import build_config, default_config_path
from unifi_cli.core import (
    LEGACY_RESOURCES,
    OFFICIAL_RESOURCES,
    UniFiClient,
    UniFiError,
    add_list_args,
    add_query_args,
    add_write_guard,
    command_acl_rules,
    command_app_info,
    command_client_action,
    command_client_forget,
    command_client_show,
    command_clients,
    command_connector_request,
    command_countries,
    command_device_action,
    command_device_adopt,
    command_device_remove,
    command_device_show,
    command_device_statistics,
    command_device_tags,
    command_devices,
    command_dns_delete,
    command_dns_policies,
    command_dns_policy_show,
    command_dns_upsert,
    command_dpi_applications,
    command_dpi_categories,
    command_firewall_audit,
    command_firewall_policies,
    command_firewall_zones,
    command_legacy_fallback_delete,
    command_legacy_fallback_list,
    command_legacy_fallback_merge,
    command_legacy_fallback_show,
    command_legacy_fallback_types,
    command_local_dns_clear,
    command_local_dns_set,
    command_network_references,
    command_network_show,
    command_networks,
    command_official_create,
    command_official_delete,
    command_official_list,
    command_official_merge,
    command_official_ordering,
    command_official_patch,
    command_official_reorder,
    command_official_show,
    command_pending_devices,
    command_port_action,
    command_radius_profiles,
    command_remembered_client_show,
    command_remembered_clients,
    command_request,
    command_reservation_clear,
    command_reservation_set,
    command_site_to_site_vpns,
    command_sites,
    command_summary,
    command_traffic_matching_lists,
    command_voucher_delete,
    command_voucher_show,
    command_vouchers,
    command_vouchers_delete,
    command_vouchers_generate,
    command_vpn_servers,
    command_wans,
    command_wifi_broadcast_show,
    command_wifi_broadcasts,
    doctor,
    format_doctor_human,
    scrub_sensitive,
)

CommandFunc = Callable[..., Any]


def emit_json(value: Any) -> None:
    json.dump(scrub_sensitive(value), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def bind(func: CommandFunc, *extra: str) -> CommandFunc:
    def wrapped(client: UniFiClient, args: argparse.Namespace) -> Any:
        return func(client, args, *extra)

    return wrapped


def add_data_json(parser: argparse.ArgumentParser, *, required: bool = True) -> None:
    parser.add_argument("--data-json", required=required, help="JSON request body")


def add_merge_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("selector")
    parser.add_argument("--data-json", help="JSON object to shallow-merge before --set values")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="repeatable dotted assignment such as enabled=false",
    )
    add_write_guard(parser)


def add_connector_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("console_id", help="UniFi console id from Site Manager")
    parser.add_argument(
        "path",
        help="proxied application path such as network/integration/v1/sites",
    )
    parser.add_argument(
        "--cloud-base-url",
        default="https://api.ui.com",
        help="UniFi Site Manager API base URL",
    )
    parser.add_argument("--data-json", help="JSON body to forward")
    add_query_args(parser)
    add_write_guard(parser)


def add_official_crud(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    resource: str,
    noun: str,
    plural: str,
    list_func: CommandFunc | None = None,
    show_func: CommandFunc | None = None,
    aliases: tuple[str, ...] = (),
) -> None:
    list_parser = subparsers.add_parser(plural, aliases=list(aliases), help=f"list {plural}")
    add_list_args(list_parser)
    list_parser.set_defaults(func=list_func or bind(command_official_list, resource))

    show_parser = subparsers.add_parser(f"{noun}-show", help=f"show one {noun}")
    show_parser.add_argument("selector")
    show_parser.set_defaults(func=show_func or bind(command_official_show, resource))

    spec = OFFICIAL_RESOURCES[resource]
    if spec.supports_create:
        create_parser = subparsers.add_parser(f"{noun}-create", help=f"create one {noun}")
        add_data_json(create_parser)
        add_write_guard(create_parser)
        create_parser.set_defaults(func=bind(command_official_create, resource))

    if spec.supports_update:
        merge_parser = subparsers.add_parser(f"{noun}-merge", help=f"fetch-merge-update one {noun}")
        add_merge_args(merge_parser)
        merge_parser.set_defaults(func=bind(command_official_merge, resource))

    if spec.supports_patch:
        patch_parser = subparsers.add_parser(
            f"{noun}-patch", help=f"patch one {noun} using --data-json"
        )
        patch_parser.add_argument("selector")
        add_data_json(patch_parser)
        add_write_guard(patch_parser)
        patch_parser.set_defaults(func=bind(command_official_patch, resource))

    if spec.supports_delete:
        delete_parser = subparsers.add_parser(f"{noun}-delete", help=f"delete one {noun}")
        delete_parser.add_argument("selector")
        if resource in {"network", "wifi-broadcast"}:
            delete_parser.add_argument(
                "--force",
                action="store_true",
                help="set the official force=true query parameter",
            )
        add_write_guard(delete_parser)
        delete_parser.set_defaults(func=bind(command_official_delete, resource))

    if spec.supports_ordering:
        ordering_parser = subparsers.add_parser(
            f"{noun}-ordering", help=f"show user-defined {noun} ordering"
        )
        if resource == "firewall-policy":
            ordering_parser.add_argument("--source-zone", required=True)
            ordering_parser.add_argument("--destination-zone", required=True)
        ordering_parser.set_defaults(func=bind(command_official_ordering, resource))

        reorder_parser = subparsers.add_parser(
            f"{noun}-reorder", help=f"replace user-defined {noun} ordering"
        )
        if resource == "firewall-policy":
            reorder_parser.add_argument("--source-zone", required=True)
            reorder_parser.add_argument("--destination-zone", required=True)
        add_data_json(reorder_parser)
        add_write_guard(reorder_parser)
        reorder_parser.set_defaults(func=bind(command_official_reorder, resource))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unifi",
        description="Safe UniFi Network CLI built around the official local Network API.",
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

    app_info = subparsers.add_parser("app-info", help="show UniFi Network application info")
    app_info.set_defaults(func=command_app_info)

    summary = subparsers.add_parser("summary", help="show a high-level controller summary")
    summary.set_defaults(func=command_summary)

    sites = subparsers.add_parser("sites", help="list local sites")
    add_list_args(sites)
    sites.set_defaults(func=command_sites)

    add_official_crud(
        subparsers,
        resource="device",
        noun="device",
        plural="devices",
        list_func=command_devices,
        show_func=command_device_show,
    )
    pending_devices = subparsers.add_parser(
        "pending-devices", help="list devices pending adoption via official API"
    )
    add_list_args(pending_devices)
    pending_devices.set_defaults(func=command_pending_devices)

    device_adopt = subparsers.add_parser("device-adopt", help="adopt a pending UniFi device")
    device_adopt.add_argument("--mac-address", help="pending device MAC address")
    device_adopt.add_argument(
        "--ignore-device-limit",
        action="store_true",
        help="set the official ignoreDeviceLimit field",
    )
    device_adopt.add_argument("--data-json", help="full JSON body, used instead of flags")
    add_write_guard(device_adopt)
    device_adopt.set_defaults(func=command_device_adopt)

    device_remove = subparsers.add_parser(
        "device-remove", help="remove / unadopt one adopted UniFi device"
    )
    device_remove.add_argument("selector")
    add_write_guard(device_remove)
    device_remove.set_defaults(func=command_device_remove)

    device_statistics = subparsers.add_parser(
        "device-statistics", help="show latest statistics for one adopted device"
    )
    device_statistics.add_argument("selector")
    device_statistics.set_defaults(func=command_device_statistics)

    device_action = subparsers.add_parser(
        "device-action", help="execute an official adopted-device action"
    )
    device_action.add_argument("selector")
    device_action.add_argument("--action", help="official action name")
    device_action.add_argument("--data-json", help="full JSON body, used instead of --action")
    add_write_guard(device_action)
    device_action.set_defaults(func=command_device_action)

    port_action = subparsers.add_parser(
        "port-action", help="execute an official switch-port action"
    )
    port_action.add_argument("selector", help="device selector")
    port_action.add_argument("port", type=int, help="port index")
    port_action.add_argument("--action", help="official action name")
    port_action.add_argument("--data-json", help="full JSON body, used instead of --action")
    add_write_guard(port_action)
    port_action.set_defaults(func=command_port_action)

    clients = subparsers.add_parser("clients", help="list connected clients via official API")
    add_list_args(clients)
    clients.set_defaults(func=command_clients)

    client_show = subparsers.add_parser("client-show", help="show one connected client")
    client_show.add_argument("selector")
    client_show.set_defaults(func=command_client_show)

    client_action = subparsers.add_parser(
        "client-action", help="execute an official connected-client action"
    )
    client_action.add_argument("selector")
    client_action.add_argument("--action", help="official action name, for example BLOCK")
    client_action.add_argument("--data-json", help="full JSON body, used instead of --action")
    add_write_guard(client_action)
    client_action.set_defaults(func=command_client_action)

    remembered_clients = subparsers.add_parser(
        "remembered-clients",
        help="legacy fallback: list remembered clients for reservation/local-DNS state",
    )
    remembered_clients.set_defaults(func=command_remembered_clients)

    remembered_client_show = subparsers.add_parser(
        "remembered-client-show",
        help="legacy fallback: show remembered client reservation/local-DNS fields",
    )
    remembered_client_show.add_argument("selector")
    remembered_client_show.set_defaults(func=command_remembered_client_show)

    reservation_set = subparsers.add_parser(
        "reservation-set",
        help="legacy fallback: set a DHCP reservation on a remembered client",
    )
    reservation_set.add_argument("selector")
    reservation_set.add_argument("--ip", required=True, help="reserved IP address")
    reservation_set.add_argument("--network-id", help="optional legacy network_id override")
    add_write_guard(reservation_set)
    reservation_set.set_defaults(func=command_reservation_set)

    reservation_clear = subparsers.add_parser(
        "reservation-clear",
        help="legacy fallback: remove a DHCP reservation from a remembered client",
    )
    reservation_clear.add_argument("selector")
    add_write_guard(reservation_clear)
    reservation_clear.set_defaults(func=command_reservation_clear)

    local_dns_set = subparsers.add_parser(
        "local-dns-set", help="legacy fallback: set a per-client local DNS record"
    )
    local_dns_set.add_argument("selector")
    local_dns_set.add_argument("--record", required=True, help="local DNS hostname")
    add_write_guard(local_dns_set)
    local_dns_set.set_defaults(func=command_local_dns_set)

    local_dns_clear = subparsers.add_parser(
        "local-dns-clear",
        help="legacy fallback: clear a per-client local DNS record",
    )
    local_dns_clear.add_argument("selector")
    add_write_guard(local_dns_clear)
    local_dns_clear.set_defaults(func=command_local_dns_clear)

    client_forget = subparsers.add_parser(
        "client-forget", help="legacy fallback: forget a remembered client via stamgr"
    )
    client_forget.add_argument("selector")
    add_write_guard(client_forget)
    client_forget.set_defaults(func=command_client_forget)

    add_official_crud(
        subparsers,
        resource="network",
        noun="network",
        plural="networks",
        list_func=command_networks,
        show_func=command_network_show,
    )
    network_refs = subparsers.add_parser(
        "network-references", help="show official references for one network"
    )
    network_refs.add_argument("selector")
    network_refs.set_defaults(func=command_network_references)

    add_official_crud(
        subparsers,
        resource="wifi-broadcast",
        noun="wifi-broadcast",
        plural="wifi-broadcasts",
        aliases=("wlans",),
        list_func=command_wifi_broadcasts,
        show_func=command_wifi_broadcast_show,
    )

    dns_policies = subparsers.add_parser(
        "dns-policies",
        aliases=["dns-static"],
        help="list official DNS policies / static DNS records",
    )
    add_list_args(dns_policies)
    dns_policies.set_defaults(func=command_dns_policies)

    dns_show = subparsers.add_parser("dns-show", help="show one official DNS policy")
    dns_show.add_argument("selector")
    dns_show.add_argument("--record-type", help="optional A, A_RECORD, or CNAME disambiguator")
    dns_show.set_defaults(func=command_dns_policy_show)

    dns_upsert = subparsers.add_parser("dns-upsert", help="create or update an official DNS policy")
    dns_upsert.add_argument("--domain", help="DNS name; preferred over legacy --key")
    dns_upsert.add_argument("--key", help="legacy alias for --domain")
    dns_upsert.add_argument("--record-type", required=True, help="A, A_RECORD, or CNAME")
    dns_upsert.add_argument("--value", required=True, help="IPv4 address or CNAME target")
    dns_upsert.add_argument("--ttl", type=int, default=0)
    dns_upsert.add_argument("--disabled", action="store_true")
    add_write_guard(dns_upsert)
    dns_upsert.set_defaults(func=command_dns_upsert)

    dns_delete = subparsers.add_parser("dns-delete", help="delete an official DNS policy")
    dns_delete.add_argument("selector")
    dns_delete.add_argument("--record-type", help="optional A, A_RECORD, or CNAME disambiguator")
    add_write_guard(dns_delete)
    dns_delete.set_defaults(func=command_dns_delete)

    add_official_crud(
        subparsers,
        resource="firewall-zone",
        noun="firewall-zone",
        plural="firewall-zones",
        list_func=command_firewall_zones,
    )
    add_official_crud(
        subparsers,
        resource="firewall-policy",
        noun="firewall-policy",
        plural="firewall-policies",
        list_func=command_firewall_policies,
    )
    add_official_crud(
        subparsers,
        resource="acl-rule",
        noun="acl-rule",
        plural="acl-rules",
        list_func=command_acl_rules,
    )
    add_official_crud(
        subparsers,
        resource="traffic-matching-list",
        noun="traffic-matching-list",
        plural="traffic-matching-lists",
        list_func=command_traffic_matching_lists,
    )

    firewall_audit = subparsers.add_parser(
        "firewall-audit",
        help="run a scored audit using official firewall, ACL, network, and device data",
    )
    firewall_audit.add_argument("--format", choices=["json", "human"], default="json")
    firewall_audit.set_defaults(func=command_firewall_audit)

    for name, func, help_text in [
        ("wans", command_wans, "list official WAN interfaces"),
        ("radius-profiles", command_radius_profiles, "list official RADIUS profiles"),
        ("device-tags", command_device_tags, "list official device tags"),
        ("vpn-servers", command_vpn_servers, "list official VPN servers"),
        ("site-to-site-vpns", command_site_to_site_vpns, "list official site-to-site VPNs"),
        ("vouchers", command_vouchers, "list official hotspot vouchers"),
    ]:
        item = subparsers.add_parser(name, help=help_text)
        add_list_args(item)
        item.set_defaults(func=func)

    for name, metadata_func, help_text in [
        ("dpi-categories", command_dpi_categories, "list official DPI application categories"),
        ("dpi-applications", command_dpi_applications, "list official DPI applications"),
        ("countries", command_countries, "list official country metadata"),
    ]:
        item = subparsers.add_parser(name, help=help_text)
        add_list_args(item)
        item.set_defaults(func=metadata_func)

    voucher_show = subparsers.add_parser("voucher-show", help="show one official hotspot voucher")
    voucher_show.add_argument("selector")
    voucher_show.set_defaults(func=command_voucher_show)

    vouchers_generate = subparsers.add_parser(
        "vouchers-generate", help="generate official hotspot vouchers"
    )
    add_data_json(vouchers_generate)
    add_write_guard(vouchers_generate)
    vouchers_generate.set_defaults(func=command_vouchers_generate)

    voucher_delete = subparsers.add_parser("voucher-delete", help="delete one hotspot voucher")
    voucher_delete.add_argument("selector")
    add_write_guard(voucher_delete)
    voucher_delete.set_defaults(func=command_voucher_delete)

    vouchers_delete = subparsers.add_parser(
        "vouchers-delete", help="bulk-delete hotspot vouchers by official filter"
    )
    vouchers_delete.add_argument("--filter", required=True, help="official voucher filter string")
    add_write_guard(vouchers_delete)
    vouchers_delete.set_defaults(func=command_vouchers_delete)

    fallback_types = subparsers.add_parser(
        "legacy-fallback-types",
        help="list legacy fallback resources that lack official Network API coverage",
    )
    fallback_types.set_defaults(func=command_legacy_fallback_types)

    fallback_list = subparsers.add_parser(
        "legacy-fallback-list",
        help="list one legacy fallback resource",
    )
    fallback_list.add_argument("resource", choices=sorted(LEGACY_RESOURCES))
    fallback_list.set_defaults(func=command_legacy_fallback_list)

    fallback_show = subparsers.add_parser(
        "legacy-fallback-show",
        help="show one object from a legacy fallback resource",
    )
    fallback_show.add_argument("resource", choices=sorted(LEGACY_RESOURCES))
    fallback_show.add_argument("selector")
    fallback_show.set_defaults(func=command_legacy_fallback_show)

    fallback_merge = subparsers.add_parser(
        "legacy-fallback-merge",
        help="fetch-merge-update one legacy fallback object",
    )
    fallback_merge.add_argument("resource", choices=sorted(LEGACY_RESOURCES))
    add_merge_args(fallback_merge)
    fallback_merge.set_defaults(func=command_legacy_fallback_merge)

    fallback_delete = subparsers.add_parser(
        "legacy-fallback-delete",
        help="delete one legacy fallback object",
    )
    fallback_delete.add_argument("resource", choices=sorted(LEGACY_RESOURCES))
    fallback_delete.add_argument("selector")
    add_write_guard(fallback_delete)
    fallback_delete.set_defaults(func=command_legacy_fallback_delete)

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        command_name = f"connector-{method.lower()}"
        connector = subparsers.add_parser(
            command_name,
            help=f"forward a {method} request through the official Cloud Connector API",
        )
        add_connector_args(connector)
        connector.set_defaults(func=bind(command_connector_request, method))

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
        if (
            getattr(args, "action", None) is None
            and getattr(args, "data_json", None) is None
            and args.command in {"client-action", "device-action", "port-action"}
        ):
            raise UniFiError(
                f"{args.command} requires --action or --data-json.",
                code="invalid_argument",
            )

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
