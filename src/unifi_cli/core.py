"""Core UniFi request, command, and formatting logic."""

from __future__ import annotations

import argparse
import copy
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from unifi_cli import __version__
from unifi_cli.config import Config

REDACTED = "***REDACTED***"
SECRET_FIELD_NAMES = {
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "passphrase",
    "password",
    "psk",
    "secret",
    "token",
    "x_secret",
    "x_iapp_key",
    "x_passphrase",
}
USER_EDITABLE_FIELDS = [
    "name",
    "note",
    "noted",
    "blocked",
    "usergroup_id",
    "network_id",
    "use_fixedip",
    "fixed_ip",
    "local_dns_record_enabled",
    "local_dns_record",
]
RESOURCE_COLLECTIONS: dict[str, dict[str, Any]] = {
    "dynamic-dns": {
        "description": "Dynamic DNS configurations",
        "lookup": ["_id", "name", "host_name", "hostname"],
        "path": "dynamicdns",
    },
    "firewall-group": {
        "description": "Legacy firewall groups",
        "lookup": ["_id", "name"],
        "path": "firewallgroup",
    },
    "firewall-rule": {
        "description": "Legacy firewall rules",
        "lookup": ["_id", "name"],
        "path": "firewallrule",
    },
    "port-forward": {
        "description": "Port forwarding rules",
        "lookup": ["_id", "name"],
        "path": "portforward",
    },
    "port-profile": {
        "description": "Switch port profiles",
        "lookup": ["_id", "name"],
        "path": "portconf",
    },
    "radius-profile": {
        "description": "RADIUS authentication profiles",
        "lookup": ["_id", "name"],
        "path": "radiusprofile",
    },
    "static-route": {
        "description": "Static routes / routing entries",
        "lookup": ["_id", "name", "static-route_network"],
        "path": "routing",
    },
    "user-group": {
        "description": "Bandwidth / QoS user groups",
        "lookup": ["_id", "name"],
        "path": "usergroup",
    },
    "wlan": {
        "description": "Wireless networks / SSIDs",
        "lookup": ["_id", "external_id", "name"],
        "path": "wlanconf",
    },
}


@dataclass
class UniFiError(RuntimeError):
    """Raised for predictable CLI and API failures."""

    message: str
    code: str = "unifi_error"
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


def ensure_live_config(config: Config) -> None:
    if not config.base_url:
        raise UniFiError(
            "Missing UniFi base URL.",
            code="config_missing",
            details={"hint": "Set UNIFI_BASE_URL or add base_url to ~/.config/unifi/config.toml."},
        )
    if not config.api_key:
        raise UniFiError(
            "Missing UniFi API key.",
            code="config_missing",
            details={"hint": "Set UNIFI_API_KEY or add api_key to ~/.config/unifi/config.toml."},
        )


def scrub_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in SECRET_FIELD_NAMES:
                cleaned[key] = REDACTED
            else:
                cleaned[key] = scrub_sensitive(item)
        return cleaned
    if isinstance(value, list):
        return [scrub_sensitive(item) for item in value]
    return value


def parse_json_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        lowered = raw.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered == "null":
            return None
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        if re.fullmatch(r"-?\d+\.\d+", raw):
            return float(raw)
        return raw


def set_nested(target: dict[str, Any], dotted_key: str, value: Any) -> None:
    cursor: dict[str, Any] = target
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        current = cursor.get(part)
        if not isinstance(current, dict):
            current = {}
            cursor[part] = current
        cursor = current
    cursor[parts[-1]] = value


def extract_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload and isinstance(payload["data"], list):
        return payload["data"]
    return payload


def count_collection(payload: Any) -> int:
    data = extract_data(payload)
    if isinstance(data, list):
        return len(data)
    if isinstance(payload, dict) and isinstance(payload.get("count"), int):
        return int(payload["count"])
    return 0


def resource_config(resource: str) -> dict[str, Any]:
    try:
        return RESOURCE_COLLECTIONS[resource]
    except KeyError as error:
        raise UniFiError(
            "Unknown resource "
            f"'{resource}'. Valid values: {', '.join(sorted(RESOURCE_COLLECTIONS))}",
            code="invalid_argument",
        ) from error


def lower_name(item: dict[str, Any]) -> str:
    return str(item.get("name", "")).strip().lower()


def infer_network_role(network: dict[str, Any]) -> str:
    name = lower_name(network)
    vlan = network.get("vlan")
    if "iot" in name:
        return "iot"
    if "guest" in name or network.get("is_guest"):
        return "guest"
    if "manage" in name or vlan == 10:
        return "management"
    if "dmz" in name or vlan == 60:
        return "dmz"
    if "work" in name or vlan == 255:
        return "work"
    if "storage" in name or vlan == 20:
        return "storage"
    if "lab" in name or vlan == 30:
        return "lab"
    if "home" in name or vlan == 40:
        return "home"
    if name == "default":
        return "default"
    return "other"


def zone_label_from_networks(networks: list[dict[str, Any]]) -> str:
    purposes = {str(network.get("purpose", "")).lower() for network in networks}
    roles = {infer_network_role(network) for network in networks}
    if "wan" in purposes:
        return "External"
    if len(roles) > 1:
        return "Shared LAN"
    if "dmz" in roles:
        return "DMZ"
    if roles & {"default", "home", "iot", "lab", "management", "storage", "work"}:
        return "Internal"
    return "Unknown"


def severity_score(severity: str) -> int:
    return {"critical": 5, "warning": 2, "informational": 1}.get(severity, 0)


def score_label(score: int) -> str:
    if score >= 80:
        return "healthy"
    if score >= 60:
        return "needs_attention"
    return "critical"


class UniFiClient:
    """Thin UniFi API client over the overlapping API surfaces."""

    def __init__(self, config: Config):
        self.config = config
        self._site_id: str | None = config.site_id
        if config.verify_tls:
            self.ssl_context: ssl.SSLContext | None = None
        else:
            self.ssl_context = ssl._create_unverified_context()  # noqa: SLF001

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        payload: Any | None = None,
    ) -> Any:
        ensure_live_config(self.config)
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{self.config.base_url}{path}"

        if query:
            encoded_query = urllib.parse.urlencode(
                [(key, str(value)) for key, value in query.items() if value is not None],
                doseq=True,
            )
            if encoded_query:
                separator = "&" if urllib.parse.urlparse(url).query else "?"
                url = f"{url}{separator}{encoded_query}"

        data_bytes: bytes | None = None
        headers = {"Accept": "application/json", "X-API-KEY": str(self.config.api_key)}
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url, method=method.upper(), data=data_bytes, headers=headers
        )

        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                context=self.ssl_context,
                timeout=self.config.timeout_seconds,
            ) as response:
                body = response.read()
                content_type = response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise UniFiError(
                f"{method.upper()} {url} failed with HTTP {error.code}.",
                code="http_error",
                details={"body": body, "status": error.code},
            ) from error
        except urllib.error.URLError as error:
            raise UniFiError(
                f"{method.upper()} {url} failed.",
                code="network_error",
                details={"reason": str(error.reason)},
            ) from error

        if not body:
            return {"status": "ok"}

        text = body.decode("utf-8", errors="replace")
        if "json" in content_type or text[:1] in {"{", "["}:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
        return {"raw": text}

    def integration(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return self.request(method, f"/proxy/network/integration/v1{suffix}", **kwargs)

    def legacy(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return self.request(method, f"/proxy/network/api/s/{self.config.site}{suffix}", **kwargs)

    def v2(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return self.request(
            method, f"/proxy/network/v2/api/site/{self.config.site}{suffix}", **kwargs
        )

    def sites(self) -> list[dict[str, Any]]:
        payload = self.integration("GET", "/sites")
        sites = extract_data(payload)
        if not isinstance(sites, list):
            raise UniFiError("Unexpected sites payload shape.", code="response_shape")
        return sites

    def site_id(self) -> str:
        if self._site_id:
            return self._site_id

        sites = self.sites()
        if len(sites) == 1 and sites[0].get("id"):
            self._site_id = str(sites[0]["id"])
            return self._site_id

        for site in sites:
            candidate_keys = [
                site.get("id"),
                site.get("name"),
                site.get("slug"),
                site.get("description"),
            ]
            if any(
                str(candidate).lower() == self.config.site.lower()
                for candidate in candidate_keys
                if candidate
            ) and site.get("id"):
                self._site_id = str(site["id"])
                return self._site_id

        raise UniFiError(
            "Could not resolve the UniFi site UUID automatically.",
            code="site_resolution_failed",
            details={"hint": "Set UNIFI_SITE_ID or add site_id to ~/.config/unifi/config.toml."},
        )

    def summary(self) -> dict[str, Any]:
        site_id = self.site_id()
        sites = self.sites()
        devices = self.integration("GET", f"/sites/{site_id}/devices")
        clients = self.integration("GET", f"/sites/{site_id}/clients")
        networks = self.legacy("GET", "/rest/networkconf")
        wlans = self.legacy("GET", "/rest/wlanconf")
        static_dns = self.v2("GET", "/static-dns")
        dns_policies = self.integration(
            "GET", f"/sites/{site_id}/dns/policies", query={"limit": 200}
        )
        wans = self.integration("GET", f"/sites/{site_id}/wans")
        firewall_zones = self.integration("GET", f"/sites/{site_id}/firewall/zones")
        firewall_policies = self.v2("GET", "/firewall-policies")
        traffic_routes = self.v2("GET", "/trafficroutes")
        content_filtering = self.v2("GET", "/content-filtering")
        port_profiles = self.legacy("GET", "/rest/portconf")
        port_forwards = self.legacy("GET", "/rest/portforward")
        static_routes = self.legacy("GET", "/rest/routing")
        user_groups = self.legacy("GET", "/rest/usergroup")
        radius_profiles = self.legacy("GET", "/rest/radiusprofile")
        dynamic_dns = self.legacy("GET", "/rest/dynamicdns")
        firewall_groups = self.legacy("GET", "/rest/firewallgroup")
        firewall_rules = self.legacy("GET", "/rest/firewallrule")

        network_list = extract_data(networks)
        wlan_list = extract_data(wlans)
        return {
            "controller": self.config.base_url,
            "counts": {
                "clients": count_collection(clients),
                "content_filtering_profiles": count_collection(content_filtering),
                "devices": count_collection(devices),
                "dns_policies": count_collection(dns_policies),
                "dynamic_dns": count_collection(dynamic_dns),
                "firewall_groups": count_collection(firewall_groups),
                "firewall_policies": count_collection(firewall_policies),
                "firewall_rules": count_collection(firewall_rules),
                "firewall_zones": count_collection(firewall_zones),
                "networks": count_collection(networks),
                "port_forwards": count_collection(port_forwards),
                "port_profiles": count_collection(port_profiles),
                "radius_profiles": count_collection(radius_profiles),
                "sites": len(sites),
                "static_dns": count_collection(static_dns),
                "static_routes": count_collection(static_routes),
                "traffic_routes": count_collection(traffic_routes),
                "user_groups": count_collection(user_groups),
                "wans": count_collection(wans),
                "wlans": count_collection(wlans),
            },
            "networks": [
                {
                    "dhcp_enabled": item.get("dhcpd_enabled"),
                    "domain_name": item.get("domain_name"),
                    "name": item.get("name"),
                    "purpose": item.get("purpose"),
                    "vlan": item.get("vlan"),
                }
                for item in network_list
                if isinstance(item, dict)
            ],
            "site": self.config.site,
            "site_id": site_id,
            "wlans": [
                {
                    "enabled": item.get("enabled"),
                    "name": item.get("name"),
                    "networkconf_id": item.get("networkconf_id"),
                    "security": item.get("security"),
                }
                for item in wlan_list
                if isinstance(item, dict)
            ],
        }

    def find_client(self, selector: str) -> dict[str, Any]:
        payload = self.legacy("GET", "/rest/user")
        clients = extract_data(payload)
        if not isinstance(clients, list):
            raise UniFiError("Unexpected clients payload shape.", code="response_shape")

        normalized = selector.strip().lower()
        exact: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        for client in clients:
            values = [
                client.get("_id"),
                client.get("mac"),
                client.get("hostname"),
                client.get("name"),
                client.get("local_dns_record"),
            ]
            string_values = [str(value).lower() for value in values if value]
            if normalized in string_values:
                exact.append(client)
            elif any(normalized in value for value in string_values):
                partial.append(client)

        matches = exact or partial
        if not matches:
            raise UniFiError(f"No client matched selector '{selector}'.", code="not_found")
        if len(matches) > 1:
            choices = [
                {
                    "_id": item.get("_id"),
                    "hostname": item.get("hostname"),
                    "local_dns_record": item.get("local_dns_record"),
                    "mac": item.get("mac"),
                    "name": item.get("name"),
                }
                for item in matches[:10]
            ]
            raise UniFiError(
                f"Selector '{selector}' matched multiple clients.",
                code="ambiguous_selector",
                details={"matches": choices},
            )
        return matches[0]

    def find_network(self, selector: str) -> dict[str, Any]:
        payload = self.legacy("GET", "/rest/networkconf")
        networks = extract_data(payload)
        if not isinstance(networks, list):
            raise UniFiError("Unexpected networks payload shape.", code="response_shape")

        normalized = selector.strip().lower()
        matches = [
            network
            for network in networks
            if normalized
            in {
                str(network.get("_id", "")).lower(),
                str(network.get("external_id", "")).lower(),
                str(network.get("name", "")).lower(),
            }
        ]
        if not matches:
            matches = [
                network
                for network in networks
                if normalized in str(network.get("name", "")).lower()
            ]
        if not matches:
            raise UniFiError(f"No network matched selector '{selector}'.", code="not_found")
        if len(matches) > 1:
            raise UniFiError(
                "Network selector matched multiple networks.",
                code="ambiguous_selector",
                details={"matches": [item.get("name") for item in matches]},
            )
        return matches[0]

    def find_static_dns(self, key: str, record_type: str | None = None) -> dict[str, Any]:
        payload = self.v2("GET", "/static-dns")
        records = extract_data(payload)
        if not isinstance(records, list):
            raise UniFiError("Unexpected static DNS payload shape.", code="response_shape")

        normalized_key = key.strip().lower()
        record_type_normalized = record_type.upper() if record_type else None
        matches = []
        for record in records:
            same_key = (
                str(record.get("_id", "")).lower() == normalized_key
                or str(record.get("key", "")).lower() == normalized_key
            )
            same_type = (
                record_type_normalized is None
                or str(record.get("record_type", "")).upper() == record_type_normalized
            )
            if same_key and same_type:
                matches.append(record)
        if not matches:
            raise UniFiError(f"No static DNS record matched '{key}'.", code="not_found")
        if len(matches) > 1:
            raise UniFiError(
                "Static DNS selector matched multiple records.",
                code="ambiguous_selector",
                details={
                    "matches": [
                        {"key": item.get("key"), "record_type": item.get("record_type")}
                        for item in matches
                    ]
                },
            )
        return matches[0]

    def update_client(
        self, client: dict[str, Any], updates: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        payload = {key: client[key] for key in USER_EDITABLE_FIELDS if key in client}
        payload.update(updates)
        if payload.get("note"):
            payload["noted"] = True
        elif "note" in payload and not payload["note"]:
            payload["noted"] = bool(payload.get("noted", False))
        path = f"/rest/user/{client['_id']}"
        return path, payload

    def list_resource(self, resource: str) -> Any:
        config = resource_config(resource)
        return self.legacy("GET", f"/rest/{config['path']}")

    def find_resource(self, resource: str, selector: str) -> dict[str, Any]:
        config = resource_config(resource)
        payload = self.list_resource(resource)
        records = extract_data(payload)
        if not isinstance(records, list):
            raise UniFiError(
                f"Unexpected payload shape for resource '{resource}'.",
                code="response_shape",
            )

        normalized = selector.strip().lower()
        exact: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        lookup_fields = config.get("lookup", [])

        for record in records:
            values = [record.get(field) for field in lookup_fields]
            string_values = [str(value).lower() for value in values if value not in (None, "")]
            if normalized in string_values:
                exact.append(record)
            elif any(normalized in value for value in string_values):
                partial.append(record)

        matches = exact or partial
        if not matches:
            raise UniFiError(f"No {resource} matched selector '{selector}'.", code="not_found")
        if len(matches) > 1:
            preview = [{field: item.get(field) for field in lookup_fields} for item in matches[:10]]
            raise UniFiError(
                f"Selector '{selector}' matched multiple {resource} entries.",
                code="ambiguous_selector",
                details={"matches": preview},
            )
        return matches[0]


def add_write_guard(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--yes", action="store_true", help="apply the write instead of returning a dry-run payload"
    )


def add_query_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="repeatable query-string pair for request/raw commands",
    )


def require_confirmation(args: argparse.Namespace, method: str, path: str, payload: Any) -> None:
    if args.yes:
        return
    raise UniFiError(
        "Write not applied.",
        code="dry_run",
        details={
            "message": "Re-run with --yes to execute.",
            "request": {"method": method.upper(), "path": path, "payload": payload},
        },
    )


def doctor(config: Config) -> tuple[dict[str, Any], bool]:
    report: dict[str, Any] = {
        "api_key_status": {
            "configured": bool(config.api_key),
            "source": config.sources["api_key"],
        },
        "base_url": {
            "configured": bool(config.base_url),
            "source": config.sources["base_url"],
            "value": config.base_url,
        },
        "config_file": {
            "exists": config.config_exists,
            "path": str(config.config_path),
        },
        "site": {
            "source": config.sources["site"],
            "value": config.site,
        },
        "site_id": {
            "configured": bool(config.site_id),
            "source": config.sources["site_id"],
            "value": config.site_id,
        },
        "timeout_seconds": config.timeout_seconds,
        "tls_verification": {
            "enabled": config.verify_tls,
            "source": config.sources["verify_tls"],
        },
        "version": __version__,
    }
    missing: list[str] = []
    if not config.base_url:
        missing.append("UNIFI_BASE_URL")
    if not config.api_key:
        missing.append("UNIFI_API_KEY")
    report["missing"] = missing

    live: dict[str, Any] = {"attempted": False, "ok": False}
    ok = not missing
    if config.base_url and config.api_key:
        live["attempted"] = True
        try:
            client = UniFiClient(config)
            sites = client.sites()
            live["ok"] = True
            live["site_count"] = len(sites)
            try:
                live["resolved_site_id"] = client.site_id()
            except UniFiError as error:
                live["resolved_site_id_error"] = {
                    "code": error.code,
                    "message": str(error),
                    "details": scrub_sensitive(error.details or {}),
                }
                ok = False
        except UniFiError as error:
            live["error"] = {
                "code": error.code,
                "message": str(error),
                "details": scrub_sensitive(error.details or {}),
            }
            ok = False
    report["live_check"] = live
    report["ok"] = ok and live.get("ok", False) if live["attempted"] else ok
    return report, bool(report["ok"])


def format_doctor_human(report: dict[str, Any]) -> str:
    config_status = "present" if report["config_file"]["exists"] else "missing"
    api_key_status = "present" if report["api_key_status"]["configured"] else "missing"
    tls_status = "enabled" if report["tls_verification"]["enabled"] else "disabled"
    lines = [
        f"unifi {report['version']}",
        f"Config file: {report['config_file']['path']} ({config_status})",
        f"Base URL: {report['base_url']['value'] or 'missing'} [{report['base_url']['source']}]",
        f"API key: {api_key_status} [{report['api_key_status']['source']}]",
        f"Site: {report['site']['value']} [{report['site']['source']}]",
        f"Site ID: {report['site_id']['value'] or 'auto'} [{report['site_id']['source']}]",
        f"TLS verification: {tls_status} [{report['tls_verification']['source']}]",
        f"Timeout: {report['timeout_seconds']}s",
    ]
    if report["missing"]:
        lines.append(f"Missing: {', '.join(report['missing'])}")

    live = report["live_check"]
    if live["attempted"] and live.get("ok"):
        lines.append(
            f"Live check: ok ({live['site_count']} site{'s' if live['site_count'] != 1 else ''})"
        )
        if live.get("resolved_site_id"):
            lines.append(f"Resolved site ID: {live['resolved_site_id']}")
        elif live.get("resolved_site_id_error"):
            lines.append(f"Resolved site ID: failed ({live['resolved_site_id_error']['message']})")
    elif live["attempted"]:
        lines.append(f"Live check: failed ({live['error']['message']})")
    else:
        lines.append("Live check: skipped")
    return "\n".join(lines)


def command_summary(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.summary()


def command_sites(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.sites()


def command_devices(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.integration("GET", f"/sites/{client.site_id()}/devices")


def command_clients(client: UniFiClient, args: argparse.Namespace) -> Any:
    if args.online:
        return client.legacy("GET", "/stat/sta")
    return client.legacy("GET", "/rest/user")


def command_client_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.find_client(args.selector)


def command_reservation_set(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_client(args.selector)
    path, payload = client.update_client(
        client_obj,
        {
            "use_fixedip": True,
            "fixed_ip": args.ip,
            **({"network_id": args.network_id} if args.network_id else {}),
        },
    )
    require_confirmation(args, "PUT", f"/proxy/network/api/s/{client.config.site}{path}", payload)
    return client.legacy("PUT", path, payload=payload)


def command_reservation_clear(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_client(args.selector)
    path, payload = client.update_client(client_obj, {"fixed_ip": "", "use_fixedip": False})
    require_confirmation(args, "PUT", f"/proxy/network/api/s/{client.config.site}{path}", payload)
    return client.legacy("PUT", path, payload=payload)


def command_local_dns_set(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_client(args.selector)
    path, payload = client.update_client(
        client_obj,
        {"local_dns_record": args.record, "local_dns_record_enabled": True},
    )
    require_confirmation(args, "PUT", f"/proxy/network/api/s/{client.config.site}{path}", payload)
    return client.legacy("PUT", path, payload=payload)


def command_local_dns_clear(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_client(args.selector)
    path, payload = client.update_client(
        client_obj,
        {"local_dns_record": "", "local_dns_record_enabled": False},
    )
    require_confirmation(args, "PUT", f"/proxy/network/api/s/{client.config.site}{path}", payload)
    return client.legacy("PUT", path, payload=payload)


def command_client_forget(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_client(args.selector)
    payload = {"cmd": "forget-sta", "macs": [client_obj["mac"]]}
    path = f"/proxy/network/api/s/{client.config.site}/cmd/stamgr"
    require_confirmation(args, "POST", path, payload)
    return client.legacy("POST", "/cmd/stamgr", payload=payload)


def command_networks(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.legacy("GET", "/rest/networkconf")


def command_network_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.find_network(args.selector)


def command_network_merge(client: UniFiClient, args: argparse.Namespace) -> Any:
    network = client.find_network(args.selector)
    merged = copy.deepcopy(network)
    for assignment in args.set or []:
        if "=" not in assignment:
            raise UniFiError(
                f"Invalid --set value '{assignment}'. Use dotted.key=value.",
                code="invalid_argument",
            )
        key, raw_value = assignment.split("=", 1)
        set_nested(merged, key, parse_json_value(raw_value))
    path = f"/rest/networkconf/{network['_id']}"
    require_confirmation(args, "PUT", f"/proxy/network/api/s/{client.config.site}{path}", merged)
    return client.legacy("PUT", path, payload=merged)


def command_wlans(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.legacy("GET", "/rest/wlanconf")


def command_wans(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.integration("GET", f"/sites/{client.site_id()}/wans")


def command_dns_static(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.v2("GET", "/static-dns")


def command_dns_policies(client: UniFiClient, args: argparse.Namespace) -> Any:
    query = {"limit": args.limit}
    if args.filter:
        query["filter"] = args.filter
    return client.integration("GET", f"/sites/{client.site_id()}/dns/policies", query=query)


def build_dns_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "enabled": not args.disabled,
        "key": args.key,
        "record_type": args.record_type.upper(),
        "ttl": args.ttl,
        "value": args.value,
    }
    if args.priority is not None:
        payload["priority"] = args.priority
    if args.weight is not None:
        payload["weight"] = args.weight
    if args.port is not None:
        payload["port"] = args.port
    return payload


def command_dns_upsert(client: UniFiClient, args: argparse.Namespace) -> Any:
    payload = build_dns_payload(args)
    try:
        current = client.find_static_dns(args.key, args.record_type)
    except UniFiError as error:
        if error.code != "not_found":
            raise
        current = None

    if current is None:
        path = f"/proxy/network/v2/api/site/{client.config.site}/static-dns"
        require_confirmation(args, "POST", path, payload)
        return client.v2("POST", "/static-dns", payload=payload)

    merged = dict(current)
    merged.update(payload)
    path = f"/proxy/network/v2/api/site/{client.config.site}/static-dns/{current['_id']}"
    require_confirmation(args, "PUT", path, merged)
    return client.v2("PUT", f"/static-dns/{current['_id']}", payload=merged)


def command_dns_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    record = client.find_static_dns(args.selector, args.record_type)
    path = f"/proxy/network/v2/api/site/{client.config.site}/static-dns/{record['_id']}"
    require_confirmation(args, "DELETE", path, {"record": record})
    return client.v2("DELETE", f"/static-dns/{record['_id']}")


def command_firewall_zones(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.integration("GET", f"/sites/{client.site_id()}/firewall/zones")


def command_firewall_policies(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.v2("GET", "/firewall-policies")


def command_traffic_routes(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.v2("GET", "/trafficroutes")


def command_content_filtering(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.v2("GET", "/content-filtering")


def build_firewall_audit_report(client: UniFiClient) -> dict[str, Any]:
    networks_payload = client.legacy("GET", "/rest/networkconf")
    networks = extract_data(networks_payload)
    if not isinstance(networks, list):
        raise UniFiError(
            "Unexpected network payload shape while building firewall audit.", code="response_shape"
        )

    firewall_policies = client.v2("GET", "/firewall-policies")
    if not isinstance(firewall_policies, list):
        raise UniFiError(
            "Unexpected firewall policy payload shape while building firewall audit.",
            code="response_shape",
        )

    devices_payload = client.integration("GET", f"/sites/{client.site_id()}/devices")
    devices = extract_data(devices_payload)
    if not isinstance(devices, list):
        raise UniFiError(
            "Unexpected devices payload shape while building firewall audit.", code="response_shape"
        )

    traffic_routes = client.v2("GET", "/trafficroutes")
    legacy_firewall_rules = extract_data(client.legacy("GET", "/rest/firewallrule"))
    firewall_groups = extract_data(client.legacy("GET", "/rest/firewallgroup"))

    if not isinstance(legacy_firewall_rules, list):
        legacy_firewall_rules = []
    if not isinstance(firewall_groups, list):
        firewall_groups = []

    corporate_networks = [
        network for network in networks if str(network.get("purpose", "")).lower() == "corporate"
    ]
    wan_networks = [
        network for network in networks if str(network.get("purpose", "")).lower() == "wan"
    ]
    networks_by_zone_id: dict[str, list[dict[str, Any]]] = {}
    for network in networks:
        zone_id = str(network.get("firewall_zone_id") or "")
        if not zone_id:
            continue
        networks_by_zone_id.setdefault(zone_id, []).append(network)

    zone_labels = {
        zone_id: zone_label_from_networks(zone_networks)
        for zone_id, zone_networks in networks_by_zone_id.items()
    }

    custom_policies = [policy for policy in firewall_policies if not policy.get("predefined")]
    enabled_custom_policies = [policy for policy in custom_policies if policy.get("enabled", True)]
    enabled_routes = [
        route
        for route in (traffic_routes if isinstance(traffic_routes, list) else [])
        if route.get("enabled", True)
    ]
    online_devices = [
        device for device in devices if str(device.get("state", "")).upper() == "ONLINE"
    ]
    offline_devices = [
        device for device in devices if str(device.get("state", "")).upper() != "ONLINE"
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

    corporate_zone_groups = {
        zone_id: [
            network
            for network in zone_networks
            if str(network.get("purpose", "")).lower() == "corporate"
        ]
        for zone_id, zone_networks in networks_by_zone_id.items()
    }

    iot_network = next(
        (network for network in corporate_networks if infer_network_role(network) == "iot"), None
    )
    management_network = next(
        (network for network in corporate_networks if infer_network_role(network) == "management"),
        None,
    )
    dmz_network = next(
        (network for network in corporate_networks if infer_network_role(network) == "dmz"), None
    )

    if iot_network:
        same_zone = corporate_zone_groups.get(str(iot_network.get("firewall_zone_id")), [])
        peer_names = [
            network.get("name")
            for network in same_zone
            if network.get("_id") != iot_network.get("_id")
        ]
        if peer_names and not enabled_custom_policies and not legacy_firewall_rules:
            add_finding(
                "SEG-01",
                "segmentation",
                "critical",
                "IoT shares a firewall zone with trusted LANs and there are no custom "
                "policies compensating for it.",
                evidence={
                    "iot_network": iot_network.get("name"),
                    "shared_zone_networks": peer_names,
                    "zone_id": iot_network.get("firewall_zone_id"),
                },
                recommendation=(
                    "Create explicit isolation rules for IoT, or move IoT into a distinct "
                    "firewall zone before relying on zone-based policy."
                ),
            )

    if management_network:
        same_zone = corporate_zone_groups.get(str(management_network.get("firewall_zone_id")), [])
        peer_names = [
            network.get("name")
            for network in same_zone
            if network.get("_id") != management_network.get("_id")
        ]
        if peer_names and not enabled_custom_policies and not legacy_firewall_rules:
            add_finding(
                "SEG-02",
                "segmentation",
                "critical",
                "Management shares a firewall zone with non-management networks and no "
                "custom access policy is present.",
                evidence={
                    "management_network": management_network.get("name"),
                    "shared_zone_networks": peer_names,
                    "zone_id": management_network.get("firewall_zone_id"),
                },
                recommendation=(
                    "Restrict management access with explicit allow/block policy or split "
                    "management into a dedicated firewall zone."
                ),
            )

    if dmz_network:
        same_zone = corporate_zone_groups.get(str(dmz_network.get("firewall_zone_id")), [])
        peer_names = [
            network.get("name")
            for network in same_zone
            if network.get("_id") != dmz_network.get("_id")
        ]
        if peer_names and not enabled_custom_policies and not legacy_firewall_rules:
            add_finding(
                "SEG-03",
                "segmentation",
                "critical",
                "DMZ currently shares a firewall zone with internal LANs and no custom "
                "segmentation policy is visible.",
                evidence={
                    "dmz_network": dmz_network.get("name"),
                    "shared_zone_networks": peer_names,
                    "zone_id": dmz_network.get("firewall_zone_id"),
                },
                recommendation=(
                    "Treat DMZ as a separate security boundary: either move it to a "
                    "dedicated zone or add explicit block/allow rules."
                ),
            )

    if len(corporate_networks) > 1 and not enabled_custom_policies and not legacy_firewall_rules:
        add_finding(
            "SEG-04",
            "segmentation",
            "warning",
            "All inter-VLAN behaviour appears to rely on defaults because there are no "
            "custom firewall policies or legacy firewall rules.",
            evidence={
                "corporate_network_count": len(corporate_networks),
                "custom_policy_count": len(enabled_custom_policies),
                "legacy_firewall_rule_count": len(legacy_firewall_rules),
            },
            recommendation=(
                "Document intentional defaults or add explicit inter-VLAN policy for the "
                "network pairs you care about most."
            ),
        )

    internal_zone_ids = [zone_id for zone_id, label in zone_labels.items() if label == "Internal"]
    external_zone_ids = [zone_id for zone_id, label in zone_labels.items() if label == "External"]
    custom_internal_external_policies = [
        policy
        for policy in enabled_custom_policies
        if str(policy.get("source", {}).get("zone_id", "")) in internal_zone_ids
        and str(policy.get("destination", {}).get("zone_id", "")) in external_zone_ids
    ]
    if corporate_networks and wan_networks and not custom_internal_external_policies:
        add_finding(
            "EGR-01",
            "egress_control",
            "warning",
            "No custom outbound policy was found between internal networks and WAN zones.",
            evidence={
                "custom_internal_external_policy_count": len(custom_internal_external_policies),
                "wan_networks": [network.get("name") for network in wan_networks],
            },
            recommendation=(
                "If outbound control matters, add explicit internal-to-WAN policy for IoT, "
                "guest, or other high-risk networks."
            ),
        )

    dns_specific_policies = [
        policy for policy in enabled_custom_policies if "53" in json.dumps(policy)
    ]
    if not dns_specific_policies:
        add_finding(
            "EGR-02",
            "egress_control",
            "warning",
            "No explicit DNS-control policy was detected in the custom firewall policy set.",
            evidence={"custom_dns_policy_count": 0},
            recommendation=(
                "If you want clients pinned to approved resolvers, add explicit DNS policy "
                "rather than relying on convention."
            ),
        )

    if len(custom_policies) == 0:
        add_finding(
            "HYG-01",
            "rule_hygiene",
            "warning",
            "The controller currently has no custom zone-based firewall policies.",
            evidence={"custom_policy_count": 0, "predefined_policy_count": len(firewall_policies)},
            recommendation=(
                "That may be intentional, but it means the security model is almost entirely "
                "the system default. Add named custom policy where you need explicit intent."
            ),
        )

    if len(legacy_firewall_rules) == 0 and len(firewall_groups) == 0:
        add_finding(
            "HYG-02",
            "rule_hygiene",
            "informational",
            "Legacy firewall rule and firewall group collections are both empty.",
            evidence={"firewall_group_count": 0, "legacy_firewall_rule_count": 0},
            recommendation=(
                "This is tidy, but it also means there are no legacy compensating controls "
                "for VLAN segmentation."
            ),
        )

    placeholder_named_policies = [
        policy.get("name")
        for policy in custom_policies
        if re.fullmatch(
            r"(rule|new rule|untitled)( \d+)?", str(policy.get("name", "")).strip().lower()
        )
        or re.fullmatch(r"\d+", str(policy.get("name", "")).strip())
    ]
    if placeholder_named_policies:
        add_finding(
            "HYG-03",
            "rule_hygiene",
            "warning",
            "Some custom firewall policies have placeholder-style names.",
            evidence={"placeholder_names": placeholder_named_policies},
            recommendation=(
                "Rename custom policies so future audits and changes are easier to reason about."
            ),
        )

    if offline_devices:
        add_finding(
            "TOP-01",
            "topology",
            "critical",
            "One or more UniFi devices are offline during the audit.",
            evidence={"offline_devices": [device.get("name") for device in offline_devices]},
            recommendation=(
                "Bring offline network devices back before trusting firewall behaviour or "
                "topology assumptions."
            ),
        )

    categories: dict[str, dict[str, Any]] = {
        "egress_control": {"max": 25},
        "rule_hygiene": {"max": 25},
        "segmentation": {"max": 25},
        "topology": {"max": 25},
    }
    for category in categories:
        category_findings = [finding for finding in findings if finding["category"] == category]
        deduction = sum(severity_score(finding["severity"]) for finding in category_findings)
        categories[category] = {
            "findings": category_findings,
            "max": 25,
            "score": max(0, 25 - deduction),
        }

    overall_score = sum(item["score"] for item in categories.values())
    critical_findings = [finding for finding in findings if finding["severity"] == "critical"]
    recommendations = [
        finding["recommendation"] for finding in findings if finding.get("recommendation")
    ]

    summary = {
        "corporate_networks": len(corporate_networks),
        "custom_policies": len(custom_policies),
        "firewall_groups": len(firewall_groups),
        "legacy_firewall_rules": len(legacy_firewall_rules),
        "offline_devices": len(offline_devices),
        "online_devices": len(online_devices),
        "predefined_policies": len(firewall_policies) - len(custom_policies),
        "total_policies": len(firewall_policies),
        "traffic_routes": len(enabled_routes),
        "zones": [
            {
                "label": zone_labels[zone_id],
                "networks": [network.get("name") for network in zone_networks],
                "zone_id": zone_id,
            }
            for zone_id, zone_networks in networks_by_zone_id.items()
        ],
    }

    return {
        "categories": categories,
        "critical_findings": critical_findings,
        "ok": True,
        "overall_score": overall_score,
        "overall_status": score_label(overall_score),
        "recommendations": recommendations,
        "summary": summary,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def format_firewall_audit_human(report: dict[str, Any]) -> str:
    lines = [
        f"Firewall audit score: {report['overall_score']}/100 ({report['overall_status']})",
        "",
        "Category scores:",
    ]
    labels = {
        "egress_control": "Egress Control",
        "rule_hygiene": "Rule Hygiene",
        "segmentation": "Segmentation",
        "topology": "Topology",
    }
    for key in ["segmentation", "egress_control", "rule_hygiene", "topology"]:
        category = report["categories"][key]
        lines.append(f"- {labels[key]}: {category['score']}/{category['max']}")

    summary = report["summary"]
    lines.extend(
        [
            "",
            "Summary:",
            "- Total firewall policies: "
            f"{summary['total_policies']} ({summary['custom_policies']} custom, "
            f"{summary['predefined_policies']} predefined)",
            f"- Legacy firewall rules: {summary['legacy_firewall_rules']}",
            f"- Firewall groups: {summary['firewall_groups']}",
            f"- Traffic routes: {summary['traffic_routes']}",
            f"- Devices online/offline: {summary['online_devices']}/{summary['offline_devices']}",
        ]
    )
    zone_lines = ", ".join(
        f"{zone['label']}: {', '.join(zone['networks'])}" for zone in summary["zones"]
    )
    lines.append(f"- Zone map: {zone_lines or 'none'}")

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
            lines.append(f"- [{finding['benchmark_id']}] {finding['message']}")
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


def command_resource_types(_client: UniFiClient, _args: argparse.Namespace) -> Any:
    return {
        name: {
            "description": config["description"],
            "lookup": config["lookup"],
            "path": config["path"],
        }
        for name, config in sorted(RESOURCE_COLLECTIONS.items())
    }


def command_resource_list(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.list_resource(args.resource)


def command_resource_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.find_resource(args.resource, args.selector)


def command_resource_create(client: UniFiClient, args: argparse.Namespace) -> Any:
    config = resource_config(args.resource)
    payload = json.loads(args.data_json)
    path = f"/proxy/network/api/s/{client.config.site}/rest/{config['path']}"
    require_confirmation(args, "POST", path, payload)
    return client.legacy("POST", f"/rest/{config['path']}", payload=payload)


def command_resource_merge(client: UniFiClient, args: argparse.Namespace) -> Any:
    config = resource_config(args.resource)
    current = client.find_resource(args.resource, args.selector)
    merged = copy.deepcopy(current)
    for assignment in args.set or []:
        if "=" not in assignment:
            raise UniFiError(
                f"Invalid --set value '{assignment}'. Use dotted.key=value.",
                code="invalid_argument",
            )
        key, raw_value = assignment.split("=", 1)
        set_nested(merged, key, parse_json_value(raw_value))
    path = f"/proxy/network/api/s/{client.config.site}/rest/{config['path']}/{current['_id']}"
    require_confirmation(args, "PUT", path, merged)
    return client.legacy("PUT", f"/rest/{config['path']}/{current['_id']}", payload=merged)


def command_resource_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    config = resource_config(args.resource)
    record = client.find_resource(args.resource, args.selector)
    path = f"/proxy/network/api/s/{client.config.site}/rest/{config['path']}/{record['_id']}"
    require_confirmation(args, "DELETE", path, {"record": record})
    return client.legacy("DELETE", f"/rest/{config['path']}/{record['_id']}")


def parse_query_pairs(pairs: list[str]) -> dict[str, Any]:
    query: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            raise UniFiError(
                f"Invalid query pair '{pair}'. Use KEY=VALUE.",
                code="invalid_argument",
            )
        key, value = pair.split("=", 1)
        query[key] = value
    return query


def command_request(client: UniFiClient, args: argparse.Namespace) -> Any:
    query = parse_query_pairs(args.query)
    payload = json.loads(args.data_json) if args.data_json else None
    if args.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        require_confirmation(args, args.method, args.path, payload)
    return client.request(args.method, args.path, query=query, payload=payload)
