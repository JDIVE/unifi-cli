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
OFFICIAL_API_BASE = "/proxy/network/integration/v1"
LEGACY_API_BASE_TEMPLATE = "/proxy/network/api/s/{site}"
LEGACY_V2_BASE_TEMPLATE = "/proxy/network/v2/api/site/{site}"
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
LEGACY_CLIENT_EDITABLE_FIELDS = [
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
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OfficialResource:
    """An official UniFi Network API collection."""

    name: str
    collection: str
    item_label: str
    lookup_fields: tuple[str, ...]
    supports_create: bool = False
    supports_update: bool = False
    supports_patch: bool = False
    supports_delete: bool = False
    supports_ordering: bool = False


@dataclass(frozen=True)
class LegacyResource:
    """A legacy fallback collection kept only when the official API lacks coverage."""

    description: str
    path: str
    lookup_fields: tuple[str, ...]


OFFICIAL_RESOURCES: dict[str, OfficialResource] = {
    "acl-rule": OfficialResource(
        name="acl-rule",
        collection="acl-rules",
        item_label="aclRuleId",
        lookup_fields=("id", "name"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
        supports_ordering=True,
    ),
    "client": OfficialResource(
        name="client",
        collection="clients",
        item_label="clientId",
        lookup_fields=("id", "name", "macAddress", "ipAddress"),
    ),
    "device": OfficialResource(
        name="device",
        collection="devices",
        item_label="deviceId",
        lookup_fields=("id", "name", "macAddress", "ipAddress"),
    ),
    "dns-policy": OfficialResource(
        name="dns-policy",
        collection="dns/policies",
        item_label="dnsPolicyId",
        lookup_fields=("id", "domain", "type"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
    ),
    "firewall-policy": OfficialResource(
        name="firewall-policy",
        collection="firewall/policies",
        item_label="firewallPolicyId",
        lookup_fields=("id", "name"),
        supports_create=True,
        supports_update=True,
        supports_patch=True,
        supports_delete=True,
        supports_ordering=True,
    ),
    "firewall-zone": OfficialResource(
        name="firewall-zone",
        collection="firewall/zones",
        item_label="firewallZoneId",
        lookup_fields=("id", "name"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
    ),
    "network": OfficialResource(
        name="network",
        collection="networks",
        item_label="networkId",
        lookup_fields=("id", "name", "vlanId"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
    ),
    "traffic-matching-list": OfficialResource(
        name="traffic-matching-list",
        collection="traffic-matching-lists",
        item_label="trafficMatchingListId",
        lookup_fields=("id", "name"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
    ),
    "wifi-broadcast": OfficialResource(
        name="wifi-broadcast",
        collection="wifi/broadcasts",
        item_label="wifiBroadcastId",
        lookup_fields=("id", "name"),
        supports_create=True,
        supports_update=True,
        supports_delete=True,
    ),
}

LEGACY_RESOURCES: dict[str, LegacyResource] = {
    "content-filtering": LegacyResource(
        description="Content filtering profiles; not exposed by the official Network API docs.",
        lookup_fields=("_id", "id", "name"),
        path="/content-filtering",
    ),
    "dynamic-dns": LegacyResource(
        description="Dynamic DNS configurations; no official Network API endpoint is documented.",
        lookup_fields=("_id", "name", "host_name", "hostname"),
        path="/rest/dynamicdns",
    ),
    "port-forward": LegacyResource(
        description="Port forwarding rules; no official Network API endpoint is documented.",
        lookup_fields=("_id", "name"),
        path="/rest/portforward",
    ),
    "port-profile": LegacyResource(
        description="Switch port profiles; official API exposes port actions but not profiles.",
        lookup_fields=("_id", "name"),
        path="/rest/portconf",
    ),
    "static-route": LegacyResource(
        description="Static routes; no official Network API endpoint is documented.",
        lookup_fields=("_id", "name", "static-route_network"),
        path="/rest/routing",
    ),
    "traffic-route": LegacyResource(
        description=(
            "Traffic routes; official API exposes traffic matching lists, not this route set."
        ),
        lookup_fields=("_id", "id", "name"),
        path="/trafficroutes",
    ),
    "user-group": LegacyResource(
        description="Bandwidth / QoS user groups; no official Network API endpoint is documented.",
        lookup_fields=("_id", "name"),
        path="/rest/usergroup",
    ),
}


@dataclass
class UniFiError(RuntimeError):
    """Raised for predictable CLI and API failures."""

    message: str
    code: str = "unifi_error"
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


def ensure_live_config(config: Config, *, require_base_url: bool = True) -> None:
    if require_base_url and not config.base_url:
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


def parse_data_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise UniFiError(
            "Invalid JSON supplied to --data-json.",
            code="invalid_argument",
            details={"error": str(error)},
        ) from error


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


def data_list(payload: Any) -> list[Any]:
    data = extract_data(payload)
    return data if isinstance(data, list) else []


def with_limit(args: argparse.Namespace) -> dict[str, Any]:
    query: dict[str, Any] = {}
    if getattr(args, "limit", None) is not None:
        query["limit"] = args.limit
    if getattr(args, "offset", None) is not None:
        query["offset"] = args.offset
    if getattr(args, "filter", None):
        query["filter"] = args.filter
    return query


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


def http_status(error: UniFiError) -> int | None:
    if not isinstance(error.details, dict):
        return None
    status = error.details.get("status")
    return status if isinstance(status, int) else None


def path_with_query(path: str, query: dict[str, Any]) -> str:
    encoded_query = urllib.parse.urlencode(
        [(key, str(value)) for key, value in query.items() if value is not None],
        doseq=True,
    )
    if not encoded_query:
        return path
    separator = "&" if urllib.parse.urlparse(path).query else "?"
    return f"{path}{separator}{encoded_query}"


def normalise_record_type(record_type: str) -> str:
    value = record_type.strip().upper()
    if value == "A":
        return "A_RECORD"
    if value in {"CNAME", "A_RECORD"}:
        return value
    raise UniFiError(
        "Unsupported DNS policy type.",
        code="invalid_argument",
        details={"supported": ["A", "A_RECORD", "CNAME"]},
    )


def official_resource(name: str) -> OfficialResource:
    try:
        return OFFICIAL_RESOURCES[name]
    except KeyError as error:
        raise UniFiError(
            f"Unknown official resource '{name}'.",
            code="invalid_argument",
            details={"valid": sorted(OFFICIAL_RESOURCES)},
        ) from error


def legacy_resource(name: str) -> LegacyResource:
    try:
        return LEGACY_RESOURCES[name]
    except KeyError as error:
        raise UniFiError(
            f"Unknown legacy fallback resource '{name}'.",
            code="invalid_argument",
            details={"valid": sorted(LEGACY_RESOURCES)},
        ) from error


class UniFiClient:
    """Thin UniFi API client, with the official Network API as the primary surface."""

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
        is_absolute_url = path.startswith("http://") or path.startswith("https://")
        ensure_live_config(self.config, require_base_url=not is_absolute_url)
        url = path if is_absolute_url else f"{self.config.base_url}{path}"

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

    def official(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return self.request(method, f"{OFFICIAL_API_BASE}{suffix}", **kwargs)

    def legacy(self, method: str, suffix: str, **kwargs: Any) -> Any:
        base = LEGACY_API_BASE_TEMPLATE.format(site=self.config.site)
        return self.request(method, f"{base}{suffix}", **kwargs)

    def legacy_v2(self, method: str, suffix: str, **kwargs: Any) -> Any:
        base = LEGACY_V2_BASE_TEMPLATE.format(site=self.config.site)
        return self.request(method, f"{base}{suffix}", **kwargs)

    # Backwards-compatible alias used by older tests and callers.
    def integration(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return self.official(method, suffix, **kwargs)

    def sites(self) -> list[dict[str, Any]]:
        payload = self.official("GET", "/sites")
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

    def official_collection_path(self, resource: OfficialResource) -> str:
        return f"/sites/{self.site_id()}/{resource.collection}"

    def official_item_path(self, resource: OfficialResource, item_id: str) -> str:
        return f"{self.official_collection_path(resource)}/{item_id}"

    def legacy_fallback_path(self, resource: LegacyResource) -> tuple[str, bool]:
        if resource.path.startswith("/rest/"):
            return resource.path, False
        return resource.path, True

    def list_official(
        self,
        resource: str | OfficialResource,
        *,
        query: dict[str, Any] | None = None,
    ) -> Any:
        spec = official_resource(resource) if isinstance(resource, str) else resource
        return self.official("GET", self.official_collection_path(spec), query=query)

    def get_official(self, resource: str | OfficialResource, item_id: str) -> Any:
        spec = official_resource(resource) if isinstance(resource, str) else resource
        return self.official("GET", self.official_item_path(spec, item_id))

    def find_official(
        self,
        resource: str | OfficialResource,
        selector: str,
        *,
        record_type: str | None = None,
    ) -> dict[str, Any]:
        spec = official_resource(resource) if isinstance(resource, str) else resource
        normalized = selector.strip().lower()

        if UUID_RE.fullmatch(selector):
            item = self.get_official(spec, selector)
            if isinstance(item, dict):
                return item
            raise UniFiError("Unexpected item payload shape.", code="response_shape")

        payload = self.list_official(spec, query={"limit": 500})
        records = extract_data(payload)
        if not isinstance(records, list):
            raise UniFiError(
                f"Unexpected payload shape for official resource '{spec.name}'.",
                code="response_shape",
            )

        exact: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            if record_type and str(record.get("type", "")).upper() != record_type.upper():
                continue
            values = [record.get(field) for field in spec.lookup_fields]
            string_values = [str(value).lower() for value in values if value not in (None, "")]
            if normalized in string_values:
                exact.append(record)
            elif any(normalized in value for value in string_values):
                partial.append(record)

        matches = exact or partial
        if not matches:
            raise UniFiError(f"No {spec.name} matched selector '{selector}'.", code="not_found")
        if len(matches) > 1:
            preview = [
                {field: item.get(field) for field in spec.lookup_fields} for item in matches[:10]
            ]
            raise UniFiError(
                f"Selector '{selector}' matched multiple {spec.name} entries.",
                code="ambiguous_selector",
                details={"matches": preview},
            )
        return matches[0]

    def list_legacy_fallback(self, resource_name: str) -> Any:
        spec = legacy_resource(resource_name)
        suffix, use_v2 = self.legacy_fallback_path(spec)
        if use_v2:
            return self.legacy_v2("GET", suffix)
        return self.legacy("GET", suffix)

    def find_legacy_fallback(self, resource_name: str, selector: str) -> dict[str, Any]:
        spec = legacy_resource(resource_name)
        payload = self.list_legacy_fallback(resource_name)
        records = extract_data(payload)
        if not isinstance(records, list):
            raise UniFiError(
                f"Unexpected payload shape for legacy fallback resource '{resource_name}'.",
                code="response_shape",
            )

        normalized = selector.strip().lower()
        exact: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            values = [record.get(field) for field in spec.lookup_fields]
            string_values = [str(value).lower() for value in values if value not in (None, "")]
            if normalized in string_values:
                exact.append(record)
            elif any(normalized in value for value in string_values):
                partial.append(record)

        matches = exact or partial
        if not matches:
            raise UniFiError(f"No {resource_name} matched selector '{selector}'.", code="not_found")
        if len(matches) > 1:
            preview = [
                {field: item.get(field) for field in spec.lookup_fields} for item in matches[:10]
            ]
            raise UniFiError(
                f"Selector '{selector}' matched multiple {resource_name} entries.",
                code="ambiguous_selector",
                details={"matches": preview},
            )
        return matches[0]

    def remembered_clients(self) -> list[dict[str, Any]]:
        payload = self.legacy("GET", "/rest/user")
        clients = extract_data(payload)
        if not isinstance(clients, list):
            raise UniFiError("Unexpected remembered-client payload shape.", code="response_shape")
        return clients

    def find_remembered_client(self, selector: str) -> dict[str, Any]:
        clients = self.remembered_clients()
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
            raise UniFiError(
                f"No remembered client matched selector '{selector}'.",
                code="not_found",
            )
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
                f"Selector '{selector}' matched multiple remembered clients.",
                code="ambiguous_selector",
                details={"matches": choices},
            )
        return matches[0]

    def build_remembered_client_update(
        self, client: dict[str, Any], updates: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        payload = {key: client[key] for key in LEGACY_CLIENT_EDITABLE_FIELDS if key in client}
        payload.update(updates)
        if payload.get("note"):
            payload["noted"] = True
        elif "note" in payload and not payload["note"]:
            payload["noted"] = bool(payload.get("noted", False))
        return f"/rest/user/{client['_id']}", payload

    def summary(self) -> dict[str, Any]:
        site_id = self.site_id()
        app_info = self.official("GET", "/info")
        sites = self.sites()
        official_payloads = {
            "acl_rules": self.official("GET", f"/sites/{site_id}/acl-rules", query={"limit": 500}),
            "clients": self.official("GET", f"/sites/{site_id}/clients", query={"limit": 500}),
            "devices": self.official("GET", f"/sites/{site_id}/devices", query={"limit": 500}),
            "device_tags": self.official(
                "GET", f"/sites/{site_id}/device-tags", query={"limit": 500}
            ),
            "pending_devices": self.official("GET", "/pending-devices", query={"limit": 500}),
            "dns_policies": self.official(
                "GET", f"/sites/{site_id}/dns/policies", query={"limit": 500}
            ),
            "dpi_categories": self.official("GET", "/dpi/categories", query={"limit": 500}),
            "dpi_applications": self.official("GET", "/dpi/applications", query={"limit": 500}),
            "countries": self.official("GET", "/countries", query={"limit": 500}),
            "firewall_policies": self.official(
                "GET", f"/sites/{site_id}/firewall/policies", query={"limit": 500}
            ),
            "firewall_zones": self.official(
                "GET", f"/sites/{site_id}/firewall/zones", query={"limit": 500}
            ),
            "networks": self.official("GET", f"/sites/{site_id}/networks", query={"limit": 500}),
            "radius_profiles": self.official(
                "GET", f"/sites/{site_id}/radius/profiles", query={"limit": 500}
            ),
            "traffic_matching_lists": self.official(
                "GET", f"/sites/{site_id}/traffic-matching-lists", query={"limit": 500}
            ),
            "vpn_servers": self.official(
                "GET", f"/sites/{site_id}/vpn/servers", query={"limit": 500}
            ),
            "site_to_site_vpns": self.official(
                "GET", f"/sites/{site_id}/vpn/site-to-site-tunnels", query={"limit": 500}
            ),
            "wans": self.official("GET", f"/sites/{site_id}/wans", query={"limit": 500}),
            "wifi_broadcasts": self.official(
                "GET", f"/sites/{site_id}/wifi/broadcasts", query={"limit": 500}
            ),
        }
        networks = extract_data(official_payloads["networks"])
        wifi_broadcasts = extract_data(official_payloads["wifi_broadcasts"])
        fallback_counts: dict[str, int] = {}
        for name in ["port-profile", "port-forward", "static-route", "traffic-route"]:
            try:
                fallback_counts[name.replace("-", "_")] = count_collection(
                    self.list_legacy_fallback(name)
                )
            except UniFiError as error:
                fallback_counts[name.replace("-", "_")] = -1
                fallback_counts[f"{name.replace('-', '_')}_error"] = error.code  # type: ignore[assignment]

        return {
            "api": {
                "application_version": app_info.get("applicationVersion")
                if isinstance(app_info, dict)
                else None,
                "primary_surface": "official_network_integration_v1",
            },
            "controller": self.config.base_url,
            "counts": {
                **{key: count_collection(value) for key, value in official_payloads.items()},
                "sites": len(sites),
            },
            "fallback_counts": fallback_counts,
            "networks": [
                {
                    "enabled": item.get("enabled"),
                    "hostIpAddress": item.get("ipv4Configuration", {}).get("hostIpAddress"),
                    "name": item.get("name"),
                    "vlanId": item.get("vlanId"),
                    "zoneId": item.get("zoneId"),
                }
                for item in networks
                if isinstance(item, dict)
            ],
            "site": self.config.site,
            "site_id": site_id,
            "wifi_broadcasts": [
                {
                    "enabled": item.get("enabled"),
                    "name": item.get("name"),
                    "network": item.get("network"),
                    "type": item.get("type"),
                }
                for item in wifi_broadcasts
                if isinstance(item, dict)
            ],
        }


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


def add_list_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--offset", type=int)
    parser.add_argument("--filter", help="official API filter string")


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


def require_capability(spec: OfficialResource, capability: str) -> None:
    attr = f"supports_{capability}"
    if not bool(getattr(spec, attr)):
        raise UniFiError(
            f"The official {spec.name} resource does not support {capability}.",
            code="unsupported_operation",
        )


def official_dry_run_path(client: UniFiClient, suffix: str) -> str:
    return f"{OFFICIAL_API_BASE}{suffix}"


def connector_dry_run_path(base_url: str, console_id: str, connector_path: str) -> str:
    clean_base = base_url.rstrip("/")
    clean_path = connector_path.lstrip("/")
    return f"{clean_base}/v1/connector/consoles/{console_id}/{clean_path}"


def legacy_dry_run_path(client: UniFiClient, suffix: str, *, v2: bool = False) -> str:
    if v2:
        return f"{LEGACY_V2_BASE_TEMPLATE.format(site=client.config.site)}{suffix}"
    return f"{LEGACY_API_BASE_TEMPLATE.format(site=client.config.site)}{suffix}"


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
            app_info = client.official("GET", "/info")
            sites = client.sites()
            live["application_version"] = (
                app_info.get("applicationVersion") if isinstance(app_info, dict) else None
            )
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
        version = live.get("application_version") or "unknown"
        lines.append(
            f"Live check: ok ({live['site_count']} site{'s' if live['site_count'] != 1 else ''})"
        )
        lines.append(f"Network application version: {version}")
        if live.get("resolved_site_id"):
            lines.append(f"Resolved site ID: {live['resolved_site_id']}")
        elif live.get("resolved_site_id_error"):
            lines.append(f"Resolved site ID: failed ({live['resolved_site_id_error']['message']})")
    elif live["attempted"]:
        lines.append(f"Live check: failed ({live['error']['message']})")
    else:
        lines.append("Live check: skipped")
    return "\n".join(lines)


def command_app_info(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.official("GET", "/info")


def command_summary(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.summary()


def command_sites(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", "/sites", query=with_limit(args))


def command_official_list(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    return client.list_official(resource_name, query=with_limit(args))


def command_official_show(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    return client.find_official(resource_name, args.selector)


def command_official_create(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "create")
    payload = parse_data_json(args.data_json)
    suffix = client.official_collection_path(spec)
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_official_merge(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "update")
    current = client.find_official(spec, args.selector)
    merged = copy.deepcopy(current)
    if args.data_json:
        data = parse_data_json(args.data_json)
        if not isinstance(data, dict):
            raise UniFiError("--data-json must be a JSON object.", code="invalid_argument")
        merged.update(data)
    for assignment in args.set or []:
        if "=" not in assignment:
            raise UniFiError(
                f"Invalid --set value '{assignment}'. Use dotted.key=value.",
                code="invalid_argument",
            )
        key, raw_value = assignment.split("=", 1)
        set_nested(merged, key, parse_json_value(raw_value))
    item_id = str(current["id"])
    suffix = client.official_item_path(spec, item_id)
    require_confirmation(args, "PUT", official_dry_run_path(client, suffix), merged)
    return client.official("PUT", suffix, payload=merged)


def command_official_patch(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "patch")
    current = client.find_official(spec, args.selector)
    payload = parse_data_json(args.data_json)
    suffix = client.official_item_path(spec, str(current["id"]))
    require_confirmation(args, "PATCH", official_dry_run_path(client, suffix), payload)
    return client.official("PATCH", suffix, payload=payload)


def command_official_delete(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "delete")
    current = client.find_official(spec, args.selector)
    suffix = client.official_item_path(spec, str(current["id"]))
    query = {"force": "true"} if getattr(args, "force", False) else {}
    dry_run_path = path_with_query(official_dry_run_path(client, suffix), query)
    require_confirmation(args, "DELETE", dry_run_path, current)
    return client.official("DELETE", suffix, query=query)


def firewall_policy_ordering_query(
    client: UniFiClient,
    args: argparse.Namespace,
) -> dict[str, str]:
    source_zone = client.find_official("firewall-zone", args.source_zone)
    destination_zone = client.find_official("firewall-zone", args.destination_zone)
    return {
        "sourceFirewallZoneId": str(source_zone["id"]),
        "destinationFirewallZoneId": str(destination_zone["id"]),
    }


def command_official_ordering(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "ordering")
    suffix = f"{client.official_collection_path(spec)}/ordering"
    query = firewall_policy_ordering_query(client, args) if spec.name == "firewall-policy" else {}
    return client.official("GET", suffix, query=query)


def command_official_reorder(
    client: UniFiClient,
    args: argparse.Namespace,
    resource_name: str,
) -> Any:
    spec = official_resource(resource_name)
    require_capability(spec, "ordering")
    payload = parse_data_json(args.data_json)
    suffix = f"{client.official_collection_path(spec)}/ordering"
    query = firewall_policy_ordering_query(client, args) if spec.name == "firewall-policy" else {}
    dry_run_path = path_with_query(official_dry_run_path(client, suffix), query)
    require_confirmation(args, "PUT", dry_run_path, payload)
    return client.official("PUT", suffix, query=query, payload=payload)


def command_devices(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "device")


def command_device_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_show(client, args, "device")


def command_pending_devices(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", "/pending-devices", query=with_limit(args))


def command_device_adopt(client: UniFiClient, args: argparse.Namespace) -> Any:
    if args.data_json:
        payload = parse_data_json(args.data_json)
    else:
        if not args.mac_address:
            raise UniFiError(
                "device-adopt requires --mac-address or --data-json.",
                code="invalid_argument",
            )
        payload = {
            "ignoreDeviceLimit": bool(args.ignore_device_limit),
            "macAddress": args.mac_address,
        }
    suffix = f"/sites/{client.site_id()}/devices"
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_device_remove(client: UniFiClient, args: argparse.Namespace) -> Any:
    device = client.find_official("device", args.selector)
    suffix = f"/sites/{client.site_id()}/devices/{device['id']}"
    require_confirmation(args, "DELETE", official_dry_run_path(client, suffix), device)
    return client.official("DELETE", suffix)


def command_device_statistics(client: UniFiClient, args: argparse.Namespace) -> Any:
    device = client.find_official("device", args.selector)
    suffix = f"/sites/{client.site_id()}/devices/{device['id']}/statistics/latest"
    return client.official("GET", suffix)


def command_device_action(client: UniFiClient, args: argparse.Namespace) -> Any:
    device = client.find_official("device", args.selector)
    payload = parse_data_json(args.data_json) if args.data_json else {"action": args.action}
    suffix = f"/sites/{client.site_id()}/devices/{device['id']}/actions"
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_port_action(client: UniFiClient, args: argparse.Namespace) -> Any:
    device = client.find_official("device", args.selector)
    payload = parse_data_json(args.data_json) if args.data_json else {"action": args.action}
    suffix = (
        f"/sites/{client.site_id()}/devices/{device['id']}/interfaces/ports/{args.port}/actions"
    )
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_clients(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", f"/sites/{client.site_id()}/clients", query=with_limit(args))


def command_client_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_official("client", args.selector)
    suffix = f"/sites/{client.site_id()}/clients/{client_obj['id']}"
    return client.official("GET", suffix)


def command_client_action(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_official("client", args.selector)
    payload = parse_data_json(args.data_json) if args.data_json else {"action": args.action}
    suffix = f"/sites/{client.site_id()}/clients/{client_obj['id']}/actions"
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_remembered_clients(client: UniFiClient, _args: argparse.Namespace) -> Any:
    return client.remembered_clients()


def command_remembered_client_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.find_remembered_client(args.selector)


def command_reservation_set(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_remembered_client(args.selector)
    path, payload = client.build_remembered_client_update(
        client_obj,
        {
            "use_fixedip": True,
            "fixed_ip": args.ip,
            **({"network_id": args.network_id} if args.network_id else {}),
        },
    )
    require_confirmation(args, "PUT", legacy_dry_run_path(client, path), payload)
    return client.legacy("PUT", path, payload=payload)


def command_reservation_clear(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_remembered_client(args.selector)
    path, payload = client.build_remembered_client_update(
        client_obj, {"fixed_ip": "", "use_fixedip": False}
    )
    require_confirmation(args, "PUT", legacy_dry_run_path(client, path), payload)
    return client.legacy("PUT", path, payload=payload)


def command_local_dns_set(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_remembered_client(args.selector)
    path, payload = client.build_remembered_client_update(
        client_obj,
        {"local_dns_record": args.record, "local_dns_record_enabled": True},
    )
    require_confirmation(args, "PUT", legacy_dry_run_path(client, path), payload)
    return client.legacy("PUT", path, payload=payload)


def command_local_dns_clear(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_remembered_client(args.selector)
    path, payload = client.build_remembered_client_update(
        client_obj,
        {"local_dns_record": "", "local_dns_record_enabled": False},
    )
    require_confirmation(args, "PUT", legacy_dry_run_path(client, path), payload)
    return client.legacy("PUT", path, payload=payload)


def command_client_forget(client: UniFiClient, args: argparse.Namespace) -> Any:
    client_obj = client.find_remembered_client(args.selector)
    payload = {"cmd": "forget-sta", "macs": [client_obj["mac"]]}
    path = "/cmd/stamgr"
    require_confirmation(args, "POST", legacy_dry_run_path(client, path), payload)
    return client.legacy("POST", path, payload=payload)


def command_networks(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "network")


def command_network_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_show(client, args, "network")


def legacy_network_matches(network: dict[str, Any], legacy_network: dict[str, Any]) -> bool:
    if str(legacy_network.get("name", "")).lower() == str(network.get("name", "")).lower():
        return True
    vlan = network.get("vlanId")
    legacy_vlan = legacy_network.get("vlan")
    return vlan is not None and legacy_vlan is not None and str(vlan) == str(legacy_vlan)


def port_profile_references_network(
    port_profile: dict[str, Any],
    legacy_network_id: str,
) -> bool:
    candidate_values: list[Any] = [
        port_profile.get("native_networkconf_id"),
        port_profile.get("voice_networkconf_id"),
    ]
    for key in ["tagged_networkconf_ids", "networkconf_ids"]:
        values = port_profile.get(key)
        if isinstance(values, list):
            candidate_values.extend(values)
    return legacy_network_id in {str(value) for value in candidate_values if value}


def network_reference_resource(
    resource_type: str,
    references: list[dict[str, Any]],
    *,
    source: str,
) -> dict[str, Any]:
    return {
        "referenceCount": len(references),
        "referenceSource": source,
        "references": references,
        "resourceType": resource_type,
    }


def build_network_references_fallback(
    client: UniFiClient,
    network: dict[str, Any],
    official_error: UniFiError,
) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    fallback_errors: list[dict[str, Any]] = []
    network_id = str(network["id"])

    try:
        wifi_payload = client.official(
            "GET", f"/sites/{client.site_id()}/wifi/broadcasts", query={"limit": 500}
        )
        wifi_references = [
            {
                "enabled": wifi.get("enabled"),
                "name": wifi.get("name"),
                "referenceId": wifi.get("id"),
            }
            for wifi in data_list(wifi_payload)
            if isinstance(wifi, dict)
            and isinstance(wifi.get("network"), dict)
            and wifi["network"].get("networkId") == network_id
        ]
        if wifi_references:
            resources.append(
                network_reference_resource(
                    "WIFI", wifi_references, source="official_wifi_broadcasts"
                )
            )
    except UniFiError as error:
        fallback_errors.append({"code": error.code, "message": str(error), "source": "wifi"})

    legacy_network_id: str | None = None
    port_profile_ids: set[str] = set()
    try:
        legacy_networks = data_list(client.legacy("GET", "/rest/networkconf"))
        for item in legacy_networks:
            if isinstance(item, dict) and legacy_network_matches(network, item):
                legacy_network_id = str(item["_id"])
                break

        if legacy_network_id:
            port_profiles = data_list(client.list_legacy_fallback("port-profile"))
            port_profile_references = []
            for profile in port_profiles:
                if not isinstance(profile, dict):
                    continue
                if port_profile_references_network(profile, legacy_network_id):
                    profile_id = str(profile.get("_id") or "")
                    if profile_id:
                        port_profile_ids.add(profile_id)
                    port_profile_references.append(
                        {
                            "name": profile.get("name"),
                            "nativeNetworkconfId": profile.get("native_networkconf_id"),
                            "referenceId": profile_id,
                            "voiceNetworkconfId": profile.get("voice_networkconf_id"),
                        }
                    )
            if port_profile_references:
                resources.append(
                    network_reference_resource(
                        "LEGACY_PORT_PROFILE",
                        port_profile_references,
                        source="legacy_port_profiles",
                    )
                )

            devices = data_list(client.legacy("GET", "/stat/device"))
            port_references: list[dict[str, Any]] = []
            for device in devices:
                if not isinstance(device, dict):
                    continue
                for port in device.get("port_table") or []:
                    if not isinstance(port, dict):
                        continue
                    portconf_id = str(port.get("portconf_id") or "")
                    native_network_id = str(port.get("native_networkconf_id") or "")
                    if (
                        portconf_id not in port_profile_ids
                        and native_network_id != legacy_network_id
                    ):
                        continue
                    device_id = device.get("_id") or device.get("mac")
                    port_references.append(
                        {
                            "deviceName": device.get("name"),
                            "nativeNetworkconfId": native_network_id or None,
                            "portIdx": port.get("port_idx"),
                            "portName": port.get("name"),
                            "portProfileId": portconf_id or None,
                            "referenceId": f"{device_id}:{port.get('port_idx')}",
                        }
                    )
            if port_references:
                resources.append(
                    network_reference_resource(
                        "LEGACY_SWITCH_PORT",
                        port_references,
                        source="legacy_device_port_table",
                    )
                )

            remembered_references = []
            for remembered in client.remembered_clients():
                if not isinstance(remembered, dict):
                    continue
                last_network_id = str(remembered.get("last_connection_network_id") or "")
                override_id = str(remembered.get("virtual_network_override_id") or "")
                has_static_client_config = any(
                    [
                        remembered.get("use_fixedip"),
                        remembered.get("local_dns_record_enabled"),
                        remembered.get("virtual_network_override_enabled"),
                    ]
                )
                if not has_static_client_config:
                    continue
                if legacy_network_id not in {last_network_id, override_id}:
                    continue
                remembered_references.append(
                    {
                        "fixedIp": remembered.get("fixed_ip"),
                        "localDnsRecord": remembered.get("local_dns_record"),
                        "macAddress": remembered.get("mac"),
                        "name": remembered.get("name") or remembered.get("hostname"),
                        "referenceId": remembered.get("_id") or remembered.get("mac"),
                    }
                )
            if remembered_references:
                resources.append(
                    network_reference_resource(
                        "CLIENT",
                        remembered_references,
                        source="legacy_remembered_clients",
                    )
                )
    except UniFiError as error:
        fallback_errors.append({"code": error.code, "message": str(error), "source": "legacy"})

    return {
        "fallback": {
            "reason": "official_network_references_failed",
            "source": "best_effort_local_read_model",
        },
        "fallbackErrors": fallback_errors,
        "network": {
            "id": network.get("id"),
            "legacyNetworkconfId": legacy_network_id,
            "name": network.get("name"),
            "vlanId": network.get("vlanId"),
        },
        "officialError": {
            "code": official_error.code,
            "details": scrub_sensitive(official_error.details or {}),
            "message": str(official_error),
        },
        "referenceResources": resources,
    }


def command_network_references(client: UniFiClient, args: argparse.Namespace) -> Any:
    network = client.find_official("network", args.selector)
    suffix = f"/sites/{client.site_id()}/networks/{network['id']}/references"
    try:
        return client.official("GET", suffix)
    except UniFiError as error:
        if error.code == "http_error" and (http_status(error) or 0) >= 500:
            return build_network_references_fallback(client, network, error)
        raise


def command_wifi_broadcasts(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "wifi-broadcast")


def command_wifi_broadcast_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_show(client, args, "wifi-broadcast")


def command_dns_policies(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "dns-policy")


def command_dns_policy_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    record_type = normalise_record_type(args.record_type) if args.record_type else None
    return client.find_official("dns-policy", args.selector, record_type=record_type)


def build_dns_policy_payload(args: argparse.Namespace) -> dict[str, Any]:
    record_type = normalise_record_type(args.record_type)
    domain = args.domain or args.key
    if not domain:
        raise UniFiError("DNS policy requires --domain.", code="invalid_argument")

    payload: dict[str, Any] = {
        "domain": domain,
        "enabled": not args.disabled,
        "ttlSeconds": args.ttl,
        "type": record_type,
    }
    if record_type == "A_RECORD":
        payload["ipv4Address"] = args.value
    elif record_type == "CNAME":
        payload["cname"] = args.value
    return payload


def command_dns_upsert(client: UniFiClient, args: argparse.Namespace) -> Any:
    payload = build_dns_policy_payload(args)
    record_type = str(payload["type"])
    domain = str(payload["domain"])
    try:
        current = client.find_official("dns-policy", domain, record_type=record_type)
    except UniFiError as error:
        if error.code != "not_found":
            raise
        current = None

    spec = official_resource("dns-policy")
    if current is None:
        suffix = client.official_collection_path(spec)
        require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
        return client.official("POST", suffix, payload=payload)

    merged = dict(current)
    merged.update(payload)
    suffix = client.official_item_path(spec, str(current["id"]))
    require_confirmation(args, "PUT", official_dry_run_path(client, suffix), merged)
    return client.official("PUT", suffix, payload=merged)


def command_dns_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    record_type = normalise_record_type(args.record_type) if args.record_type else None
    record = client.find_official("dns-policy", args.selector, record_type=record_type)
    spec = official_resource("dns-policy")
    suffix = client.official_item_path(spec, str(record["id"]))
    require_confirmation(args, "DELETE", official_dry_run_path(client, suffix), record)
    return client.official("DELETE", suffix)


def command_firewall_zones(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "firewall-zone")


def command_firewall_policies(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "firewall-policy")


def command_acl_rules(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "acl-rule")


def command_traffic_matching_lists(client: UniFiClient, args: argparse.Namespace) -> Any:
    return command_official_list(client, args, "traffic-matching-list")


def command_wans(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", f"/sites/{client.site_id()}/wans", query=with_limit(args))


def command_radius_profiles(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official(
        "GET", f"/sites/{client.site_id()}/radius/profiles", query=with_limit(args)
    )


def command_device_tags(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", f"/sites/{client.site_id()}/device-tags", query=with_limit(args))


def command_vpn_servers(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", f"/sites/{client.site_id()}/vpn/servers", query=with_limit(args))


def command_site_to_site_vpns(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official(
        "GET", f"/sites/{client.site_id()}/vpn/site-to-site-tunnels", query=with_limit(args)
    )


def command_vouchers(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official(
        "GET", f"/sites/{client.site_id()}/hotspot/vouchers", query=with_limit(args)
    )


def command_voucher_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    suffix = f"/sites/{client.site_id()}/hotspot/vouchers/{args.selector}"
    return client.official("GET", suffix)


def command_vouchers_generate(client: UniFiClient, args: argparse.Namespace) -> Any:
    payload = parse_data_json(args.data_json)
    suffix = f"/sites/{client.site_id()}/hotspot/vouchers"
    require_confirmation(args, "POST", official_dry_run_path(client, suffix), payload)
    return client.official("POST", suffix, payload=payload)


def command_voucher_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    suffix = f"/sites/{client.site_id()}/hotspot/vouchers/{args.selector}"
    require_confirmation(args, "DELETE", official_dry_run_path(client, suffix), {})
    return client.official("DELETE", suffix)


def command_vouchers_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    query = {"filter": args.filter}
    suffix = f"/sites/{client.site_id()}/hotspot/vouchers"
    dry_run_path = path_with_query(official_dry_run_path(client, suffix), query)
    require_confirmation(args, "DELETE", dry_run_path, None)
    return client.official("DELETE", suffix, query=query)


def command_dpi_categories(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", "/dpi/categories", query=with_limit(args))


def command_dpi_applications(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", "/dpi/applications", query=with_limit(args))


def command_countries(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.official("GET", "/countries", query=with_limit(args))


def command_connector_request(
    client: UniFiClient,
    args: argparse.Namespace,
    method: str,
) -> Any:
    payload = parse_data_json(args.data_json) if args.data_json else None
    query = parse_query_pairs(args.query)
    url = connector_dry_run_path(args.cloud_base_url, args.console_id, args.path)
    if method.upper() != "GET":
        require_confirmation(args, method, path_with_query(url, query), payload)
    return client.request(method, url, query=query, payload=payload)


def command_legacy_fallback_types(_client: UniFiClient, _args: argparse.Namespace) -> Any:
    return {
        name: {
            "description": spec.description,
            "lookup": list(spec.lookup_fields),
            "path": spec.path,
        }
        for name, spec in sorted(LEGACY_RESOURCES.items())
    }


def command_legacy_fallback_list(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.list_legacy_fallback(args.resource)


def command_legacy_fallback_show(client: UniFiClient, args: argparse.Namespace) -> Any:
    return client.find_legacy_fallback(args.resource, args.selector)


def command_legacy_fallback_merge(client: UniFiClient, args: argparse.Namespace) -> Any:
    spec = legacy_resource(args.resource)
    current = client.find_legacy_fallback(args.resource, args.selector)
    merged = copy.deepcopy(current)
    if args.data_json:
        data = parse_data_json(args.data_json)
        if not isinstance(data, dict):
            raise UniFiError("--data-json must be a JSON object.", code="invalid_argument")
        merged.update(data)
    for assignment in args.set or []:
        if "=" not in assignment:
            raise UniFiError(
                f"Invalid --set value '{assignment}'. Use dotted.key=value.",
                code="invalid_argument",
            )
        key, raw_value = assignment.split("=", 1)
        set_nested(merged, key, parse_json_value(raw_value))

    item_id = str(current.get("_id") or current.get("id"))
    if not item_id:
        raise UniFiError("Legacy fallback object has no usable id.", code="response_shape")
    suffix, use_v2 = client.legacy_fallback_path(spec)
    path = f"{suffix}/{item_id}"
    require_confirmation(args, "PUT", legacy_dry_run_path(client, path, v2=use_v2), merged)
    if use_v2:
        return client.legacy_v2("PUT", path, payload=merged)
    return client.legacy("PUT", path, payload=merged)


def command_legacy_fallback_delete(client: UniFiClient, args: argparse.Namespace) -> Any:
    spec = legacy_resource(args.resource)
    current = client.find_legacy_fallback(args.resource, args.selector)
    item_id = str(current.get("_id") or current.get("id"))
    if not item_id:
        raise UniFiError("Legacy fallback object has no usable id.", code="response_shape")
    suffix, use_v2 = client.legacy_fallback_path(spec)
    path = f"{suffix}/{item_id}"
    require_confirmation(args, "DELETE", legacy_dry_run_path(client, path, v2=use_v2), current)
    if use_v2:
        return client.legacy_v2("DELETE", path)
    return client.legacy("DELETE", path)


def network_role(network: dict[str, Any]) -> str:
    name = str(network.get("name", "")).lower()
    vlan = network.get("vlanId")
    if "management" in name or vlan == 10:
        return "management"
    if "storage" in name or vlan == 20:
        return "storage"
    if "lab" in name or vlan == 30:
        return "lab"
    if "home" in name or vlan == 40:
        return "home"
    if "iot" in name or vlan == 50:
        return "iot"
    if "dmz" in name or vlan == 60:
        return "dmz"
    if "work" in name or vlan == 255:
        return "work"
    if name == "default" or vlan == 1:
        return "default"
    return "other"


def policy_is_user_defined(policy: dict[str, Any]) -> bool:
    metadata = policy.get("metadata")
    if isinstance(metadata, dict):
        return metadata.get("origin") == "USER_DEFINED"
    return bool(policy.get("predefined") is False)


def severity_score(severity: str) -> int:
    return {"critical": 5, "warning": 2, "informational": 1}.get(severity, 0)


def score_label(score: int) -> str:
    if score >= 80:
        return "healthy"
    if score >= 60:
        return "needs_attention"
    return "critical"


def build_firewall_audit_report(client: UniFiClient) -> dict[str, Any]:
    site_id = client.site_id()
    networks_payload = client.official("GET", f"/sites/{site_id}/networks", query={"limit": 500})
    policies_payload = client.official(
        "GET", f"/sites/{site_id}/firewall/policies", query={"limit": 500}
    )
    zones_payload = client.official("GET", f"/sites/{site_id}/firewall/zones", query={"limit": 500})
    devices_payload = client.official("GET", f"/sites/{site_id}/devices", query={"limit": 500})
    acl_payload = client.official("GET", f"/sites/{site_id}/acl-rules", query={"limit": 500})

    networks = extract_data(networks_payload)
    policies = extract_data(policies_payload)
    zones = extract_data(zones_payload)
    devices = extract_data(devices_payload)
    acl_rules = extract_data(acl_payload)
    if not isinstance(networks, list) or not isinstance(policies, list):
        raise UniFiError("Unexpected official firewall audit payload shape.", code="response_shape")
    if not isinstance(zones, list):
        zones = []
    if not isinstance(devices, list):
        devices = []
    if not isinstance(acl_rules, list):
        acl_rules = []

    user_policies = [
        policy for policy in policies if isinstance(policy, dict) and policy_is_user_defined(policy)
    ]
    enabled_user_policies = [policy for policy in user_policies if policy.get("enabled", True)]
    online_devices = [
        device for device in devices if str(device.get("state", "")).upper() == "ONLINE"
    ]
    offline_devices = [
        device for device in devices if str(device.get("state", "")).upper() != "ONLINE"
    ]

    zone_networks: dict[str, list[dict[str, Any]]] = {}
    for network in networks:
        if not isinstance(network, dict):
            continue
        zone_id = str(network.get("zoneId") or "")
        if zone_id:
            zone_networks.setdefault(zone_id, []).append(network)

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

    sensitive_roles = {"dmz", "iot", "management", "storage", "work"}
    for zone_id, members in zone_networks.items():
        roles = {network_role(member) for member in members}
        if len(members) <= 1:
            continue
        if roles & sensitive_roles and not enabled_user_policies:
            add_finding(
                "SEG-01",
                "segmentation",
                "critical",
                "Sensitive networks share a firewall zone and no enabled user-defined "
                "firewall policies were found.",
                evidence={
                    "roles": sorted(roles),
                    "zone_id": zone_id,
                    "networks": [member.get("name") for member in members],
                },
                recommendation=(
                    "Use explicit user-defined firewall policies or separate firewall zones "
                    "before trusting this as a segmented network."
                ),
            )

    if len(networks) > 1 and not enabled_user_policies:
        add_finding(
            "SEG-02",
            "segmentation",
            "warning",
            "Multiple networks exist but no enabled user-defined firewall policies were found.",
            evidence={"network_count": len(networks), "user_policy_count": 0},
            recommendation="Add named policies for the intended inter-network trust model.",
        )

    dns_specific_policies = [
        policy for policy in enabled_user_policies if "53" in json.dumps(policy, sort_keys=True)
    ]
    if not dns_specific_policies:
        add_finding(
            "EGR-01",
            "egress_control",
            "warning",
            "No explicit DNS-control firewall policy was detected.",
            evidence={"custom_dns_policy_count": 0},
            recommendation=(
                "If DNS pinning matters, add explicit policy for approved resolvers rather "
                "than relying only on DHCP convention."
            ),
        )

    placeholder_named_policies = [
        policy.get("name")
        for policy in user_policies
        if re.fullmatch(
            r"(rule|new rule|untitled)( \d+)?", str(policy.get("name", "")).strip().lower()
        )
        or re.fullmatch(r"\d+", str(policy.get("name", "")).strip())
    ]
    if placeholder_named_policies:
        add_finding(
            "HYG-01",
            "rule_hygiene",
            "warning",
            "Some user-defined firewall policies have placeholder-style names.",
            evidence={"placeholder_names": placeholder_named_policies},
            recommendation="Rename policies so future audits and changes are easier to review.",
        )

    if offline_devices:
        add_finding(
            "TOP-01",
            "topology",
            "critical",
            "One or more UniFi devices are offline during the audit.",
            evidence={"offline_devices": [device.get("name") for device in offline_devices]},
            recommendation="Bring offline network devices back before trusting topology checks.",
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
    recommendations = [
        finding["recommendation"] for finding in findings if finding.get("recommendation")
    ]

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
            "networks": len(networks),
            "user_defined_firewall_policies": len(user_policies),
            "zone_map": [
                {
                    "networks": [member.get("name") for member in members],
                    "roles": sorted({network_role(member) for member in members}),
                    "zone_id": zone_id,
                }
                for zone_id, members in zone_networks.items()
            ],
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }


def format_firewall_audit_human(report: dict[str, Any]) -> str:
    lines = [
        f"Firewall audit score: {report['overall_score']}/100 ({report['overall_status']})",
        f"API surface: {report['api_surface']}",
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
            f"- Networks: {summary['networks']}",
            f"- Firewall zones: {summary['firewall_zones']}",
            "- Firewall policies: "
            f"{summary['firewall_policies']} "
            f"({summary['user_defined_firewall_policies']} user-defined)",
            f"- ACL rules: {summary['acl_rules']}",
            f"- Devices online/offline: {summary['devices_online']}/{summary['devices_offline']}",
        ]
    )
    zone_lines = ", ".join(
        f"{', '.join(zone['networks'])} ({', '.join(zone['roles'])})"
        for zone in summary["zone_map"]
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


def command_request(client: UniFiClient, args: argparse.Namespace) -> Any:
    query = parse_query_pairs(args.query)
    payload = parse_data_json(args.data_json) if args.data_json else None
    if args.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        require_confirmation(args, args.method, args.path, payload)
    return client.request(args.method, args.path, query=query, payload=payload)
