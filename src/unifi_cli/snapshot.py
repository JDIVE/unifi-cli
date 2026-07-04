"""Snapshot, diff, and backup commands.

``snapshot`` writes one JSON file per collection into a directory; ``diff``
re-reads the same collections live and reports added/removed/changed items so a
configuration drift can be reviewed like ``git status``. Backup verbs wrap the
legacy ``/cmd/backup`` endpoint and the autobackup download path.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from unifi_cli import __version__
from unifi_cli.core import (
    UniFiClient,
    UniFiError,
    data_list,
    legacy_dry_run_path,
    require_confirmation,
    wants_human_format,
)

# Volatile top-level fields stripped from client/device snapshots so diffs stay
# stable across runs. Config collections are never stripped.
VOLATILE_FIELDS: frozenset[str] = frozenset(
    {
        "uptimeSec",
        "lastSeen",
        "connectedAt",
        "statistics",
        "latency",
        "uplink",
        "experience",
        "cpuUtilizationPct",
        "memoryUtilizationPct",
        "txRateBps",
        "rxRateBps",
    }
)

# Collections whose items get volatile fields stripped.
VOLATILE_COLLECTIONS: frozenset[str] = frozenset({"clients", "devices"})

# Official per-site collections read via paginate_path against a raw suffix.
OFFICIAL_COLLECTIONS: dict[str, str] = {
    "networks": "networks",
    "wifi-broadcasts": "wifi/broadcasts",
    "dns-policies": "dns/policies",
    "firewall-zones": "firewall/zones",
    "firewall-policies": "firewall/policies",
    "acl-rules": "acl-rules",
    "traffic-matching-lists": "traffic-matching-lists",
    "devices": "devices",
    "clients": "clients",
    "switch-lags": "switching/lags",
    "mc-lag-domains": "switching/mc-lag-domains",
    "switch-stacks": "switching/switch-stacks",
    "wans": "wans",
    "radius-profiles": "radius/profiles",
    "device-tags": "device-tags",
    "vpn-servers": "vpn/servers",
    "site-to-site-vpns": "vpn/site-to-site-tunnels",
}

# Legacy fallback collections, keyed by the legacy resource name; the on-disk
# filename is prefixed with "legacy-".
LEGACY_COLLECTIONS: tuple[str, ...] = (
    "port-profile",
    "port-forward",
    "static-route",
    "dynamic-dns",
    "user-group",
    "content-filtering",
    "traffic-route",
)

_SORT_KEYS = ("name", "domain", "_id", "id")


def _sort_key(item: dict[str, Any]) -> str:
    for key in _SORT_KEYS:
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _item_id(item: dict[str, Any]) -> str:
    for key in ("id", "_id", "name", "domain"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _item_label(item: dict[str, Any]) -> str:
    for key in ("name", "domain"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return _item_id(item)


def strip_volatile(collection: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop top-level volatile fields from client/device items only."""
    if collection not in VOLATILE_COLLECTIONS:
        return items
    cleaned: list[dict[str, Any]] = []
    for item in items:
        cleaned.append({key: value for key, value in item.items() if key not in VOLATILE_FIELDS})
    return cleaned


def normalise_collection(collection: str, raw_items: list[Any]) -> list[dict[str, Any]]:
    """Strip volatile fields (when applicable) and sort for stable ordering."""
    items = [item for item in raw_items if isinstance(item, dict)]
    items = strip_volatile(collection, items)
    return sorted(items, key=_sort_key)


def _filename(collection: str, *, legacy: bool) -> str:
    return f"legacy-{collection}.json" if legacy else f"{collection}.json"


def read_official_collection(client: UniFiClient, suffix: str) -> list[dict[str, Any]]:
    site_id = client.site_id()
    return client.paginate_path(f"/sites/{site_id}/{suffix}")


def read_legacy_collection(client: UniFiClient, name: str) -> list[dict[str, Any]]:
    items = data_list(client.list_legacy_fallback(name))
    return [item for item in items if isinstance(item, dict)]


def collect_all(
    client: UniFiClient,
    *,
    official: dict[str, str] | None = None,
    legacy: tuple[str, ...] | None = None,
) -> tuple[dict[str, tuple[list[dict[str, Any]], bool]], dict[str, dict[str, Any]]]:
    """Read every requested collection live.

    Returns a mapping of ``collection -> (items, is_legacy)`` for the collections
    that succeeded, and an ``errors`` mapping for the ones that failed.
    """
    official = OFFICIAL_COLLECTIONS if official is None else official
    legacy = LEGACY_COLLECTIONS if legacy is None else legacy
    results: dict[str, tuple[list[dict[str, Any]], bool]] = {}
    errors: dict[str, dict[str, Any]] = {}

    for collection, suffix in official.items():
        try:
            items = read_official_collection(client, suffix)
            results[collection] = (normalise_collection(collection, items), False)
        except UniFiError as error:
            errors[collection] = {"code": error.code, "message": str(error)}

    for name in legacy:
        try:
            items = read_legacy_collection(client, name)
            results[name] = (normalise_collection(name, items), True)
        except UniFiError as error:
            errors[name] = {"code": error.code, "message": str(error)}

    return results, errors


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _controller_host(base_url: str | None) -> str | None:
    if not base_url:
        return None
    return urlparse(base_url).hostname


def command_snapshot(client: UniFiClient, args: argparse.Namespace) -> Any:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dir_arg = getattr(args, "dir", None)
    directory = Path(dir_arg) if dir_arg else Path(f"unifi-snapshot-{timestamp}")
    directory.mkdir(parents=True, exist_ok=True)

    results, errors = collect_all(client)

    counts: dict[str, int] = {}
    for collection, (items, legacy) in results.items():
        _write_json(directory / _filename(collection, legacy=legacy), items)
        counts[collection] = len(items)

    try:
        app_info = client.official("GET", "/info")
        application_version = (
            app_info.get("applicationVersion") if isinstance(app_info, dict) else None
        )
    except UniFiError as error:
        application_version = None
        errors["_info"] = {"code": error.code, "message": str(error)}

    meta = {
        "application_version": application_version,
        "cli_version": __version__,
        "collections": sorted(counts),
        "controller_host": _controller_host(client.config.base_url),
        "counts": counts,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    _write_json(directory / "_meta.json", meta)
    if errors:
        _write_json(directory / "_errors.json", errors)

    return {
        "ok": True,
        "dir": str(directory),
        "collections": sorted(counts),
        "counts": counts,
        "errors": errors,
    }


def _snapshot_collections(directory: Path) -> dict[str, bool]:
    """Map each snapshot file back to ``collection_name -> is_legacy``."""
    mapping: dict[str, bool] = {}
    for path in directory.glob("*.json"):
        stem = path.stem
        if stem.startswith("_"):
            continue
        if stem.startswith("legacy-"):
            mapping[stem[len("legacy-") :]] = True
        else:
            mapping[stem] = False
    return mapping


def _load_snapshot(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text())
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def diff_collection(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    before_by_id = {_item_id(item): item for item in before}
    after_by_id = {_item_id(item): item for item in after}

    added = [
        _item_label(after_by_id[item_id]) for item_id in after_by_id if item_id not in before_by_id
    ]
    removed = [
        _item_label(before_by_id[item_id]) for item_id in before_by_id if item_id not in after_by_id
    ]
    changed: list[dict[str, Any]] = []
    for item_id, old_item in before_by_id.items():
        new_item = after_by_id.get(item_id)
        if new_item is None or new_item == old_item:
            continue
        fields = sorted(
            {key for key in set(old_item) | set(new_item) if old_item.get(key) != new_item.get(key)}
        )
        changed.append({"label": _item_label(new_item), "fields": fields})

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "changed": sorted(changed, key=lambda entry: entry["label"]),
    }


def build_diff(
    client: UniFiClient,
    directory: Path,
    *,
    only: list[str] | None = None,
) -> dict[str, Any]:
    if not directory.is_dir():
        raise UniFiError(
            f"Snapshot directory '{directory}' does not exist.",
            code="not_found",
        )
    snapshot_map = _snapshot_collections(directory)
    if only:
        requested = set(only)
        snapshot_map = {name: value for name, value in snapshot_map.items() if name in requested}

    official = {
        name: OFFICIAL_COLLECTIONS[name]
        for name, is_legacy in snapshot_map.items()
        if not is_legacy and name in OFFICIAL_COLLECTIONS
    }
    legacy = tuple(name for name, is_legacy in snapshot_map.items() if is_legacy)

    live, errors = collect_all(client, official=official, legacy=legacy)

    collections: dict[str, Any] = {}
    identical = True
    for collection, is_legacy in sorted(snapshot_map.items()):
        if not is_legacy and collection not in OFFICIAL_COLLECTIONS:
            collections[collection] = {
                "error": {
                    "code": "unknown_collection",
                    "message": f"Snapshot file '{collection}.json' has no known collection.",
                }
            }
            identical = False
            continue
        path = directory / _filename(collection, legacy=is_legacy)
        before = _load_snapshot(path)
        if collection in errors:
            collections[collection] = {"error": errors[collection]}
            identical = False
            continue
        after_items = live.get(collection, ([], is_legacy))[0]
        result = diff_collection(before, after_items)
        collections[collection] = result
        if result["added"] or result["removed"] or result["changed"]:
            identical = False

    return {"collections": collections, "identical": identical}


def format_diff_human(report: dict[str, Any]) -> str:
    lines: list[str] = []
    if report["identical"]:
        lines.append("No differences from snapshot.")
        return "\n".join(lines)
    lines.append("Differences from snapshot:")
    for collection in sorted(report["collections"]):
        result = report["collections"][collection]
        if "error" in result:
            lines.append(f"  {collection}: error ({result['error']['code']})")
            continue
        added = result["added"]
        removed = result["removed"]
        changed = result["changed"]
        if not (added or removed or changed):
            continue
        lines.append(f"  {collection}:")
        for label in added:
            lines.append(f"    A  {label}")
        for label in removed:
            lines.append(f"    D  {label}")
        for entry in changed:
            fields = ", ".join(entry["fields"])
            lines.append(f"    M  {entry['label']} ({fields})")
    if len(lines) == 1:
        lines.append("  (no changes)")
    return "\n".join(lines)


def command_diff(client: UniFiClient, args: argparse.Namespace) -> Any:
    directory = Path(args.dir)
    only = list(args.collection) if getattr(args, "collection", None) else None
    report = build_diff(client, directory, only=only)
    # Stash the verdict on the namespace so main() can honour --exit-code even
    # when the human formatter turns the report into a string.
    args.diff_identical = report["identical"]
    if wants_human_format(args):
        return format_diff_human(report)
    return report


def diff_exit_code(args: argparse.Namespace) -> int:
    """Exit code for diff: 1 when --exit-code was passed and differences exist."""
    if not getattr(args, "exit_code", False):
        return 0
    return 0 if getattr(args, "diff_identical", True) else 1


# ---------------------------------------------------------------------------
# Backup verbs (item 4)
# ---------------------------------------------------------------------------

AUTOBACKUP_DL_TEMPLATE = "/proxy/network/dl/autobackup/{filename}"


def command_backup_list(client: UniFiClient, _args: argparse.Namespace) -> Any:
    payload = {"cmd": "list-backups"}
    response = client.legacy("POST", "/cmd/backup", payload=payload)
    if isinstance(response, dict) and isinstance(response.get("data"), list):
        return response["data"]
    return response


def command_backup_generate(client: UniFiClient, args: argparse.Namespace) -> Any:
    days = args.days if getattr(args, "days", None) is not None else -1
    payload = {"cmd": "backup", "days": days}
    path = "/cmd/backup"
    require_confirmation(args, "POST", legacy_dry_run_path(client, path), payload)
    return client.legacy("POST", path, payload=payload)


def _newest_backup_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not entries:
        return None

    def sort_key(entry: dict[str, Any]) -> tuple[float, str]:
        for key in ("time", "datetime", "mtime", "date"):
            value = entry.get(key)
            if isinstance(value, int | float) and not isinstance(value, bool):
                return (float(value), "")
            if isinstance(value, str) and value:
                return (0.0, value)
        return (0.0, "")

    return sorted(entries, key=sort_key)[-1]


def _backup_filename(entry: dict[str, Any]) -> str | None:
    for key in ("filename", "file", "name"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    url = entry.get("url")
    if isinstance(url, str) and url:
        return url.rsplit("/", 1)[-1]
    return None


def resolve_backup_path(client: UniFiClient, args: argparse.Namespace) -> str:
    override = getattr(args, "path", None)
    if override:
        return str(override)
    response = client.legacy("POST", "/cmd/backup", payload={"cmd": "list-backups"})
    entries = [item for item in data_list(response) if isinstance(item, dict)]
    newest = _newest_backup_entry(entries)
    if newest is None:
        raise UniFiError(
            "No backups found to download; run backup-generate first or pass --path.",
            code="not_found",
        )
    filename = _backup_filename(newest)
    if not filename:
        raise UniFiError(
            "Newest backup entry has no filename/url field.",
            code="response_shape",
            details={"entry_keys": sorted(newest)},
        )
    if filename.startswith(("http://", "https://", "/")):
        return filename
    return AUTOBACKUP_DL_TEMPLATE.format(filename=filename)


def command_backup_download(client: UniFiClient, args: argparse.Namespace) -> Any:
    path = resolve_backup_path(client, args)
    data = client.request_bytes("GET", path)
    output = Path(args.output)
    output.write_bytes(data)
    return {
        "ok": True,
        "path": path,
        "output": str(output),
        "bytes": len(data),
    }
