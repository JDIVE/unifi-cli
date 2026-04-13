"""Configuration loading for the UniFi CLI."""

from __future__ import annotations

import argparse
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SITE = "default"
DEFAULT_TIMEOUT_SECONDS = 30
ENV_ALIASES: dict[str, list[str]] = {
    "base_url": ["UNIFI_BASE_URL", "UNIFI_NETWORK_BASE_URL"],
    "api_key": ["UNIFI_API_KEY", "UNIFI_NETWORK_API_KEY"],
    "site": ["UNIFI_SITE"],
    "site_id": ["UNIFI_SITE_ID"],
    "verify_tls": ["UNIFI_VERIFY_TLS"],
    "timeout_seconds": ["UNIFI_TIMEOUT_SECONDS"],
}


@dataclass(frozen=True)
class Config:
    base_url: str | None
    site: str
    site_id: str | None
    api_key: str | None
    verify_tls: bool
    timeout_seconds: int
    config_path: Path
    config_exists: bool
    sources: dict[str, str]


def default_config_path() -> Path:
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home).expanduser() / "unifi" / "config.toml"
    return Path.home() / ".config" / "unifi" / "config.toml"


def parse_bool(value: str | bool | None, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    return payload if isinstance(payload, dict) else {}


def _resolve_value(
    *,
    arg_value: Any,
    env_names: list[str],
    config_data: dict[str, Any],
    config_key: str,
    default: Any,
    transform: Any = None,
) -> tuple[Any, str]:
    if arg_value is not None:
        value = transform(arg_value) if transform else arg_value
        return value, "flag"

    for env_name in env_names:
        raw_value = os.environ.get(env_name)
        if raw_value not in (None, ""):
            value = transform(raw_value) if transform else raw_value
            return value, f"env:{env_name}"

    if config_key in config_data and config_data[config_key] not in (None, ""):
        raw_value = config_data[config_key]
        value = transform(raw_value) if transform else raw_value
        return value, "config"

    return default, "default"


def build_config(args: argparse.Namespace) -> Config:
    config_path = Path(args.config).expanduser() if args.config else default_config_path()
    config_data = _load_toml(config_path)
    sources: dict[str, str] = {}

    base_url, sources["base_url"] = _resolve_value(
        arg_value=args.base_url,
        env_names=ENV_ALIASES["base_url"],
        config_data=config_data,
        config_key="base_url",
        default=None,
        transform=lambda value: str(value).rstrip("/"),
    )
    site, sources["site"] = _resolve_value(
        arg_value=args.site,
        env_names=ENV_ALIASES["site"],
        config_data=config_data,
        config_key="site",
        default=DEFAULT_SITE,
        transform=str,
    )
    site_id, sources["site_id"] = _resolve_value(
        arg_value=args.site_id,
        env_names=ENV_ALIASES["site_id"],
        config_data=config_data,
        config_key="site_id",
        default=None,
        transform=str,
    )
    api_key, sources["api_key"] = _resolve_value(
        arg_value=args.api_key,
        env_names=ENV_ALIASES["api_key"],
        config_data=config_data,
        config_key="api_key",
        default=None,
        transform=str,
    )

    insecure_flag = getattr(args, "insecure", False)
    verify_arg = False if insecure_flag else None
    verify_tls, sources["verify_tls"] = _resolve_value(
        arg_value=verify_arg,
        env_names=ENV_ALIASES["verify_tls"],
        config_data=config_data,
        config_key="verify_tls",
        default=True,
        transform=lambda value: parse_bool(value, default=True),
    )
    timeout_seconds, sources["timeout_seconds"] = _resolve_value(
        arg_value=args.timeout_seconds,
        env_names=ENV_ALIASES["timeout_seconds"],
        config_data=config_data,
        config_key="timeout_seconds",
        default=DEFAULT_TIMEOUT_SECONDS,
        transform=int,
    )

    return Config(
        base_url=base_url,
        site=site,
        site_id=site_id,
        api_key=api_key,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        config_path=config_path,
        config_exists=config_path.exists(),
        sources=sources,
    )
