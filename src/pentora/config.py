"""3-layer config loader: built-in defaults < user config < CLI overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULTS: dict[str, Any] = {
    "defaults": {
        "rate_limit": 10,
        "threads": 50,
        "proxy": "auto",
        "llm_provider": None,  # no default — must be set by user
        "llm_model": None,
    },
    "api_keys": {},
    "profiles": {},
}


@dataclass
class Config:
    rate_limit: int = 10
    threads: int = 50
    proxy: str = "auto"
    llm_provider: str | None = None
    llm_model: str | None = None
    api_keys: dict[str, str] = field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)


def _interpolate_env(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        return os.environ.get(value[1:], value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(cli_overrides: dict[str, Any] | None = None) -> Config:
    merged = dict(_DEFAULTS)

    user_path = os.environ.get("PENTORA_CONFIG") or str(Path.home() / ".pentora" / "config.yaml")
    p = Path(user_path)
    if p.exists():
        user_cfg = yaml.safe_load(p.read_text()) or {}
        merged = _deep_merge(merged, user_cfg)

    merged = _interpolate_env(merged)

    defaults = merged["defaults"]
    if cli_overrides:
        for k, v in cli_overrides.items():
            defaults[k] = v

    return Config(
        rate_limit=defaults["rate_limit"],
        threads=defaults["threads"],
        proxy=defaults["proxy"],
        llm_provider=defaults["llm_provider"],
        llm_model=defaults["llm_model"],
        api_keys=merged.get("api_keys", {}),
        profiles=merged.get("profiles", {}),
    )
