"""OpenAPI 3.x spec loading, endpoint extraction, and offline spec diffing."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


@dataclass(frozen=True)
class Endpoint:
    path: str
    method: str  # lowercase


@dataclass(frozen=True)
class ParamChange:
    path: str
    method: str
    added_params: tuple[str, ...]  # "in:name"
    removed_params: tuple[str, ...]
    now_required: tuple[str, ...]


@dataclass(frozen=True)
class SpecDiff:
    added_endpoints: tuple[Endpoint, ...]
    removed_endpoints: tuple[Endpoint, ...]
    param_changes: tuple[ParamChange, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_endpoints": [
                {"method": e.method.upper(), "path": e.path} for e in self.added_endpoints
            ],
            "removed_endpoints": [
                {"method": e.method.upper(), "path": e.path} for e in self.removed_endpoints
            ],
            "param_changes": [
                {
                    "method": pc.method.upper(),
                    "path": pc.path,
                    "added_params": list(pc.added_params),
                    "removed_params": list(pc.removed_params),
                    "now_required": list(pc.now_required),
                }
                for pc in self.param_changes
            ],
        }


def load_spec(path: Path) -> dict[str, Any]:
    """Load an OpenAPI 3.x spec from a YAML or JSON file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data: Any = json.loads(text)
    else:
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a spec mapping")
    return data


def iter_endpoints(spec: dict[str, Any]) -> list[Endpoint]:
    """List every operation defined in the spec, deterministically ordered."""
    paths = spec.get("paths") or {}
    endpoints: list[Endpoint] = []
    for path in sorted(paths):
        item = paths[path]
        if not isinstance(item, dict):
            continue
        for method in sorted(HTTP_METHODS):
            if isinstance(item.get(method), dict):
                endpoints.append(Endpoint(path=path, method=method))
    return endpoints


def _effective_security(spec: dict[str, Any], ep: Endpoint) -> Any:
    paths = spec.get("paths") or {}
    item = paths.get(ep.path) or {}
    operation = item.get(ep.method) or {} if isinstance(item, dict) else {}
    security = operation.get("security") if isinstance(operation, dict) else None
    if security is None:
        security = spec.get("security")
    return security


def is_secured(spec: dict[str, Any], ep: Endpoint, *, assume_secured: bool = False) -> bool:
    """True when the endpoint declares security; --assume-secured marks all secured.

    A non-empty ``security`` requirement (operation-level overriding the global
    one) counts as secured. An explicit empty list means deliberately public.
    """
    if assume_secured:
        return True
    security = _effective_security(spec, ep)
    return bool(security)


def spec_diff(old: dict[str, Any], new: dict[str, Any]) -> SpecDiff:
    """Diff two spec revisions: added/removed endpoints and parameter changes."""
    old_eps = set(iter_endpoints(old))
    new_eps = set(iter_endpoints(new))

    param_changes: list[ParamChange] = []
    for shared in sorted(old_eps & new_eps, key=lambda e: (e.path, e.method)):
        change = _param_diff(
            _params_for(old, shared),
            _params_for(new, shared),
        )
        if change is not None:
            param_changes.append(
                ParamChange(path=shared.path, method=shared.method, **change)
            )

    order = lambda e: (e.path, e.method)  # noqa: E731
    return SpecDiff(
        added_endpoints=tuple(sorted(new_eps - old_eps, key=order)),
        removed_endpoints=tuple(sorted(old_eps - new_eps, key=order)),
        param_changes=tuple(param_changes),
    )


def _params_for(spec: dict[str, Any], ep: Endpoint) -> list[dict[str, Any]]:
    """Merge path-level and operation-level parameter definitions."""
    paths = spec.get("paths") or {}
    item = paths.get(ep.path) or {}
    if not isinstance(item, dict):
        return []
    operation = item.get(ep.method) or {}
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in (item, operation):
        if not isinstance(source, dict):
            continue
        for p in source.get("parameters") or []:
            if isinstance(p, dict) and "name" in p and "in" in p:
                merged[(str(p["in"]), str(p["name"]))] = p
    return list(merged.values())


def _param_diff(
    old_params: list[dict[str, Any]], new_params: list[dict[str, Any]]
) -> dict[str, tuple[str, ...]] | None:
    def keys(params: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        return {(str(p["in"]), str(p["name"])): p for p in params}

    old_by_key, new_by_key = keys(old_params), keys(new_params)
    added = sorted(f"{i}:{n}" for i, n in new_by_key.keys() - old_by_key.keys())
    removed = sorted(f"{i}:{n}" for i, n in old_by_key.keys() - new_by_key.keys())
    now_required = sorted(
        f"{i}:{n}"
        for (i, n), p in new_by_key.items()
        if (i, n) in old_by_key
        and p.get("required", False)
        and not old_by_key[(i, n)].get("required", False)
    )
    if not (added or removed or now_required):
        return None
    return {
        "added_params": tuple(added),
        "removed_params": tuple(removed),
        "now_required": tuple(now_required),
    }
