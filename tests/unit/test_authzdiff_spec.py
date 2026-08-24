import json
from pathlib import Path

import pytest

from pentora.authzdiff.spec import (
    Endpoint,
    is_secured,
    iter_endpoints,
    load_spec,
    spec_diff,
)

GLOBAL_SECURED = [{"bearerAuth": []}]


def _write_yaml(tmp_path: Path, data: dict) -> Path:
    import yaml

    p = tmp_path / "spec.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def _spec(security: list | None = GLOBAL_SECURED) -> dict:
    return {
        "openapi": "3.1.0",
        "info": {"title": "api", "version": "1"},
        "security": security,
        "paths": {
            "/api/users/{id}": {
                "get": {"responses": {}},
                "put": {"responses": {}},
            },
            "/health": {
                "get": {
                    "security": [],
                },
            },
        },
    }


def test_load_spec_yaml_and_json(tmp_path: Path) -> None:
    yml = _write_yaml(tmp_path, _spec())
    assert load_spec(yml)["openapi"] == "3.1.0"

    js = tmp_path / "spec.json"
    js.write_text(json.dumps(_spec()), encoding="utf-8")
    assert load_spec(js)["openapi"] == "3.1.0"


def test_load_spec_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_spec(p)


def test_iter_endpoints_extracts_operations() -> None:
    endpoints = iter_endpoints(_spec())
    assert (Endpoint("/api/users/{id}", "get") in endpoints)
    assert (Endpoint("/api/users/{id}", "put") in endpoints)
    assert (Endpoint("/health", "get") in endpoints)
    assert len(endpoints) == 3


def test_is_secured_global_operation_override_and_flag() -> None:
    spec = _spec()
    get_ep = Endpoint("/api/users/{id}", "get")
    health = Endpoint("/health", "get")
    assert is_secured(spec, get_ep) is True
    assert is_secured(spec, health) is False  # explicit empty security list
    assert is_secured({"openapi": "3.1.0", "paths": {"/x": {"get": {}}}}, Endpoint("/x", "get")) is False
    assert is_secured(spec, health, assume_secured=True) is True


def test_is_secured_operation_level_overrides_global() -> None:
    spec = _spec()
    spec["paths"]["/health"]["get"] = {"security": []}
    assert is_secured(spec, Endpoint("/health", "get")) is False
    spec["paths"]["/public"] = {"get": {"security": [{"apiKey": []}]}}
    assert is_secured(spec, Endpoint("/public", "get")) is True


def test_spec_diff_detects_added_and_removed() -> None:
    old = _spec()
    new = _spec()
    new["paths"]["/api/orders/{id}"] = {"get": {"responses": {}}}
    del new["paths"]["/health"]

    diff = spec_diff(old, new)
    assert [e.path for e in diff.added_endpoints] == ["/api/orders/{id}"]
    assert [e.path for e in diff.removed_endpoints] == ["/health"]
    assert diff.param_changes == ()
    payload = diff.to_dict()
    assert payload["added_endpoints"] == [{"method": "GET", "path": "/api/orders/{id}"}]


def test_spec_diff_param_changes_added_removed_required() -> None:
    old = _spec()
    old["paths"]["/api/users/{id}"]["get"]["parameters"] = [
        {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
        {"name": "filter", "in": "query", "required": False},
    ]
    new = _spec()
    new["paths"]["/api/users/{id}"]["get"]["parameters"] = [
        {"name": "filter", "in": "query", "required": True},
        {"name": "expand", "in": "query"},
    ]

    diff = spec_diff(old, new)
    assert len(diff.param_changes) == 1
    change = diff.param_changes[0]
    assert change.path == "/api/users/{id}"
    assert change.method == "get"
    assert change.added_params == ("query:expand",)
    assert change.removed_params == ("query:verbose",)
    assert change.now_required == ("query:filter",)


def test_spec_diff_no_changes_yields_empty() -> None:
    diff = spec_diff(_spec(), _spec())
    assert diff.added_endpoints == ()
    assert diff.removed_endpoints == ()
    assert diff.param_changes == ()
