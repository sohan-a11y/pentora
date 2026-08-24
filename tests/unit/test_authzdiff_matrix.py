import json
from pathlib import Path

import pytest
import yaml

from pentora.authzdiff.matrix import (
    build_matrix,
    load_roles,
    render_plan_json,
    render_plan_markdown,
)

ROLES = [
    {"name": "admin", "headers": {"Authorization": "Bearer admin-tok"}},
    {"name": "user", "headers": {"Authorization": "Bearer user-tok"}},
    {"name": "support", "headers": {}},
]


def _spec(*, n_secured: int = 2, n_public: int = 1) -> dict:
    paths: dict = {}
    for i in range(n_secured):
        paths[f"/api/resource{i}"] = {"get": {"responses": {}}}
    for i in range(n_public):
        paths[f"/public{i}"] = {"get": {"security": []}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "api", "version": "1"},
        "security": [{"bearerAuth": []}],
        "paths": paths,
    }


def test_load_roles_wrapped_and_bare(tmp_path: Path) -> None:
    wrapped = tmp_path / "wrapped.yaml"
    wrapped.write_text(yaml.safe_dump({"roles": ROLES}), encoding="utf-8")
    roles = load_roles(wrapped)
    assert [r.name for r in roles] == ["admin", "user", "support"]
    assert roles[0].headers == {"Authorization": "Bearer admin-tok"}

    bare = tmp_path / "bare.yaml"
    bare.write_text(yaml.safe_dump(ROLES), encoding="utf-8")
    assert load_roles(bare) == roles


def test_load_roles_rejects_invalid(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("roles: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        load_roles(empty)

    bad = tmp_path / "bad.yaml"
    bad.write_text("- name_only_missing_headers_is_fine\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid role entry"):
        load_roles(bad)


def test_matrix_pair_count_matches_n_secured_times_n_times_n_minus_1() -> None:
    spec = _spec(n_secured=2, n_public=1)
    cases = build_matrix(spec, _roles())
    # 2 secured endpoints * 3 roles * (3 - 1) foreign pairs = 12
    assert len(cases) == 2 * 3 * 2


def test_matrix_excludes_own_role_pairs() -> None:
    cases = build_matrix(_spec(n_secured=1), _roles())
    for c in cases:
        assert c.caller != c.owner
    pairs = {(c.caller, c.owner) for c in cases}
    assert ("user", "admin") in pairs
    assert ("admin", "admin") not in pairs


def test_matrix_assume_secured_includes_public_endpoints() -> None:
    spec = _spec(n_secured=1, n_public=1)
    without_flag = len(build_matrix(spec, _roles()))
    with_flag = len(build_matrix(spec, _roles(), assume_secured=True))
    # one extra endpoint becomes secured: +3*2 cases
    assert with_flag == without_flag + 3 * 2


def test_case_ids_are_stable_and_unique() -> None:
    cases_a = build_matrix(_spec(), _roles())
    cases_b = build_matrix(_spec(), _roles())
    ids_a = [c.case_id for c in cases_a]
    assert ids_a == [c.case_id for c in cases_b]
    assert len(set(ids_a)) == len(ids_a)


def test_plan_json_contains_expected_verdicts() -> None:
    cases = build_matrix(_spec(), _roles())
    payload = json.loads(render_plan_json(cases, roles=_roles()))
    assert payload["total_cases"] == len(cases)
    assert payload["expected_verdict"]["status"] == [403, 404]
    first = payload["cases"][0]
    assert first["expected_status"] == [403, 404]
    assert first["caller"] != first["owner"]
    assert json.dumps(payload).count('"expected_status": [403, 404]') == len(cases)


def test_plan_markdown_lists_cases_and_expected_verdicts(tmp_path: Path) -> None:
    cases = build_matrix(_spec(n_secured=1), _roles())
    md = render_plan_markdown(cases, roles=_roles())
    out = tmp_path / "plan.md"
    out.write_text(md, encoding="utf-8")

    assert "# Authorization Diff Plan" in md
    assert f"## Cases ({len(cases)})" in md
    assert "403/404" in md
    for c in cases:
        assert c.case_id in md
        assert c.caller in md and c.owner in md
        row = next(line for line in md.splitlines() if c.case_id in line)
        assert "| 403/404 |" in row
    assert Path(out).read_text(encoding="utf-8") == md


def _roles():
    from pentora.authzdiff.matrix import Role

    return [Role(r["name"], dict(r["headers"])) for r in ROLES]
