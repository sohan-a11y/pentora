import json
from pathlib import Path

import respx
from click.testing import CliRunner

from pentora.cli import main

SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "api", "version": "1"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/users/{id}": {"get": {"responses": {}}},
        "/health": {"get": {"security": []}},
    },
}

ROLES = """
roles:
  - name: admin
    headers:
      Authorization: Bearer admin-tok
  - name: user
    headers:
      Authorization: Bearer user-tok
"""


def _write_inputs(tmp_path: Path, spec: dict | None = None, old_spec: dict | None = None) -> dict:
    files = {}
    spec = spec if spec is not None else SPEC
    current = tmp_path / "current.yaml"
    current.write_text(json.dumps(spec), encoding="utf-8")
    files["spec"] = str(current)
    if old_spec is not None:
        previous = tmp_path / "previous.yaml"
        previous.write_text(json.dumps(old_spec), encoding="utf-8")
        files["old"] = str(previous)
    roles = tmp_path / "roles.yaml"
    roles.write_text(ROLES, encoding="utf-8")
    files["roles"] = str(roles)
    return files


def test_authzdiff_writes_json_and_markdown_plans(tmp_path: Path) -> None:
    files = _write_inputs(tmp_path)
    out = tmp_path / "report"
    result = CliRunner().invoke(
        main,
        [
            "authzdiff",
            "--spec", files["spec"],
            "--roles", files["roles"],
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Planned 2 cross-principal case(s)" in result.output  # 1 secured * 2 * 1

    payload = json.loads((out / "plan.json").read_text(encoding="utf-8"))
    assert payload["total_cases"] == 2
    assert all(c["expected_status"] == [403, 404] for c in payload["cases"])
    assert payload["results"] is None

    md = (out / "plan.md").read_text(encoding="utf-8")
    assert "# Authorization Diff Plan" in md
    assert "| 403/404 |" in md


def test_authzdiff_with_old_spec_includes_diff_section(tmp_path: Path) -> None:
    old = {"openapi": "3.1.0", "info": {"title": "api", "version": "0"}, "paths": {}}
    files = _write_inputs(tmp_path, old_spec=old)
    out = tmp_path / "report"
    result = CliRunner().invoke(
        main,
        ["authzdiff", "--spec", files["spec"], "--old", files["old"], "--roles", files["roles"], "--out", str(out)],  # noqa: E501
    )
    assert result.exit_code == 0, result.output
    assert "+2 / -0 endpoint(s)" in result.output

    payload = json.loads((out / "plan.json").read_text(encoding="utf-8"))
    assert payload["spec_diff"]["added_endpoints"] == [
        {"method": "GET", "path": "/api/users/{id}"},
        {"method": "GET", "path": "/health"},
    ]
    md = (out / "plan.md").read_text(encoding="utf-8")
    assert "## Spec Diff (old → current)" in md


def test_authzdiff_live_replay_classifies_verdicts_via_respx(tmp_path: Path) -> None:
    files = _write_inputs(
        tmp_path,
        spec={**SPEC, "servers": [{"url": "https://stg.example"}]},
    )
    out = tmp_path / "report"

    with respx.mock:
        # Foreign access succeeds -> CRITICAL; control (owner role) also 200.
        respx.get("https://stg.example/api/users/1").mock(return_value=json_response(200))
        result = CliRunner().invoke(
            main,
            ["authzdiff", "--spec", files["spec"], "--roles", files["roles"], "--live", "--out", str(out)],  # noqa: E501
        )

    assert result.exit_code == 0, result.output
    assert "Replaying 2 case(s)" in result.output
    # Mock returns 200 for every send (foreign AND control) -> all critical.
    assert "2 CRITICAL finding(s), 0 expected deny, 0 inconclusive" in result.output
    assert "[!] 2xx on foreign access" in result.output

    payload = json.loads((out / "plan.json").read_text(encoding="utf-8"))
    verdicts = [r["verdict"] for r in payload["results"]]
    assert verdicts.count("critical_finding") == 2


@respx.mock
def test_authzdiff_live_all_denied_is_clean(tmp_path: Path) -> None:
    files = _write_inputs(
        tmp_path,
        spec={**SPEC, "servers": [{"url": "https://stg.example"}]},
    )
    out = tmp_path / "report"
    respx.route(host="stg.example").mock(return_value=json_response(403))

    result = CliRunner().invoke(
        main,
        ["authzdiff", "--spec", files["spec"], "--roles", files["roles"], "--live", "--out", str(out)],  # noqa: E501
    )
    assert result.exit_code == 0, result.output
    assert "0 CRITICAL finding(s), 2 expected deny, 0 inconclusive" in result.output


def test_authzdiff_live_requires_base_url_when_spec_has_no_servers(tmp_path: Path) -> None:
    files = _write_inputs(tmp_path)
    result = CliRunner().invoke(
        main,
        ["authzdiff", "--spec", files["spec"], "--roles", files["roles"], "--live", "--out", str(tmp_path)],  # noqa: E501
    )
    assert result.exit_code != 0
    assert "--live requires --base-url" in result.output


def json_response(status: int):
    import httpx

    return httpx.Response(status, json={"ok": status})
