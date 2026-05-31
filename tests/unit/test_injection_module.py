"""TDD tests for InjectionModule — write first, implement after."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.injection import InjectionModule
from pentora.scope import Scope
from pentora.wrappers.dalfox import DalfoxHit
from pentora.wrappers.ghauri import GhauriFinding
from pentora.wrappers.oralyzer import OralyzerHit
from pentora.wrappers.smuggler import SmugglerFinding
from pentora.wrappers.sqlmap import SqlmapFinding


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _finding(endpoint: str, method: str = "GET", **extra: object) -> Finding:
    return Finding(
        module="discovery.endpoint",
        title="endpoint",
        endpoint=endpoint,
        method=method,
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra=dict(extra),
    )


# ---------------------------------------------------------------------------
# Routing tests — assert correct wrappers are invoked based on URL/param shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sqli_wrapper_invoked_for_numeric_param(tmp_path: Path) -> None:
    """Endpoint with numeric param triggers sqlmap + ghauri."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/items/42"))

    sqlmap_result = [
        SqlmapFinding(parameter="id", dbms="MySQL", technique="time-based", evidence="vuln")
    ]
    ghauri_result: list[GhauriFinding] = []

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        MockSqlmap.return_value.run = AsyncMock(return_value=sqlmap_result)
        MockGhauri.return_value.run = AsyncMock(return_value=ghauri_result)
        MockDalfox.return_value.run = AsyncMock(return_value=[])
        MockXss.return_value.run = AsyncMock(return_value=[])
        MockCommix.return_value.run = AsyncMock(return_value=[])
        MockOralyzer.return_value.run = AsyncMock(return_value=[])
        MockSmuggler.return_value.run = AsyncMock(return_value=[])

        findings = await InjectionModule().run(ctx)

    assert MockSqlmap.return_value.run.called
    assert MockGhauri.return_value.run.called
    sqli_findings = [f for f in findings if "sqli" in f.module or "sql" in f.module.lower()]
    assert len(sqli_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in sqli_findings)


@pytest.mark.asyncio
async def test_xss_wrapper_invoked_for_search_param(tmp_path: Path) -> None:
    """Endpoint with 'q' param triggers dalfox + xsstrike."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/search", params=["q"]))

    xss_hit = DalfoxHit(param="q", payload="<script>", type="R", severity="high")

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        MockSqlmap.return_value.run = AsyncMock(return_value=[])
        MockGhauri.return_value.run = AsyncMock(return_value=[])
        MockDalfox.return_value.run = AsyncMock(return_value=[xss_hit])
        MockXss.return_value.run = AsyncMock(return_value=[])
        MockCommix.return_value.run = AsyncMock(return_value=[])
        MockOralyzer.return_value.run = AsyncMock(return_value=[])
        MockSmuggler.return_value.run = AsyncMock(return_value=[])

        findings = await InjectionModule().run(ctx)

    assert MockDalfox.return_value.run.called
    assert MockXss.return_value.run.called
    xss_findings = [f for f in findings if "xss" in f.module.lower()]
    assert len(xss_findings) >= 1


@pytest.mark.asyncio
async def test_open_redirect_wrapper_invoked_for_redirect_param(tmp_path: Path) -> None:
    """Endpoint with 'next' param triggers oralyzer."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/login", params=["next"]))

    redir_hit = OralyzerHit(url="https://t.example/login?next=evil", redirect_to="https://evil.com")

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        MockSqlmap.return_value.run = AsyncMock(return_value=[])
        MockGhauri.return_value.run = AsyncMock(return_value=[])
        MockDalfox.return_value.run = AsyncMock(return_value=[])
        MockXss.return_value.run = AsyncMock(return_value=[])
        MockCommix.return_value.run = AsyncMock(return_value=[])
        MockOralyzer.return_value.run = AsyncMock(return_value=[redir_hit])
        MockSmuggler.return_value.run = AsyncMock(return_value=[])

        findings = await InjectionModule().run(ctx)

    assert MockOralyzer.return_value.run.called
    redir_findings = [f for f in findings if "redirect" in f.module.lower()]
    assert len(redir_findings) >= 1
    assert any(f.severity in (Severity.LOW, Severity.MEDIUM) for f in redir_findings)


@pytest.mark.asyncio
async def test_smuggler_invoked_once_per_host(tmp_path: Path) -> None:
    """Smuggler runs once per unique host, not once per endpoint."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    # Two endpoints on same host
    await ctx.store.add(_finding("https://t.example/a"))
    await ctx.store.add(_finding("https://t.example/b"))

    smug_hit = SmugglerFinding(technique="CL.TE", evidence="CL.TE timeout differential")

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        MockSqlmap.return_value.run = AsyncMock(return_value=[])
        MockGhauri.return_value.run = AsyncMock(return_value=[])
        MockDalfox.return_value.run = AsyncMock(return_value=[])
        MockXss.return_value.run = AsyncMock(return_value=[])
        MockCommix.return_value.run = AsyncMock(return_value=[])
        MockOralyzer.return_value.run = AsyncMock(return_value=[])
        MockSmuggler.return_value.run = AsyncMock(return_value=[smug_hit])

        findings = await InjectionModule().run(ctx)

    # Smuggler should run exactly once for t.example
    assert MockSmuggler.return_value.run.call_count == 1
    smug_findings = [f for f in findings if "smuggl" in f.module.lower()]
    assert len(smug_findings) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_nosqli_injection_detected_on_json_body(tmp_path: Path) -> None:
    """NoSQLi check fires on json_body kind endpoints and detects auth bypass."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(
        _finding("https://t.example/api/login", method="POST", kind="json_body")
    )

    # Normal POST returns a short body
    normal_body = json.dumps({"error": "invalid credentials"})
    # NoSQLi payload returns a longer body (admin panel data) — structure differs
    nosql_body = json.dumps({"token": "abc123", "user": {"id": 1, "role": "admin"}})

    def responder(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "$gt" in body or "$ne" in body:
            return httpx.Response(200, text=nosql_body)
        return httpx.Response(401, text=normal_body)

    respx.post("https://t.example/api/login").mock(side_effect=responder)

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        all_mocks = (
            MockSqlmap, MockGhauri, MockDalfox, MockXss,
            MockCommix, MockOralyzer, MockSmuggler,
        )
        for mock in all_mocks:
            mock.return_value.run = AsyncMock(return_value=[])

        findings = await InjectionModule().run(ctx)

    nosql_findings = [
        f for f in findings if "nosql" in f.module.lower() or "nosql" in f.title.lower()
    ]
    assert len(nosql_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in nosql_findings)


@pytest.mark.asyncio
async def test_findings_persisted_to_store(tmp_path: Path) -> None:
    """All findings should be saved to ctx.store."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/items/1"))

    sqli = SqlmapFinding(parameter="id", dbms="MySQL", technique="blind", evidence="vuln")

    with (
        patch("pentora.modules.injection.SqlmapWrapper") as MockSqlmap,
        patch("pentora.modules.injection.GhauriWrapper") as MockGhauri,
        patch("pentora.modules.injection.DalfoxWrapper") as MockDalfox,
        patch("pentora.modules.injection.XsstrikeWrapper") as MockXss,
        patch("pentora.modules.injection.CommixWrapper") as MockCommix,
        patch("pentora.modules.injection.OralyzerWrapper") as MockOralyzer,
        patch("pentora.modules.injection.SmugglerWrapper") as MockSmuggler,
    ):
        MockSqlmap.return_value.run = AsyncMock(return_value=[sqli])
        other_mocks = (
            MockGhauri, MockDalfox, MockXss, MockCommix, MockOralyzer, MockSmuggler
        )
        for mock in other_mocks:
            mock.return_value.run = AsyncMock(return_value=[])

        await InjectionModule().run(ctx)

    stored = await ctx.store.all()
    injection_stored = [f for f in stored if f.module.startswith("injection")]
    assert len(injection_stored) >= 1


@pytest.mark.asyncio
async def test_no_candidates_returns_empty(tmp_path: Path) -> None:
    """When the store is empty, no findings are emitted."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await InjectionModule().run(ctx)
    assert findings == []
