"""TDD tests for CorsModule."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.cors import CorsModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _endpoint_finding(url: str = "https://t.example/api/data") -> Finding:
    return Finding(
        module="discovery.endpoint",
        title="endpoint",
        endpoint=url,
        method="GET",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )


@pytest.mark.asyncio
@respx.mock
async def test_reflected_evil_origin_flagged(tmp_path: Path) -> None:
    """Server reflects evil.com origin => HIGH finding."""
    respx.get("https://t.example/api/data").mock(
        return_value=httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "https://evil.com",
                "access-control-allow-credentials": "true",
            },
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_endpoint_finding())
    findings = await CorsModule().run(ctx)
    cors = [f for f in findings if "cors" in f.title.lower() or "origin" in f.title.lower()]
    assert len(cors) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in cors)


@pytest.mark.asyncio
@respx.mock
async def test_null_origin_reflected_flagged(tmp_path: Path) -> None:
    """Server reflects null origin => HIGH finding."""
    def respond(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        if origin == "null":
            return httpx.Response(
                200, headers={"access-control-allow-origin": "null"}
            )
        return httpx.Response(200, headers={})

    respx.get("https://t.example/api/data").mock(side_effect=respond)
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_endpoint_finding())
    findings = await CorsModule().run(ctx)
    null_findings = [
        f for f in findings
        if "null" in f.evidence.lower() or "cors" in f.title.lower()
    ]
    assert len(null_findings) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_wildcard_with_credentials_critical(tmp_path: Path) -> None:
    """Wildcard ACAO + credentials => CRITICAL finding."""
    respx.get("https://t.example/api/data").mock(
        return_value=httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_endpoint_finding())
    findings = await CorsModule().run(ctx)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_strict_cors_no_findings(tmp_path: Path) -> None:
    """Server returns its own origin only => no CORS finding."""
    respx.get("https://t.example/api/data").mock(
        return_value=httpx.Response(
            200,
            headers={"access-control-allow-origin": "https://t.example"},
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_endpoint_finding())
    findings = await CorsModule().run(ctx)
    cors = [f for f in findings if "cors" in f.title.lower()]
    assert cors == []


@pytest.mark.asyncio
async def test_no_endpoints_returns_empty(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await CorsModule().run(ctx)
    assert findings == []
