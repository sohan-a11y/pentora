"""TDD tests for TakeoverModule."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.takeover import TakeoverModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _subdomain_finding(url: str) -> Finding:
    return Finding(
        module="recon.subdomain",
        title="Subdomain",
        endpoint=url,
        method="GET",
        evidence="subdomain",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )


@pytest.mark.asyncio
@respx.mock
async def test_github_pages_takeover_critical(tmp_path: Path) -> None:
    """GitHub Pages body fingerprint => CRITICAL finding."""
    url = "https://assets.t.example"
    respx.get(url).mock(
        return_value=httpx.Response(
            200, text="There isn't a GitHub Pages site here"
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_subdomain_finding(url))
    findings = await TakeoverModule().run(ctx)
    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert "takeover" in findings[0].title.lower() or "github" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_heroku_takeover_critical(tmp_path: Path) -> None:
    url = "https://api.t.example"
    respx.get(url).mock(
        return_value=httpx.Response(200, text="No such app")
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_subdomain_finding(url))
    findings = await TakeoverModule().run(ctx)
    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_no_fingerprint_match_no_finding(tmp_path: Path) -> None:
    """Normal 200 response with no fingerprint => no finding."""
    url = "https://www.t.example"
    respx.get(url).mock(
        return_value=httpx.Response(200, text="Welcome to our site!")
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_subdomain_finding(url))
    findings = await TakeoverModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_no_subdomains_returns_empty(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await TakeoverModule().run(ctx)
    assert findings == []


def test_fingerprints_count_is_15() -> None:
    from pentora.data.takeover_fingerprints import TAKEOVER_FINGERPRINTS
    assert len(TAKEOVER_FINGERPRINTS) == 15
