"""TDD tests for RateLimitModule."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.ratelimit import RateLimitModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _auth_finding(url: str = "https://t.example/login") -> Finding:
    return Finding(
        module="auth.login",
        title="Login endpoint",
        endpoint=url,
        method="POST",
        evidence="login",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra={"kind": "login"},
    )


@pytest.mark.asyncio
@respx.mock
async def test_no_throttle_flagged_as_high(tmp_path: Path) -> None:
    """All 30 requests return 401 (no 429) => HIGH finding."""
    respx.post("https://t.example/login").mock(return_value=httpx.Response(401))
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_auth_finding())
    findings = await RateLimitModule().run(ctx)
    assert len(findings) >= 1
    assert any(f.severity in (Severity.MEDIUM, Severity.HIGH) for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_throttled_requests_no_finding(tmp_path: Path) -> None:
    """All 30 requests return 429 => no finding."""
    respx.post("https://t.example/login").mock(return_value=httpx.Response(429))
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_auth_finding())
    findings = await RateLimitModule().run(ctx)
    rate_limit_findings = [
        f for f in findings if "rate" in f.title.lower() or "throttle" in f.title.lower()
    ]
    assert rate_limit_findings == []


@pytest.mark.asyncio
@respx.mock
async def test_retry_after_header_counts_as_throttled(tmp_path: Path) -> None:
    """Retry-After header => counts as throttled => no finding."""
    respx.post("https://t.example/login").mock(
        return_value=httpx.Response(
            200, headers={"retry-after": "60"}
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_auth_finding())
    findings = await RateLimitModule().run(ctx)
    rate_limit_findings = [
        f for f in findings if "rate" in f.title.lower() or "throttle" in f.title.lower()
    ]
    assert rate_limit_findings == []


@pytest.mark.asyncio
async def test_no_auth_endpoints_returns_empty(tmp_path: Path) -> None:
    """No auth-like endpoints stored => module returns empty."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await RateLimitModule().run(ctx)
    assert findings == []
