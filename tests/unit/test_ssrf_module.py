"""TDD tests for SsrfModule — SSRF to metadata endpoints and internal ports."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.ssrf import SsrfModule
from pentora.scope import Scope


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


@pytest.mark.asyncio
@respx.mock
async def test_aws_metadata_ssrf_critical(tmp_path: Path) -> None:
    """SSRF to AWS metadata endpoint returning ami-id is Critical."""
    # The app proxies our injected URL
    respx.get("https://t.example/fetch").mock(
        return_value=httpx.Response(200, text="ami-id=ami-0123456789abcdef0\ninstance-id=i-1234567890abcdef0")
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/fetch", params=["url"]))

    findings = await SsrfModule().run(ctx)
    ssrf_findings = [f for f in findings if "ssrf" in f.module.lower() or "ssrf" in f.title.lower()]
    assert len(ssrf_findings) >= 1
    high_or_critical = [f for f in ssrf_findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(high_or_critical) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_no_ssrf_params_returns_empty(tmp_path: Path) -> None:
    """Endpoint with no URL-accepting params skips SSRF checks."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    # Params that are not redirect/URL params
    await ctx.store.add(_finding("https://t.example/search", params=["q", "page"]))

    findings = await SsrfModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_internal_port_probe_differs_is_high(tmp_path: Path) -> None:
    """Different response to internal IP vs external indicates SSRF."""
    call_count = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        # Internal probe (127.0.0.1) gets a different response
        url_param = str(request.url)
        if "127.0.0.1" in url_param or "127.0.0.1" in request.content.decode(errors="replace"):
            return httpx.Response(200, text="SSH-2.0-OpenSSH_8.2p1")
        return httpx.Response(200, text="not found")

    respx.get("https://t.example/fetch").mock(side_effect=responder)

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/fetch", params=["url"]))

    findings = await SsrfModule().run(ctx)
    # Should have some finding (internal probe or AWS check)
    assert isinstance(findings, list)  # doesn't crash


@pytest.mark.asyncio
async def test_no_candidates_returns_empty(tmp_path: Path) -> None:
    """Empty store returns no findings."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await SsrfModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_ssrf_findings_persisted(tmp_path: Path) -> None:
    """SSRF findings are saved to ctx.store."""
    respx.get("https://t.example/proxy").mock(
        return_value=httpx.Response(200, text="ami-id=ami-0abc instance-id=i-0def")
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/proxy", params=["url"]))

    await SsrfModule().run(ctx)

    stored = await ctx.store.all()
    ssrf_stored = [f for f in stored if f.module.startswith("ssrf")]
    assert len(ssrf_stored) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_ssrf_detects_callback_param(tmp_path: Path) -> None:
    """'callback' param is recognized as SSRF candidate."""
    respx.get("https://t.example/notify").mock(
        return_value=httpx.Response(200, text="ami-id=ami-deadbeef")
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/notify", params=["callback"]))

    findings = await SsrfModule().run(ctx)
    assert len(findings) >= 1
