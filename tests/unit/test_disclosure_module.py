"""TDD tests for DisclosureModule."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Finding, Severity
from pentora.modules.disclosure import DisclosureModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _js_finding(url: str = "https://t.example/app.js") -> Finding:
    from pentora.finding import CVSS
    return Finding(
        module="discovery.endpoint",
        title="js-file",
        endpoint=url,
        method="GET",
        evidence="js",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra={"content_type": "application/javascript"},
    )


@pytest.mark.asyncio
@respx.mock
async def test_aws_key_in_js_raises_finding(tmp_path: Path) -> None:
    """AWS key found in JS body => HIGH finding."""
    respx.get("https://t.example/app.js").mock(
        return_value=httpx.Response(200, text="var key = 'AKIAIOSFODNN7EXAMPLE1234';")
    )
    respx.get("https://t.example/app.js.map").mock(return_value=httpx.Response(404))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_js_finding())

    findings = await DisclosureModule().run(ctx)
    assert any("AWS" in f.title or "secret" in f.title.lower() or "disclosure" in f.title.lower() for f in findings)
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_source_map_found_medium(tmp_path: Path) -> None:
    """Source map 200 => MEDIUM finding."""
    respx.get("https://t.example/app.js").mock(
        return_value=httpx.Response(200, text="var x = 1;")
    )
    respx.get("https://t.example/app.js.map").mock(
        return_value=httpx.Response(200, text='{"version":3,"sources":["app.ts"]}')
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_js_finding())

    findings = await DisclosureModule().run(ctx)
    map_findings = [f for f in findings if "map" in f.title.lower() or "source" in f.title.lower()]
    assert len(map_findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in map_findings)


@pytest.mark.asyncio
@respx.mock
async def test_no_findings_on_clean_js(tmp_path: Path) -> None:
    """Clean JS file with no secrets and no source map => no findings."""
    respx.get("https://t.example/app.js").mock(
        return_value=httpx.Response(200, text="console.log('hello world');")
    )
    respx.get("https://t.example/app.js.map").mock(return_value=httpx.Response(404))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(_js_finding())

    findings = await DisclosureModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_html_comment_with_password_flagged(tmp_path: Path) -> None:
    """HTML comment containing 'password' => MEDIUM finding."""
    from pentora.finding import CVSS
    html_finding = Finding(
        module="discovery.endpoint",
        title="html-page",
        endpoint="https://t.example/page.html",
        method="GET",
        evidence="html",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra={"content_type": "text/html"},
    )
    respx.get("https://t.example/page.html").mock(
        return_value=httpx.Response(
            200,
            text="<html><!-- TODO: password=admin123 remove before launch --><body></body></html>",
        )
    )
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store
    await ctx.store.add(html_finding)

    findings = await DisclosureModule().run(ctx)
    assert any("comment" in f.title.lower() or "html" in f.title.lower() or "disclosure" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_no_candidates_returns_empty(tmp_path: Path) -> None:
    """No stored findings => module returns empty list."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await DisclosureModule().run(ctx)
    assert findings == []
