"""TDD tests for UploadModule — extension-bypass + SVG-XSS."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.upload import UploadModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _upload_finding(endpoint: str) -> Finding:
    return Finding(
        module="discovery.endpoint",
        title="upload endpoint",
        endpoint=endpoint,
        method="POST",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra={"kind": "upload"},
    )


@pytest.mark.asyncio
@respx.mock
async def test_php_upload_accepted_is_critical(tmp_path: Path) -> None:
    """A 200 response to a .php file upload is a Critical RCE finding."""
    respx.post("https://t.example/upload").mock(return_value=httpx.Response(200, text="ok"))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_upload_finding("https://t.example/upload"))

    findings = await UploadModule().run(ctx)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1
    php_findings = [f for f in critical if "php" in f.title.lower() or "php" in f.evidence.lower()]
    assert len(php_findings) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_php_jpg_bypass_accepted_is_critical(tmp_path: Path) -> None:
    """Extension bypass (.php.jpg) accepted → Critical."""
    respx.post("https://t.example/upload").mock(return_value=httpx.Response(200, text="ok"))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_upload_finding("https://t.example/upload"))

    findings = await UploadModule().run(ctx)
    bypass = [f for f in findings if "bypass" in f.title.lower() or "bypass" in f.evidence.lower()]
    assert len(bypass) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_svg_xss_payload_accepted_is_high(tmp_path: Path) -> None:
    """SVG with XSS payload accepted → High."""
    respx.post("https://t.example/upload").mock(return_value=httpx.Response(200, text="ok"))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_upload_finding("https://t.example/upload"))

    findings = await UploadModule().run(ctx)
    svg_findings = [f for f in findings if "svg" in f.title.lower() or "svg" in f.evidence.lower()]
    assert len(svg_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in svg_findings)


@pytest.mark.asyncio
@respx.mock
async def test_upload_rejected_no_findings(tmp_path: Path) -> None:
    """All uploads rejected (400/403) → no findings."""
    respx.post("https://t.example/upload").mock(return_value=httpx.Response(400, text="bad file"))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_upload_finding("https://t.example/upload"))

    findings = await UploadModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_upload_endpoint_discovered_by_url_pattern(tmp_path: Path) -> None:
    """/avatar endpoint detected by URL pattern match, not kind annotation."""
    respx.post("https://t.example/api/avatar").mock(
        return_value=httpx.Response(200, text="uploaded")
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    # kind="url" (not "upload") but URL matches /avatar pattern
    await ctx.store.add(
        Finding(
            module="discovery.endpoint",
            title="t",
            endpoint="https://t.example/api/avatar",
            method="POST",
            evidence="e",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            extra={"kind": "url"},
        )
    )

    findings = await UploadModule().run(ctx)
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_no_upload_candidates_returns_empty(tmp_path: Path) -> None:
    """No upload endpoints → empty findings."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    # Add a non-upload finding
    await ctx.store.add(
        Finding(
            module="recon.subdomain",
            title="t",
            endpoint="https://t.example/",
            method="GET",
            evidence="e",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            extra={"kind": "url"},
        )
    )
    findings = await UploadModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_findings_persisted(tmp_path: Path) -> None:
    """Upload findings are saved to ctx.store."""
    import respx as rx

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_upload_finding("https://t.example/upload"))

    with rx.mock:
        rx.post("https://t.example/upload").mock(return_value=httpx.Response(200))
        await UploadModule().run(ctx)

    stored = await ctx.store.all()
    upload_findings = [f for f in stored if f.module.startswith("upload")]
    assert len(upload_findings) >= 1
