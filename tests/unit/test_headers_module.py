"""TDD tests for HeadersModule."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.headers import HeadersModule
from pentora.scope import Scope


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


@pytest.mark.asyncio
@respx.mock
async def test_unsafe_inline_csp_flagged(tmp_path: Path) -> None:
    """CSP with unsafe-inline => HIGH finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={
                "content-security-policy": "script-src 'self' 'unsafe-inline'",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
            },
            text="<html></html>",
        )
    )
    findings = await HeadersModule().run(_ctx(tmp_path))
    csp_findings = [f for f in findings if "csp" in f.title.lower() or "unsafe" in f.title.lower()]
    assert len(csp_findings) >= 1
    assert any(f.severity in (Severity.MEDIUM, Severity.HIGH) for f in csp_findings)


@pytest.mark.asyncio
@respx.mock
async def test_missing_x_content_type_flagged(tmp_path: Path) -> None:
    """Missing X-Content-Type-Options => finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
            },
            text="<html></html>",
        )
    )
    findings = await HeadersModule().run(_ctx(tmp_path))
    xcto = [f for f in findings if "content-type" in f.title.lower() or "x-content" in f.title.lower()]
    assert len(xcto) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_fully_configured_headers_minimal_findings(tmp_path: Path) -> None:
    """All important headers present and strict CSP => no HIGH findings."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": (
                    "default-src 'self'; "
                    "script-src 'self' 'nonce-abc'; "
                    "object-src 'none'; "
                    "base-uri 'self'; "
                    "frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
            text="<html></html>",
        )
    )
    findings = await HeadersModule().run(_ctx(tmp_path))
    high_findings = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert high_findings == []


@pytest.mark.asyncio
@respx.mock
async def test_no_csp_header_flagged(tmp_path: Path) -> None:
    """No CSP header at all => finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            },
            text="<html></html>",
        )
    )
    findings = await HeadersModule().run(_ctx(tmp_path))
    csp = [f for f in findings if "csp" in f.title.lower() or "content-security" in f.title.lower()]
    assert len(csp) >= 1
