"""TDD tests for TransportModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.transport import TransportModule
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
async def test_missing_hsts_flagged(tmp_path: Path) -> None:
    """No Strict-Transport-Security header => MEDIUM finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(200, headers={}, text="<html></html>")
    )
    with patch(
        "pentora.modules.transport.TlsScanWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        findings = await TransportModule().run(_ctx(tmp_path))
    hsts = [f for f in findings if "hsts" in f.title.lower() or "transport" in f.title.lower()]
    assert len(hsts) >= 1
    assert any(f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH) for f in hsts)


@pytest.mark.asyncio
@respx.mock
async def test_hsts_present_no_hsts_finding(tmp_path: Path) -> None:
    """HSTS present => no HSTS finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
            text="<html></html>",
        )
    )
    with patch(
        "pentora.modules.transport.TlsScanWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        findings = await TransportModule().run(_ctx(tmp_path))
    hsts = [f for f in findings if "hsts" in f.title.lower()]
    assert hsts == []


@pytest.mark.asyncio
@respx.mock
async def test_mixed_content_flagged(tmp_path: Path) -> None:
    """HTML body with http:// resource link => MEDIUM finding."""
    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={"strict-transport-security": "max-age=31536000"},
            text='<html><img src="http://cdn.example.com/img.png"/></html>',
        )
    )
    with patch(
        "pentora.modules.transport.TlsScanWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        findings = await TransportModule().run(_ctx(tmp_path))
    mixed = [f for f in findings if "mixed" in f.title.lower()]
    assert len(mixed) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_weak_tls_from_testssl_flagged(tmp_path: Path) -> None:
    """TlsScanWrapper returning HIGH issue => finding emitted."""
    from pentora.wrappers.testssl import TlsIssue

    respx.get("https://t.example").mock(
        return_value=httpx.Response(
            200,
            headers={"strict-transport-security": "max-age=31536000"},
            text="<html></html>",
        )
    )
    fake_issue = TlsIssue(id="SSLv3", severity="HIGH", finding="SSLv3 enabled", cve="CVE-2014-3566")
    with patch(
        "pentora.modules.transport.TlsScanWrapper.run",
        new_callable=AsyncMock,
        return_value=[fake_issue],
    ):
        findings = await TransportModule().run(_ctx(tmp_path))
    tls = [f for f in findings if "tls" in f.title.lower() or "ssl" in f.title.lower()]
    assert len(tls) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in tls)
