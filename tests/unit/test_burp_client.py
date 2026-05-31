"""Tests for BurpClient — all network mocked with respx."""
from __future__ import annotations

from pathlib import Path

import pytest
import respx
from httpx import Response

from pentora.proxy.burp import BurpClient


BASE = "http://127.0.0.1:1337"


@respx.mock
@pytest.mark.asyncio
async def test_is_alive_true() -> None:
    respx.get(f"{BASE}/burp/versions").mock(return_value=Response(200, json={"burpVersion": "2022.9.5"}))
    client = BurpClient()
    assert await client.is_alive() is True


@respx.mock
@pytest.mark.asyncio
async def test_is_alive_false_on_error() -> None:
    respx.get(f"{BASE}/burp/versions").mock(side_effect=Exception("connection refused"))
    client = BurpClient()
    assert await client.is_alive() is False


@respx.mock
@pytest.mark.asyncio
async def test_add_to_scope() -> None:
    route = respx.put(f"{BASE}/burp/target/scope").mock(return_value=Response(200))
    client = BurpClient()
    await client.add_to_scope(["https://example.com", "https://api.example.com"])
    assert route.called
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_start_active_scan() -> None:
    respx.post(f"{BASE}/burp/scanner/scans/active").mock(
        return_value=Response(200, json={"id": "scan-42"})
    )
    client = BurpClient()
    scan_id = await client.start_active_scan(["https://example.com"])
    assert scan_id == "scan-42"


@respx.mock
@pytest.mark.asyncio
async def test_start_active_scan_empty_urls() -> None:
    client = BurpClient()
    result = await client.start_active_scan([])
    assert result == ""


@respx.mock
@pytest.mark.asyncio
async def test_wait_for_scan_completes() -> None:
    respx.get(f"{BASE}/burp/scanner/status").mock(
        return_value=Response(200, json={"scanPercentage": 100})
    )
    client = BurpClient()
    await client.wait_for_scan("scan-42", poll_interval_s=0, timeout_s=10)


@respx.mock
@pytest.mark.asyncio
async def test_wait_for_scan_timeout() -> None:
    respx.get(f"{BASE}/burp/scanner/status").mock(
        return_value=Response(200, json={"scanPercentage": 50})
    )
    client = BurpClient()
    with pytest.raises(TimeoutError):
        await client.wait_for_scan("scan-42", poll_interval_s=0, timeout_s=0)


@respx.mock
@pytest.mark.asyncio
async def test_get_findings() -> None:
    issues = [
        {
            "issueName": "SQL Injection",
            "url": "https://example.com/api",
            "severity": "High",
            "issueDetail": "Parameter id is injectable",
            "issueBackground": "SQL injection allows...",
            "remediationBackground": "Use parameterized queries",
        },
        {
            "issueName": "XSS",
            "url": "https://example.com/search",
            "severity": "Medium",
            "issueDetail": "Reflected XSS in q",
            "issueBackground": "XSS allows...",
            "remediationBackground": "Escape output",
        },
    ]
    respx.get(f"{BASE}/burp/scanner/issues").mock(return_value=Response(200, json=issues))
    client = BurpClient()
    findings = await client.get_findings()
    assert len(findings) == 2
    assert findings[0].title == "SQL Injection"
    assert findings[0].source == "burp"
    assert findings[1].title == "XSS"
    from pentora.finding import Severity
    # "High" Burp severity uses C:H/I:H/A:N vector → CVSS 9.1 → CRITICAL in Pentora
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert findings[1].severity == Severity.MEDIUM


@respx.mock
@pytest.mark.asyncio
async def test_export_xml(tmp_path: Path) -> None:
    xml_content = b"<report><issues/></report>"
    respx.get(f"{BASE}/burp/report").mock(return_value=Response(200, content=xml_content))
    client = BurpClient()
    out = tmp_path / "burp-export.xml"
    await client.export_xml(str(out))
    assert out.read_bytes() == xml_content
