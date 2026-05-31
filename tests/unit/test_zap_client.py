"""Tests for ZapClient — all network mocked with respx."""
from __future__ import annotations

from pathlib import Path

import pytest
import respx
from httpx import Response

from pentora.proxy.zap import ZapClient

BASE = "http://127.0.0.1:8090"


@respx.mock
@pytest.mark.asyncio
async def test_is_alive_true() -> None:
    respx.get(f"{BASE}/JSON/core/view/version/").mock(
        return_value=Response(200, json={"version": "2.12.0"})
    )
    client = ZapClient(api_key="test-key")
    assert await client.is_alive() is True


@respx.mock
@pytest.mark.asyncio
async def test_is_alive_false_on_error() -> None:
    respx.get(f"{BASE}/JSON/core/view/version/").mock(side_effect=Exception("refused"))
    client = ZapClient(api_key="test-key")
    assert await client.is_alive() is False


@respx.mock
@pytest.mark.asyncio
async def test_add_to_scope() -> None:
    route = respx.get(f"{BASE}/JSON/context/action/includeInContext/").mock(
        return_value=Response(200, json={"Result": "OK"})
    )
    client = ZapClient(api_key="test-key")
    await client.add_to_scope(["https://example.com", "https://api.example.com"])
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_start_active_scan() -> None:
    respx.get(f"{BASE}/JSON/ascan/action/scan/").mock(
        return_value=Response(200, json={"scan": "7"})
    )
    client = ZapClient(api_key="test-key")
    scan_id = await client.start_active_scan(["https://example.com"])
    assert scan_id == "7"


@respx.mock
@pytest.mark.asyncio
async def test_start_active_scan_empty() -> None:
    client = ZapClient(api_key="test-key")
    result = await client.start_active_scan([])
    assert result == ""


@respx.mock
@pytest.mark.asyncio
async def test_wait_for_scan_completes() -> None:
    respx.get(f"{BASE}/JSON/ascan/view/status/").mock(
        return_value=Response(200, json={"status": "100"})
    )
    client = ZapClient(api_key="test-key")
    await client.wait_for_scan("7", poll_interval_s=0, timeout_s=10)


@respx.mock
@pytest.mark.asyncio
async def test_wait_for_scan_timeout() -> None:
    respx.get(f"{BASE}/JSON/ascan/view/status/").mock(
        return_value=Response(200, json={"status": "50"})
    )
    client = ZapClient(api_key="test-key")
    with pytest.raises(TimeoutError):
        await client.wait_for_scan("7", poll_interval_s=0, timeout_s=0)


@respx.mock
@pytest.mark.asyncio
async def test_get_findings() -> None:
    alerts = {
        "alerts": [
            {
                "alert": "SQL Injection",
                "url": "https://example.com/api",
                "method": "GET",
                "risk": "High",
                "evidence": "error in sql",
                "description": "SQL injection found",
                "solution": "Use parameterized queries",
            },
            {
                "alert": "X-Frame-Options Header Not Set",
                "url": "https://example.com/",
                "method": "GET",
                "risk": "Medium",
                "evidence": "",
                "description": "Missing header",
                "solution": "Add header",
            },
        ]
    }
    respx.get(f"{BASE}/JSON/core/view/alerts/").mock(return_value=Response(200, json=alerts))
    client = ZapClient(api_key="test-key")
    findings = await client.get_findings()
    assert len(findings) == 2
    assert findings[0].title == "SQL Injection"
    assert findings[0].source == "zap"
    assert findings[1].title == "X-Frame-Options Header Not Set"


@respx.mock
@pytest.mark.asyncio
async def test_export_xml(tmp_path: Path) -> None:
    xml_content = b"<report><site/></report>"
    respx.get(f"{BASE}/OTHER/core/other/xmlreport/").mock(
        return_value=Response(200, content=xml_content)
    )
    client = ZapClient(api_key="test-key")
    out = tmp_path / "zap-export.xml"
    await client.export_xml(str(out))
    assert out.read_bytes() == xml_content
