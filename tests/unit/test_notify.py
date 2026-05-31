"""Tests for webhook notification system."""
from __future__ import annotations

import httpx
import pytest
import respx

from pentora.finding import CVSS, Finding
from pentora.notify import notify, notify_finding, notify_scan_complete


@respx.mock
@pytest.mark.asyncio
async def test_notify_discord() -> None:
    url = "https://discord.com/api/webhooks/test/token"
    route = respx.post(url).mock(return_value=httpx.Response(204))
    await notify(f"discord:{url}", "test message")
    assert route.called
    assert route.calls[0].request.content  # body was sent


@respx.mock
@pytest.mark.asyncio
async def test_notify_slack() -> None:
    url = "https://hooks.slack.com/services/T00/B00/XXX"
    route = respx.post(url).mock(return_value=httpx.Response(200))
    await notify(f"slack:{url}", "test message")
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_notify_telegram() -> None:
    token = "123456:ABCDEF"
    chat_id = "987654321"
    route = respx.post(
        f"https://api.telegram.org/bot{token}/sendMessage"
    ).mock(return_value=httpx.Response(200))
    await notify(f"telegram:{token}:{chat_id}", "test message")
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_notify_finding() -> None:
    url = "https://discord.com/api/webhooks/test/token"
    route = respx.post(url).mock(return_value=httpx.Response(204))
    finding = Finding(
        module="sqli",
        title="SQL Injection",
        endpoint="https://target.com/api",
        method="POST",
        evidence="DB error",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    await notify_finding(f"discord:{url}", finding)
    assert route.called
    body = route.calls[0].request.content.decode()
    assert "SQL Injection" in body
    assert "HIGH" in body.upper() or "CRITICAL" in body.upper()


@respx.mock
@pytest.mark.asyncio
async def test_notify_scan_complete() -> None:
    url = "https://hooks.slack.com/services/T00/B00/XXX"
    route = respx.post(url).mock(return_value=httpx.Response(200))
    await notify_scan_complete(f"slack:{url}", "https://target.com", total=5, critical=2, high=1)
    assert route.called
    body = route.calls[0].request.content.decode()
    assert "target.com" in body
    assert "5" in body
