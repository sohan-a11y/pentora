"""Webhook notifications — Discord, Slack, Telegram."""
from __future__ import annotations

import httpx

from pentora.finding import Finding


async def notify(webhook_spec: str, message: str) -> None:
    """Send message to webhook.

    spec format: ''discord:URL'' | ''slack:URL'' | ''telegram:TOKEN:CHATID''
    """
    kind, _, rest = webhook_spec.partition(":")
    if kind == "discord":
        async with httpx.AsyncClient() as c:
            await c.post(rest, json={"content": message}, timeout=10.0)
    elif kind == "slack":
        async with httpx.AsyncClient() as c:
            await c.post(rest, json={"text": message}, timeout=10.0)
    elif kind == "telegram":
        # rest = TOKEN:CHATID
        token, _, chat_id = rest.rpartition(":")
        async with httpx.AsyncClient() as c:
            await c.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": message},
                timeout=10.0,
            )


async def notify_finding(webhook_spec: str, finding: Finding) -> None:
    """Send a notification about a single finding."""
    msg = (
        f"[{finding.severity.value.upper()}] {finding.title}\n"
        f"Endpoint: {finding.endpoint}\n"
        f"Evidence: {finding.evidence[:200]}"
    )
    await notify(webhook_spec, msg)


async def notify_scan_complete(
    webhook_spec: str, target: str, total: int, critical: int, high: int
) -> None:
    """Send a scan-complete summary notification."""
    msg = (
        f"Pentora scan complete: {target}\n"
        f"Total: {total} findings | Critical: {critical} | High: {high}"
    )
    await notify(webhook_spec, msg)
