"""Takeover phase -- check subdomains for dangling DNS pointing to unclaimed services."""
from __future__ import annotations

import httpx

from pentora.context import ScanContext
from pentora.data.takeover_fingerprints import TAKEOVER_FINGERPRINTS
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule

_TAKEOVER_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"  # noqa: S105


class TakeoverModule(PhaseModule):
    name = "takeover"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.store:
            return []
        all_findings = await ctx.store.all()
        if not all_findings:
            return []

        # Collect unique subdomain URLs from stored findings
        seen: set[str] = set()
        urls: list[str] = []
        for f in all_findings:
            if f.endpoint and f.endpoint not in seen:
                seen.add(f.endpoint)
                urls.append(f.endpoint)

        if not urls:
            return []

        results: list[Finding] = []
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=False  # noqa: S501
        ) as client:
            for url in urls:
                results += await _probe_takeover(client, url)

        for f in results:
            if ctx.store:
                await ctx.store.add(f)
        return results


async def _probe_takeover(client: httpx.AsyncClient, url: str) -> list[Finding]:
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return []

    body = resp.text
    for fp in TAKEOVER_FINGERPRINTS:
        if fp["body_contains"] in body:
            return [
                Finding(
                    module="takeover.subdomain",
                    title=f"Subdomain Takeover: {fp['service']}",
                    endpoint=url,
                    method="GET",
                    evidence=(
                        f"Fingerprint matched: {fp['body_contains']!r} in response body"
                    ),
                    cvss=CVSS.from_vector(_TAKEOVER_VECTOR),
                    description=(
                        f"The subdomain {url!r} resolves but the {fp['service']} "
                        "service is unclaimed. An attacker can register it."
                    ),
                    remediation=(
                        "Remove the dangling DNS record or claim the service before "
                        "an attacker does."
                    ),
                )
            ]
    return []
