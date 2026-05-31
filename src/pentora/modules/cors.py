"""CORS phase -- test for reflected origins, null origin, wildcard+credentials."""
from __future__ import annotations

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import gather_candidates

# CVSS vectors
_CORS_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # noqa: S105
_CORS_CRIT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # noqa: S105

_EVIL_ORIGIN = "https://evil.com"
_NULL_ORIGIN = "null"
_PREFIX_ORIGIN = "https://pure.app.evil.com"


class CorsModule(PhaseModule):
    name = "cors"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = await gather_candidates(ctx)
        if not candidates:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=False  # noqa: S501
        ) as client:
            # Deduplicate: one probe per unique URL
            seen: set[str] = set()
            for cand in candidates:
                url = cand.url
                if url in seen:
                    continue
                seen.add(url)
                findings += await _probe_cors(client, url)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings


async def _probe_cors(client: httpx.AsyncClient, url: str) -> list[Finding]:
    findings: list[Finding] = []

    for origin in [_EVIL_ORIGIN, _NULL_ORIGIN, _PREFIX_ORIGIN]:
        try:
            resp = await client.get(url, headers={"Origin": origin})
        except httpx.HTTPError:
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        # Wildcard + credentials = Critical
        if acao == "*" and acac == "true":
            findings.append(
                Finding(
                    module="cors.wildcard_credentials",
                    title="CORS: Wildcard + Credentials",
                    endpoint=url,
                    method="GET",
                    evidence=(
                        f"ACAO: {acao} | ACAC: {acac}"
                    ),
                    cvss=CVSS.from_vector(_CORS_CRIT_VECTOR),
                    description=(
                        "CORS allows wildcard origin with credentials — "
                        "any site can read authenticated responses."
                    ),
                    remediation="Never combine Access-Control-Allow-Origin: * with credentials.",
                )
            )
            break

        # Origin reflected back exactly (evil.com / null / prefix)
        if acao in (origin, _NULL_ORIGIN) and acao not in ("", "*"):
            findings.append(
                Finding(
                    module="cors.reflected_origin",
                    title="CORS: Reflected Origin",
                    endpoint=url,
                    method="GET",
                    evidence=f"Origin: {origin!r} reflected as ACAO: {acao!r}",
                    cvss=CVSS.from_vector(_CORS_HIGH_VECTOR),
                    description=(
                        f"Server reflects untrusted origin {origin!r} in "
                        "Access-Control-Allow-Origin."
                    ),
                    remediation="Validate Origin against an explicit allowlist.",
                )
            )

    return findings
