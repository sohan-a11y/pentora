"""RateLimit phase -- burst-test auth endpoints for missing throttling."""
from __future__ import annotations

import asyncio
import re

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule

_RATE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # noqa: S105

# Endpoints suggesting authentication/sensitive actions
_AUTH_RE = re.compile(
    r"/login|/signin|/auth|/token|/password|/reset|/otp|/verify|/2fa|/mfa",
    re.I,
)

_BURST_COUNT = 30
_THROTTLE_STATUSES = {429, 503}
_MIN_THROTTLED = 3  # Need at least this many throttled to consider it protected


def _is_auth_endpoint(url: str) -> bool:
    return bool(_AUTH_RE.search(url))


class RateLimitModule(PhaseModule):
    name = "ratelimit"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.store:
            return []
        all_findings = await ctx.store.all()

        # Collect unique auth-like endpoints
        seen: set[str] = set()
        auth_endpoints: list[tuple[str, str]] = []
        for f in all_findings:
            key = (f.endpoint, f.method)
            if key in seen:
                continue
            seen.add(key)
            if _is_auth_endpoint(f.endpoint) or str(f.extra.get("kind", "")).lower() in (
                "login", "auth", "otp", "password"
            ):
                auth_endpoints.append((f.endpoint, f.method))

        if not auth_endpoints:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10.0, verify=False  # noqa: S501
        ) as client:
            for url, method in auth_endpoints:
                findings += await self._burst_test(client, url, method, ctx)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def _burst_test(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        ctx: ScanContext,
    ) -> list[Finding]:
        # Respect global rate_limit ceiling (requests per second)
        rate_limit = ctx.config.rate_limit

        async def _send() -> httpx.Response:
            try:
                if method.upper() == "POST":
                    return await client.post(url, data={"username": "test", "password": "test"})
                return await client.get(url)
            except httpx.HTTPError:
                return httpx.Response(0)

        # Fire up to _BURST_COUNT requests in parallel (bounded by rate_limit)
        count = min(_BURST_COUNT, rate_limit * 5)
        responses = await asyncio.gather(*[_send() for _ in range(count)])

        throttled = sum(
            1
            for r in responses
            if r.status_code in _THROTTLE_STATUSES or "retry-after" in r.headers
        )

        if throttled < _MIN_THROTTLED:
            return [
                Finding(
                    module="ratelimit.auth",
                    title="Missing Rate Limiting on Auth Endpoint",
                    endpoint=url,
                    method=method,
                    evidence=(
                        f"{count} requests fired; only {throttled} were throttled "
                        f"(threshold: {_MIN_THROTTLED})"
                    ),
                    cvss=CVSS.from_vector(_RATE_VECTOR),
                    description=(
                        "The endpoint does not enforce rate limiting, "
                        "enabling credential stuffing and brute-force attacks."
                    ),
                    remediation=(
                        "Implement rate limiting (e.g., 5 req/min per IP) and "
                        "exponential back-off on auth endpoints."
                    ),
                )
            ]
        return []
