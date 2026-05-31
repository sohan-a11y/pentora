"""Logic phase -- business logic flaws: race conditions, overflow, premium bypass, coupon reuse."""
from __future__ import annotations

import asyncio
import re

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import Candidate, gather_candidates

# CVSS vectors
_RACE_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
_NEG_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
_OVERFLOW_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
_PREMIUM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
_COUPON_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
_DM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
_LOC_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"

# Endpoint patterns
_CART_RE = re.compile(r"/cart|/order|/checkout|/purchase|/buy", re.I)
_PROFILE_RE = re.compile(r"/profile|/account|/user|/me|/settings", re.I)
_ACTION_RE = re.compile(r"/pay|/transfer|/redeem|/apply|/vote|/like", re.I)
_MSG_RE = re.compile(r"/message|/msg|/chat|/conversation", re.I)

# Fields to test for premium bypass
_PREMIUM_FIELDS = {"isPremium": True, "subscription": "pro", "tier": "premium", "is_verified": True}


def _is_cart_endpoint(url: str) -> bool:
    return bool(_CART_RE.search(url))


def _is_profile_endpoint(url: str) -> bool:
    return bool(_PROFILE_RE.search(url))


def _is_action_endpoint(url: str) -> bool:
    return bool(_ACTION_RE.search(url))


def _is_message_endpoint(url: str) -> bool:
    return bool(_MSG_RE.search(url))


class LogicModule(PhaseModule):
    name = "logic"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = await gather_candidates(ctx)
        if not candidates:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            for cand in candidates:
                # POST endpoints: negative values, overflow, coupon reuse
                if cand.method == "POST":
                    findings += await self._check_negative_quantity(client, cand)
                    findings += await self._check_integer_overflow(client, cand)
                    findings += await self._check_coupon_reuse(client, cand)
                    if _is_action_endpoint(cand.url):
                        findings += await self._check_race_condition(client, cand)

                # PUT/PATCH: premium bypass
                if cand.method in ("PUT", "PATCH") and _is_profile_endpoint(cand.url):
                    findings += await self._check_premium_bypass(client, cand)

                # Dating profile-specific checks
                if ctx.profile_name == "dating":
                    if cand.method == "POST" and _is_message_endpoint(cand.url):
                        findings += await self._check_dating_direct_message(client, cand)
                    if cand.method in ("PUT", "PATCH") and _is_profile_endpoint(cand.url):
                        findings += await self._check_location_spoof(client, cand)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def _check_negative_quantity(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"quantity": -1, "amount": -100, "price": -50}
        try:
            resp = await client.post(cand.url, json=payload)
            if resp.status_code == 200:
                return [
                    Finding(
                        module="logic.negative_quantity",
                        title="Negative quantity accepted",
                        endpoint=cand.url,
                        method="POST",
                        evidence=f"POST {payload} returned HTTP {resp.status_code}.",
                        cvss=CVSS.from_vector(_NEG_VECTOR),
                        description="Negative values accepted in quantity/amount fields.",
                        remediation="Validate quantity > 0 server-side before processing.",
                    )
                ]
        except httpx.HTTPError:
            pass
        return []

    async def _check_integer_overflow(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"quantity": 2147483647, "amount": 9999999999999999}
        try:
            resp = await client.post(cand.url, json=payload)
            if resp.status_code == 200:
                return [
                    Finding(
                        module="logic.integer_overflow",
                        title="Integer overflow value accepted",
                        endpoint=cand.url,
                        method="POST",
                        evidence=f"POST with extreme values returned HTTP {resp.status_code}.",
                        cvss=CVSS.from_vector(_OVERFLOW_VECTOR),
                        description="Extreme integer values accepted without rejection.",
                        remediation="Enforce maximum value constraints server-side.",
                    )
                ]
        except httpx.HTTPError:
            pass
        return []

    async def _check_premium_bypass(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        try:
            put = await client.put(cand.url, json=_PREMIUM_FIELDS)
            if put.status_code not in (200, 204):
                return []
            get = await client.get(cand.url)
            ct = get.headers.get("content-type", "")
            body = get.json() if "json" in ct else {}
        except (httpx.HTTPError, ValueError):
            return []

        if not isinstance(body, dict):
            return []

        reflected = {k for k, v in _PREMIUM_FIELDS.items() if body.get(k) == v}
        if reflected:
            return [
                Finding(
                    module="logic.premium_bypass",
                    title="Premium/subscription bypass via field injection",
                    endpoint=cand.url,
                    method="PUT",
                    evidence=f"Fields {sorted(reflected)} reflected after PUT.",
                    cvss=CVSS.from_vector(_PREMIUM_VECTOR),
                    description="Privileged subscription fields accepted and reflected via profile update.",
                    remediation="Deny-list privilege-elevation fields from client-supplied updates.",
                )
            ]
        return []

    async def _check_coupon_reuse(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"coupon": "TESTCOUPON10"}
        successes = 0
        for _ in range(3):
            try:
                resp = await client.post(cand.url, json=payload)
                if resp.status_code == 200:
                    successes += 1
                else:
                    break
            except httpx.HTTPError:
                break
        if successes >= 3:
            return [
                Finding(
                    module="logic.coupon_reuse",
                    title="Coupon code can be reused multiple times",
                    endpoint=cand.url,
                    method="POST",
                    evidence=f"Same coupon code accepted {successes} times consecutively.",
                    cvss=CVSS.from_vector(_COUPON_VECTOR),
                    description="Coupon codes are not invalidated after first use.",
                    remediation="Mark coupons as used on first redemption; enforce single-use.",
                )
            ]
        return []

    async def _check_race_condition(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"action": "execute"}
        try:
            responses = await asyncio.gather(
                *[client.post(cand.url, json=payload) for _ in range(25)],
                return_exceptions=True,
            )
        except httpx.HTTPError:
            return []

        status_codes = [
            r.status_code
            for r in responses
            if isinstance(r, httpx.Response)
        ]
        if not status_codes:
            return []

        unique_statuses = set(status_codes)
        if len(unique_statuses) > 1 and max(status_codes.count(s) for s in unique_statuses if s != 200) > 3:
            return [
                Finding(
                    module="logic.race_condition",
                    title="Race condition on action endpoint",
                    endpoint=cand.url,
                    method="POST",
                    evidence=f"25 concurrent requests returned {unique_statuses} status codes.",
                    cvss=CVSS.from_vector(_RACE_VECTOR),
                    description="Concurrent requests produce inconsistent status codes.",
                    remediation="Use database transactions and optimistic locking for critical actions.",
                )
            ]
        return []

    async def _check_dating_direct_message(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"recipient_id": 99999999, "message": "test"}
        try:
            resp = await client.post(cand.url, json=payload)
        except httpx.HTTPError:
            return []
        if resp.status_code == 200:
            return [
                Finding(
                    module="logic.dating.direct_message",
                    title="Direct message sent to non-matched user",
                    endpoint=cand.url,
                    method="POST",
                    evidence=f"POST to non-matched recipient_id returned HTTP {resp.status_code}.",
                    cvss=CVSS.from_vector(_DM_VECTOR),
                    description="Users can send messages to arbitrary recipients without matching.",
                    remediation="Enforce match requirement before allowing direct messages.",
                )
            ]
        return []

    async def _check_location_spoof(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        payload = {"location": {"lat": 0, "lng": 0}}
        try:
            resp = await client.put(cand.url, json=payload)
        except httpx.HTTPError:
            return []
        if resp.status_code in (200, 204):
            return [
                Finding(
                    module="logic.dating.location_spoof",
                    title="Location spoofing accepted",
                    endpoint=cand.url,
                    method="PUT",
                    evidence=f"PUT location 0,0 returned HTTP {resp.status_code}.",
                    cvss=CVSS.from_vector(_LOC_VECTOR),
                    description="Arbitrary GPS coordinates accepted without validation.",
                    remediation="Validate location coordinates against known valid ranges.",
                )
            ]
        return []

