"""Auth phase — rate-limit, enumeration, OTP, JWT, reset, session, cookie checks."""
from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from pentora.auth.otp_brute import brute_otp
from pentora.auth.timing_oracle import compare_timings, measure
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.jwt_tool import JwtToolWrapper

# Matches a 3-part JWT (header.payload.signature) with base64url segments.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

_JWT_MODES = ("alg-none", "brute-secret", "kid-injection")

# Default auth-testing configuration; overridable per-profile via ctx.config.profiles.
DEFAULT_AUTH_CFG: dict[str, Any] = {
    "login_path": "/login",
    "logout_path": "/logout",
    "forgot_path": "/forgot-password",
    "protected_path": "/me",
    "otp_path": "/verify-otp",
    "otp_field": "otp",
    "otp_length": 6,
    "otp_limit": None,
    "username_field": "email",
    "password_field": "password",
    "existing_user": "existing@test.com",
    "nonexistent_user": "nonexistent@x.y.z.invalid",
    "otp_endpoint_discovered": False,
    "allow_brute": False,
    "rate_limit_attempts": 20,
    "enumeration_samples": 3,
    "enumeration_threshold_ms": 200.0,
}


class AuthModule(PhaseModule):
    name = "auth"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        cfg = dict(DEFAULT_AUTH_CFG)
        cfg.update(ctx.config.profiles.get(ctx.profile_name, {}))
        base = ctx.target.rstrip("/")
        log_dir = ctx.output_dir / "logs" / "tool-invocations"

        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            findings += await self.check_rate_limit(client, base, cfg)
            findings += await self.check_enumeration(client, base, cfg)
            findings += await self.check_otp(client, base, cfg)
            findings += await self.check_jwt(log_dir, ctx.token_a, cfg)
            findings += await self.check_password_reset(client, base, cfg)
            findings += await self.check_session(client, base, ctx.token_a, cfg)
            findings += await self.check_cookie_flags(client, base, cfg)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def check_rate_limit(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        url = f"{base}{cfg['login_path']}"
        attempts = int(cfg["rate_limit_attempts"])
        payload = {cfg["username_field"]: cfg["existing_user"], cfg["password_field"]: "wrong"}
        throttled = 0
        for i in range(attempts):
            try:
                resp = await client.post(url, json=payload)
            except httpx.HTTPError:
                return []
            # If the endpoint doesn't exist or rejects POST, it's not a login — skip.
            if i == 0 and resp.status_code in (404, 405):
                return []
            if resp.status_code == 429 or resp.status_code == 503 or "retry-after" in resp.headers:
                throttled += 1
        if throttled == 0:
            return [
                Finding(
                    module="auth.rate_limit",
                    title="No rate limit on login endpoint",
                    endpoint=url,
                    method="POST",
                    evidence=f"{attempts} failed logins returned no 429/503/Retry-After.",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
                    description="The login endpoint does not throttle repeated failures.",
                    remediation="Enforce per-account and per-IP rate limiting with backoff.",
                )
            ]
        return []

    async def check_enumeration(
        self,
        client: httpx.AsyncClient,
        base: str,
        cfg: dict[str, Any],
        clock: Callable[[], float] = time.monotonic,
    ) -> list[Finding]:
        url = f"{base}{cfg['login_path']}"
        samples = int(cfg["enumeration_samples"])
        threshold = float(cfg["enumeration_threshold_ms"])

        # Skip if the login endpoint doesn't exist (timing comparison would be noise).
        try:
            probe = await client.post(
                url, json={cfg["username_field"]: cfg["existing_user"], cfg["password_field"]: "x"}
            )
        except httpx.HTTPError:
            return []
        if probe.status_code in (404, 405):
            return []

        async def send(user: str) -> None:
            await client.post(
                url, json={cfg["username_field"]: user, cfg["password_field"]: "wrong"}
            )

        try:
            existing = await measure(lambda: send(cfg["existing_user"]), samples, clock=clock)
            missing = await measure(lambda: send(cfg["nonexistent_user"]), samples, clock=clock)
        except httpx.HTTPError:
            return []

        comparison = compare_timings(existing, missing, threshold_ms=threshold)
        if comparison.enumerable:
            return [
                Finding(
                    module="auth.enumeration",
                    title="Username enumeration via response timing",
                    endpoint=url,
                    method="POST",
                    evidence=(
                        f"Median timing delta {comparison.delta_ms:.0f}ms "
                        f"(existing={comparison.median_a_ms:.0f}ms, "
                        f"missing={comparison.median_b_ms:.0f}ms)."
                    ),
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                    description="Response time differs for valid vs invalid usernames.",
                    remediation="Normalize response timing and messages regardless of account.",
                )
            ]
        return []

    async def check_otp(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        if not (cfg["allow_brute"] and cfg["otp_endpoint_discovered"]):
            return []
        url = f"{base}{cfg['otp_path']}"

        async def is_success(resp: httpx.Response) -> bool:
            return resp.status_code == 200

        result = await brute_otp(
            client,
            url,
            length=int(cfg["otp_length"]),
            field=str(cfg["otp_field"]),
            success=is_success,
            limit=cfg["otp_limit"],
            throttle_s=0.0,
        )
        if result.found:
            return [
                Finding(
                    module="auth.otp",
                    title="Weak OTP brute-forceable",
                    endpoint=url,
                    method="POST",
                    evidence=f"OTP {result.code} accepted after {result.attempts} attempts.",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                    description="The OTP endpoint accepts brute-forced codes without lockout.",
                    remediation="Add attempt limits, exponential backoff, and OTP expiry.",
                )
            ]
        return []

    async def check_jwt(
        self, log_dir: Path, token: str | None, cfg: dict[str, Any]
    ) -> list[Finding]:
        jwt = self._extract_jwt(token)
        if jwt is None:
            return []
        findings: list[Finding] = []
        wrapper = JwtToolWrapper(log_dir=log_dir)
        for mode in _JWT_MODES:
            try:
                results = await wrapper.run(jwt, mode)
            except ToolNotInstalled:
                break
            for r in results:
                if r.vulnerable:
                    findings.append(
                        Finding(
                            module="auth.jwt",
                            title=f"JWT attack succeeded: {r.attack}",
                            endpoint="(token)",
                            method="N/A",
                            evidence=r.evidence,
                            cvss=CVSS.from_vector(
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                            ),
                            description=f"jwt_tool {r.attack} produced a valid forged token.",
                            remediation="Pin signing alg, use strong secrets, validate kid.",
                        )
                    )
        return findings

    async def check_password_reset(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        url = f"{base}{cfg['forgot_path']}"
        payload = {cfg["username_field"]: cfg["existing_user"]}
        try:
            r1 = await client.post(url, json=payload)
            # If the endpoint doesn't exist or rejects POST, there's nothing to test.
            if r1.status_code in (404, 405):
                return []
            r2 = await client.post(url, json=payload)
        except httpx.HTTPError:
            return []
        t1 = self._extract_token(r1)
        t2 = self._extract_token(r2)
        if t1 and t2 and t1 == t2:
            return [
                Finding(
                    module="auth.password_reset",
                    title="Password reset issues a static/reused token",
                    endpoint=url,
                    method="POST",
                    evidence="Two reset requests returned the same token.",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                    description="Reset tokens are predictable or reused across requests.",
                    remediation="Generate single-use, high-entropy, short-lived reset tokens.",
                )
            ]
        return []

    async def check_session(
        self, client: httpx.AsyncClient, base: str, token: str | None, cfg: dict[str, Any]
    ) -> list[Finding]:
        if not token:
            return []
        protected = f"{base}{cfg['protected_path']}"
        logout = f"{base}{cfg['logout_path']}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            before = await client.get(protected, headers=headers)
            if before.status_code != 200:
                return []
            await client.post(logout, headers=headers)
            after = await client.get(protected, headers=headers)
        except httpx.HTTPError:
            return []
        if after.status_code == 200:
            return [
                Finding(
                    module="auth.session",
                    title="Logout does not invalidate token server-side",
                    endpoint=protected,
                    method="GET",
                    evidence="Token still authorized after logout.",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                    description="Server keeps sessions/tokens valid after logout.",
                    remediation="Invalidate sessions/tokens server-side on logout.",
                )
            ]
        return []

    async def check_cookie_flags(
        self, client: httpx.AsyncClient, base: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        try:
            resp = await client.get(f"{base}/")
        except httpx.HTTPError:
            return []
        set_cookie = resp.headers.get("set-cookie")
        if not set_cookie:
            return []
        lower = set_cookie.lower()
        findings: list[Finding] = []
        checks = [
            ("Secure", "secure", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            ("HttpOnly", "httponly", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            ("SameSite", "samesite", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        ]
        for flag, needle, vector in checks:
            if needle not in lower:
                findings.append(
                    Finding(
                        module="auth.cookie_flags",
                        title=f"Cookie missing {flag} attribute",
                        endpoint=f"{base}/",
                        method="GET",
                        evidence=f"Set-Cookie: {set_cookie}",
                        cvss=CVSS.from_vector(vector),
                        description=f"A response cookie is set without the {flag} attribute.",
                        remediation=f"Add the {flag} attribute to all session cookies.",
                    )
                )
        return findings

    @staticmethod
    def _extract_jwt(token: str | None) -> str | None:
        if not token:
            return None
        match = _JWT_RE.search(token)
        return match.group(0) if match else None

    @staticmethod
    def _extract_token(resp: httpx.Response) -> str | None:
        try:
            data = resp.json()
        except (ValueError, httpx.HTTPError):
            return None
        if isinstance(data, dict):
            value = data.get("token")
            if isinstance(value, str):
                return value
        return None
