"""Authorization phase — IDOR, BOLA diff, BFLA, and mass-assignment checks.

Requires both ``ctx.token_a`` and ``ctx.token_b``. With only one (or neither)
token there is nothing to compare across privilege boundaries, so the module
logs a warning and returns no findings.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from pentora.authz.diff_engine import compare_responses
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import gather_candidates

log = logging.getLogger(__name__)

# Trailing numeric path segment, e.g. ".../users/42".
_NUM_RE = re.compile(r"(.*/)(\d+)(/?)$")
# Trailing UUID path segment.
_UUID_RE = re.compile(
    r"(.*/)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/?)$"
)

# Statuses that indicate the resource was actually served to the requester.
_ACCESS_OK = frozenset({200, 206})

_IDOR_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
_BFLA_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
_MASS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"

DEFAULT_AUTHZ_CFG: dict[str, Any] = {
    "protected_path": "/me",
    "admin_paths": ["/admin", "/admin/users", "/admin/dashboard", "/api/admin"],
    "mass_fields": {"role": "admin", "isPremium": True, "id_verified": True},
    "uuid_b": "22222222-2222-2222-2222-222222222222",
    "numeric_offsets": [1, -1, 10, -10],
}


class AuthzModule(PhaseModule):
    name = "authz"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not (ctx.token_a and ctx.token_b):
            log.warning("authz_skipped", extra={"reason": "requires both --token-a and --token-b"})
            return []

        cfg = dict(DEFAULT_AUTHZ_CFG)
        cfg.update(ctx.config.profiles.get(ctx.profile_name, {}))
        base = ctx.target.rstrip("/")
        candidates = await gather_candidates(ctx)

        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            for cand in candidates:
                findings += await self.check_idor(client, cand.url, ctx.token_a, cfg)
                findings += await self.check_bola(
                    client, cand.url, ctx.token_a, ctx.token_b, cfg
                )
            findings += await self.check_bfla(client, base, ctx.token_a, cfg)
            findings += await self.check_mass_assignment(client, base, ctx.token_a, cfg)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def check_idor(
        self, client: httpx.AsyncClient, url: str, token_a: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        """Swap the resource ID under token A; a readable neighbor implies IDOR."""
        neighbors = self._neighbor_urls(url, cfg)
        if not neighbors:
            return []
        headers = {"Authorization": f"Bearer {token_a}"}
        try:
            own = await client.get(url, headers=headers)
        except httpx.HTTPError:
            return []
        if own.status_code not in _ACCESS_OK:
            return []
        findings: list[Finding] = []
        for neighbor in neighbors:
            try:
                resp = await client.get(neighbor, headers=headers)
            except httpx.HTTPError:
                continue
            if resp.status_code in _ACCESS_OK and resp.text != own.text:
                findings.append(
                    Finding(
                        module="authz.idor",
                        title="IDOR — neighboring resource accessible with own token",
                        endpoint=neighbor,
                        method="GET",
                        evidence=f"HTTP {resp.status_code} for {neighbor} using token A.",
                        cvss=CVSS.from_vector(_IDOR_VECTOR),
                        description="Object IDs are not scoped to the authenticated user.",
                        remediation="Enforce per-object ownership checks on every request.",
                    )
                )
                break
        return findings

    async def check_bola(
        self,
        client: httpx.AsyncClient,
        url: str,
        token_a: str,
        token_b: str,
        cfg: dict[str, Any],
    ) -> list[Finding]:
        """Fetch the same resource with both tokens; similar bodies imply BOLA."""
        try:
            resp_a = await client.get(url, headers={"Authorization": f"Bearer {token_a}"})
            resp_b = await client.get(url, headers={"Authorization": f"Bearer {token_b}"})
        except httpx.HTTPError:
            return []
        if resp_a.status_code not in _ACCESS_OK or resp_b.status_code not in _ACCESS_OK:
            return []
        diff = compare_responses(resp_a.text, resp_b.text)
        if not diff.similar:
            return []
        return [
            Finding(
                module="authz.bola",
                title="BOLA — token A receives token B's object data",
                endpoint=url,
                method="GET",
                evidence=f"Response bodies are {diff.ratio:.0%} similar across both tokens.",
                cvss=CVSS.from_vector(_IDOR_VECTOR),
                description="Broken object-level authorization leaks another user's data.",
                remediation="Validate object ownership against the authenticated principal.",
            )
        ]

    async def check_bfla(
        self, client: httpx.AsyncClient, base: str, token_a: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        """A low-privilege token reaching an /admin/* path implies BFLA."""
        headers = {"Authorization": f"Bearer {token_a}"}
        findings: list[Finding] = []
        for path in cfg["admin_paths"]:
            url = f"{base}{path}"
            try:
                resp = await client.get(url, headers=headers)
            except httpx.HTTPError:
                continue
            if resp.status_code in _ACCESS_OK:
                findings.append(
                    Finding(
                        module="authz.bfla",
                        title="BFLA — admin function accessible to low-privilege token",
                        endpoint=url,
                        method="GET",
                        evidence=f"HTTP {resp.status_code} for {url} using a non-admin token.",
                        cvss=CVSS.from_vector(_BFLA_VECTOR),
                        description="Administrative functionality lacks role enforcement.",
                        remediation="Enforce role-based access control on all admin endpoints.",
                    )
                )
        return findings

    async def check_mass_assignment(
        self, client: httpx.AsyncClient, base: str, token_a: str, cfg: dict[str, Any]
    ) -> list[Finding]:
        """PUT privileged fields to the profile; reflection on GET implies acceptance."""
        url = f"{base}{cfg['protected_path']}"
        headers = {"Authorization": f"Bearer {token_a}"}
        fields: dict[str, Any] = dict(cfg["mass_fields"])
        try:
            put = await client.put(url, headers=headers, json=fields)
            if put.status_code not in _ACCESS_OK and put.status_code != 204:
                return []
            after = await client.get(url, headers=headers)
        except httpx.HTTPError:
            return []
        reflected = self._reflected_fields(after, fields)
        if not reflected:
            return []
        return [
            Finding(
                module="authz.mass_assignment",
                title="Mass assignment — privileged fields accepted via profile update",
                endpoint=url,
                method="PUT",
                evidence=f"Fields reflected after update: {', '.join(sorted(reflected))}.",
                cvss=CVSS.from_vector(_MASS_VECTOR),
                description="The API binds client-supplied fields it should never accept.",
                remediation="Allow-list updatable fields; never bind role/permission attributes.",
            )
        ]

    @staticmethod
    def _neighbor_urls(url: str, cfg: dict[str, Any]) -> list[str]:
        num = _NUM_RE.match(url)
        if num:
            prefix, value, suffix = num.groups()
            base_id = int(value)
            urls = []
            for off in cfg["numeric_offsets"]:
                nid = base_id + int(off)
                if nid >= 0 and nid != base_id:
                    urls.append(f"{prefix}{nid}{suffix}")
            return urls
        uuid = _UUID_RE.match(url)
        if uuid:
            prefix, value, suffix = uuid.groups()
            other = str(cfg["uuid_b"])
            if other and other != value:
                return [f"{prefix}{other}{suffix}"]
        return []

    @staticmethod
    def _reflected_fields(resp: httpx.Response, fields: dict[str, Any]) -> set[str]:
        try:
            data = resp.json()
        except (ValueError, httpx.HTTPError):
            return set()
        if not isinstance(data, dict):
            return set()
        return {k for k, v in fields.items() if data.get(k) == v}
