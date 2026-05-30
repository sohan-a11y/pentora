"""Discovery phase — content/param discovery + sensitive-path probes."""
from __future__ import annotations

import contextlib
from pathlib import Path

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.modules.discovery_probes import DiscoveryHit, probe_all
from pentora.wrappers.arjun import ArjunWrapper
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.ffuf import FfufWrapper
from pentora.wrappers.katana import KatanaWrapper

_WORDLIST = "wordlists/common-dirs.txt"

# Maps a probe "kind" to the finding metadata it produces.
# CVSS vectors per Phase 2 plan §5.2; severity is derived from the score.
_KIND_META: dict[str, tuple[str, str, str]] = {
    "env": (
        "discovery.env",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "Environment file publicly accessible",
    ),
    "vcs": (
        "discovery.vcs",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "Version control metadata publicly accessible",
    ),
    "swagger": (
        "discovery.swagger",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "API documentation publicly accessible",
    ),
    "graphql": (
        "discovery.graphql",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "GraphQL endpoint exposed",
    ),
}

_REMEDIATION = {
    "env": "Remove env files from the web root; rotate any leaked secrets immediately.",
    "vcs": "Block access to .git/.svn/.hg directories at the web server / CDN layer.",
    "swagger": "Restrict API documentation to authenticated internal users.",
    "graphql": "Disable introspection in production and enforce auth on the GraphQL endpoint.",
}


class DiscoveryModule(PhaseModule):
    name = "discovery"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        live_hosts = self._read_live_hosts(ctx)
        if not live_hosts:
            return []

        log_dir = ctx.output_dir / "logs" / "tool-invocations"
        findings: list[Finding] = []

        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            for host in live_hosts:
                await self._run_wrappers(host, log_dir)
                # probe sensitive paths regardless of wrapper availability
                hits = await probe_all(client, host)
                for hit in hits:
                    finding = self._hit_to_finding(hit)
                    if finding is None:
                        continue
                    findings.append(finding)
                    if ctx.store:
                        await ctx.store.add(finding)
        return findings

    @staticmethod
    def _read_live_hosts(ctx: ScanContext) -> list[str]:
        path = ctx.output_dir / "recon" / "live-hosts.txt"
        if not path.exists():
            return []
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

    @staticmethod
    async def _run_wrappers(host: str, log_dir: Path) -> None:
        """Best-effort content/param discovery; missing tools are skipped silently."""
        with contextlib.suppress(ToolNotInstalled):
            await FfufWrapper(log_dir=log_dir).run(f"{host.rstrip('/')}/FUZZ", _WORDLIST)
        with contextlib.suppress(ToolNotInstalled):
            await ArjunWrapper(log_dir=log_dir).run(host)
        with contextlib.suppress(ToolNotInstalled):
            await KatanaWrapper(log_dir=log_dir).run(host)

    @staticmethod
    def _hit_to_finding(hit: DiscoveryHit) -> Finding | None:
        meta = _KIND_META.get(hit.kind)
        if meta is None:
            return None
        module, vector, title = meta
        return Finding(
            module=module,
            title=title,
            endpoint=hit.url,
            method="GET",
            evidence=hit.evidence,
            cvss=CVSS.from_vector(vector),
            description=f"Discovery probe flagged {hit.kind} exposure at {hit.url}.",
            remediation=_REMEDIATION.get(hit.kind, ""),
        )
