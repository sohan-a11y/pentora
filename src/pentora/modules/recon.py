"""Recon phase — subdomain enumeration + HTTP probing."""
from __future__ import annotations

from urllib.parse import urlparse

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.httpx_tool import HttpxWrapper
from pentora.wrappers.subfinder import SubfinderWrapper


class ReconModule(PhaseModule):
    name = "recon"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        log_dir = ctx.output_dir / "logs" / "tool-invocations"

        # 1. Extract root domain from target
        host = urlparse(ctx.target).hostname or ctx.target
        root = ".".join(host.split(".")[-2:])

        # 2. Subdomain enumeration
        subs = await SubfinderWrapper(log_dir=log_dir).run(root)

        # 3. HTTP probe
        live = await HttpxWrapper(log_dir=log_dir).run(subs)

        # 4. Emit one finding per live subdomain (informational)
        for r in live:
            tech = ", ".join(r.tech) or "unknown"
            f = Finding(
                module="recon.subdomain",
                title=f"Live subdomain discovered: {urlparse(r.url).hostname}",
                endpoint=r.url,
                method="GET",
                evidence=f"HTTP {r.status_code} — {r.title or '(no title)'} — tech: {tech}",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                description="Subdomain reachable over HTTP/HTTPS.",
                remediation="Inventory all live subdomains; decommission unused services.",
            )
            findings.append(f)
            if ctx.store:
                await ctx.store.add(f)

        return findings
