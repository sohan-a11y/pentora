"""Recon phase — subdomain enumeration + HTTP probing.

Degrades gracefully: when the external CLI tools (subfinder, httpx) are not
installed, falls back to a native Python probe of the primary target so the
scan still produces useful output and downstream phases get live hosts.
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.httpx_tool import HttpxResult, HttpxWrapper
from pentora.wrappers.subfinder import SubfinderWrapper


class ReconModule(PhaseModule):
    name = "recon"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        log_dir = ctx.output_dir / "logs" / "tool-invocations"

        # 1. Extract root domain from target
        host = urlparse(ctx.target).hostname or ctx.target
        root = ".".join(host.split(".")[-2:])

        # 2. Subdomain enumeration (fall back to the known host if subfinder is absent)
        try:
            subs = await SubfinderWrapper(log_dir=log_dir).run(root)
        except ToolNotInstalled:
            subs = []
        if host not in subs:
            subs = [host, *subs]

        # 3. HTTP probe. Fall back to a native Python probe when the httpx CLI is
        #    absent OR yields nothing (e.g. an unrelated `httpx` binary — such as the
        #    Python httpx[cli] — shadows ProjectDiscovery's httpx on PATH).
        try:
            live = await HttpxWrapper(log_dir=log_dir).run(subs)
        except ToolNotInstalled:
            live = []
        if not live:
            live = await _native_probe(subs, ctx.target)

        # 3a. Persist live host URLs for downstream phases (e.g. discovery).
        live_hosts_file = ctx.output_dir / "recon" / "live-hosts.txt"
        live_hosts_file.write_text("".join(f"{r.url}\n" for r in live), encoding="utf-8")

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


async def _native_probe(hosts: list[str], target: str) -> list[HttpxResult]:
    """Probe hosts with native httpx when the httpx CLI is unavailable."""
    results: list[HttpxResult] = []
    seen: set[str] = set()
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=15.0, verify=False  # noqa: S501
    ) as client:
        for h in hosts:
            for candidate in _candidate_urls(h, target):
                if candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    resp = await client.get(candidate)
                except httpx.HTTPError:
                    continue
                title = _extract_title(resp.text)
                server = resp.headers.get("server", "")
                results.append(
                    HttpxResult(
                        url=str(resp.url),
                        status_code=resp.status_code,
                        title=title,
                        tech=[server] if server else [],
                    )
                )
                break  # one successful scheme per host is enough
    return results


def _candidate_urls(host: str, target: str) -> list[str]:
    """Return URLs to try for a host. If it already has a scheme, use it as-is."""
    if host.startswith(("http://", "https://")):
        return [host]
    # Prefer the target's own scheme first when the host matches the target.
    target_scheme = urlparse(target).scheme or "https"
    schemes = [target_scheme, "http" if target_scheme == "https" else "https"]
    return [f"{s}://{host}" for s in schemes]


def _extract_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title")
    if start == -1:
        return ""
    gt = lower.find(">", start)
    end = lower.find("</title>", gt)
    if gt == -1 or end == -1:
        return ""
    return html[gt + 1 : end].strip()[:200]
