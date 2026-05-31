"""Transport phase -- TLS/SSL quality, HSTS header, and mixed-content checks."""
from __future__ import annotations

import re

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.testssl import TlsScanWrapper

# CVSS vectors — missing HSTS / mixed content (C:L scores ~4.2 Medium)
_HSTS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # noqa: S105
# Weak TLS protocol: network-accessible, high confidentiality impact (~5.9 Medium)
_TLS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # noqa: S105
_MIXED_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # noqa: S105

# Detect http:// resource references in HTML (not https://)
_MIXED_RE = re.compile(r"""(?:src|href|action)\s*=\s*["']http://""", re.I)


class TransportModule(PhaseModule):
    name = "transport"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        target = ctx.target
        findings: list[Finding] = []

        # 1. Fetch target headers
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=15.0, verify=False  # noqa: S501
            ) as client:
                resp = await client.get(target)
            findings += _check_hsts(resp, target)
            findings += _check_mixed_content(resp, target)
        except httpx.HTTPError:
            pass

        # 2. Run testssl (may fail if tool not installed — log and skip)
        try:
            wrapper = TlsScanWrapper()
            from urllib.parse import urlparse

            parsed = urlparse(target)
            host_port = f"{parsed.hostname}:{parsed.port or 443}"
            tls_issues = await wrapper.run(host_port, "/dev/null")
            for issue in tls_issues:
                sev = issue.severity
                vec = _TLS_VECTOR
                findings.append(
                    Finding(
                        module="transport.tls",
                        title=f"Weak TLS: {issue.id}",
                        endpoint=target,
                        method="GET",
                        evidence=issue.finding,
                        cvss=CVSS.from_vector(vec),
                        description=(
                            f"testssl.sh detected TLS weakness [{sev}]: {issue.finding}. "
                            f"CVE: {issue.cve}"
                        ),
                        remediation="Disable weak protocols and ciphers.",
                    )
                )
        except Exception:  # noqa: BLE001,S110 - tool not installed or failed; not re-raised
            pass

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings


def _check_hsts(resp: httpx.Response, target: str) -> list[Finding]:
    if "strict-transport-security" not in resp.headers:
        return [
            Finding(
                module="transport.hsts",
                title="Missing HSTS Header",
                endpoint=target,
                method="GET",
                evidence="Strict-Transport-Security header absent",
                cvss=CVSS.from_vector(_HSTS_VECTOR),
                description="The server does not return HSTS, allowing downgrade attacks.",
                remediation=(
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
            )
        ]
    return []


def _check_mixed_content(resp: httpx.Response, target: str) -> list[Finding]:
    body = resp.text
    match = _MIXED_RE.search(body)
    if match:
        snippet = body[max(0, match.start() - 20) : match.end() + 40].strip()
        return [
            Finding(
                module="transport.mixed_content",
                title="Mixed Content Detected",
                endpoint=target,
                method="GET",
                evidence=snippet,
                cvss=CVSS.from_vector(_MIXED_VECTOR),
                description="Page served over HTTPS includes http:// sub-resources.",
                remediation="Ensure all sub-resources load via HTTPS.",
            )
        ]
    return []
