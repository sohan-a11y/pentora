"""Headers phase -- security header audit: CSP, HSTS, X-Frame-Options, etc."""
from __future__ import annotations

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.security.csp_evaluator import evaluate_csp

# CVSS vectors -- missing security headers (Medium range)
_HEADER_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # noqa: S105
_CSP_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # noqa: S105


class HeadersModule(PhaseModule):
    name = "headers"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        target = ctx.target
        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=15.0, verify=False  # noqa: S501
            ) as client:
                resp = await client.get(target)
        except httpx.HTTPError:
            return []

        findings += _check_csp(resp, target)
        findings += _check_x_content_type(resp, target)
        findings += _check_x_frame_options(resp, target)
        findings += _check_referrer_policy(resp, target)
        findings += _check_permissions_policy(resp, target)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings


def _check_csp(resp: httpx.Response, target: str) -> list[Finding]:
    csp_value = resp.headers.get("content-security-policy", "")
    if not csp_value:
        return [
            Finding(
                module="headers.csp",
                title="Missing Content-Security-Policy",
                endpoint=target,
                method="GET",
                evidence="Content-Security-Policy header absent",
                cvss=CVSS.from_vector(_HEADER_VECTOR),
                description="No CSP header returned. XSS attacks are not mitigated.",
                remediation="Add a strict Content-Security-Policy header.",
            )
        ]

    findings: list[Finding] = []
    for issue in evaluate_csp(csp_value):
        vec = _CSP_HIGH_VECTOR if issue.severity == "HIGH" else _HEADER_VECTOR
        findings.append(
            Finding(
                module="headers.csp",
                title=f"CSP Weakness: {issue.kind}",
                endpoint=target,
                method="GET",
                evidence=f"CSP: {csp_value[:120]}",
                cvss=CVSS.from_vector(vec),
                description=issue.description,
                remediation=f"Fix CSP directive: remove or restrict {issue.kind}.",
            )
        )
    return findings


def _check_x_content_type(resp: httpx.Response, target: str) -> list[Finding]:
    if "x-content-type-options" not in resp.headers:
        return [
            Finding(
                module="headers.x_content_type",
                title="Missing X-Content-Type-Options",
                endpoint=target,
                method="GET",
                evidence="X-Content-Type-Options header absent",
                cvss=CVSS.from_vector(_HEADER_VECTOR),
                description="Browser may MIME-sniff responses enabling XSS vectors.",
                remediation="Add: X-Content-Type-Options: nosniff",
            )
        ]
    return []


def _check_x_frame_options(resp: httpx.Response, target: str) -> list[Finding]:
    has_xfo = "x-frame-options" in resp.headers
    csp = resp.headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not has_xfo and not has_frame_ancestors:
        return [
            Finding(
                module="headers.x_frame_options",
                title="Missing Clickjacking Protection",
                endpoint=target,
                method="GET",
                evidence="Neither X-Frame-Options nor CSP frame-ancestors present",
                cvss=CVSS.from_vector(_HEADER_VECTOR),
                description="Page may be embedded in iframes enabling clickjacking.",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            )
        ]
    return []


def _check_referrer_policy(resp: httpx.Response, target: str) -> list[Finding]:
    if "referrer-policy" not in resp.headers:
        return [
            Finding(
                module="headers.referrer_policy",
                title="Missing Referrer-Policy",
                endpoint=target,
                method="GET",
                evidence="Referrer-Policy header absent",
                cvss=CVSS.from_vector(_HEADER_VECTOR),
                description="Browser may leak referrer URLs to third-party sites.",
                remediation="Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
            )
        ]
    return []


def _check_permissions_policy(resp: httpx.Response, target: str) -> list[Finding]:
    if "permissions-policy" not in resp.headers and "feature-policy" not in resp.headers:
        return [
            Finding(
                module="headers.permissions_policy",
                title="Missing Permissions-Policy",
                endpoint=target,
                method="GET",
                evidence="Permissions-Policy header absent",
                cvss=CVSS.from_vector(_HEADER_VECTOR),
                description="Browser features (camera, mic, geolocation) not restricted.",
                remediation="Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            )
        ]
    return []
