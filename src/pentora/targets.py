"""Shared candidate-endpoint gatherer for attack modules.

Attack phases (authz, injection, ssrf, ...) all need the same starting set of
URLs to probe: the live hosts found in recon plus the endpoints/params found in
discovery. This helper reads those findings from ``ctx.store`` and returns a
de-duplicated list of :class:`Candidate` objects keyed by ``(url, method)``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pentora.context import ScanContext


@dataclass
class Candidate:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    kind: str = "url"  # url | form | api | json_body


async def gather_candidates(ctx: ScanContext) -> list[Candidate]:
    """Build a de-duplicated Candidate list from recon + discovery findings."""
    if ctx.store is None:
        return []

    seen: dict[tuple[str, str], Candidate] = {}
    for finding in await ctx.store.all():
        if not finding.endpoint:
            continue
        key = (finding.endpoint, finding.method)
        if key in seen:
            continue
        seen[key] = Candidate(
            url=finding.endpoint,
            method=finding.method,
            params=_extract_params(finding.extra),
            kind=str(finding.extra.get("kind", "url")),
        )
    return list(seen.values())


def _extract_params(extra: dict[str, object]) -> list[str]:
    params = extra.get("params")
    if isinstance(params, list):
        return [str(p) for p in params]
    return []
