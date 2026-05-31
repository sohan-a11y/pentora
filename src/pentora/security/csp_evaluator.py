"""CSP evaluator -- detects weak Content-Security-Policy headers."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class CspIssue:
    kind: str       # "unsafe-inline", "unsafe-eval", "wildcard-script", etc.
    severity: str   # HIGH, MEDIUM, LOW
    description: str


def evaluate_csp(csp_header: str) -> list[CspIssue]:
    """Evaluate a CSP header string and return a list of weaknesses found."""
    issues: list[CspIssue] = []
    lower = csp_header.lower()
    if "'unsafe-inline'" in lower:
        issues.append(CspIssue("unsafe-inline", "HIGH", "CSP allows unsafe-inline scripts"))
    if "'unsafe-eval'" in lower:
        issues.append(CspIssue("unsafe-eval", "HIGH", "CSP allows unsafe-eval"))
    if re.search(r"script-src[^;]*\s\*", lower):
        issues.append(CspIssue("wildcard-script", "HIGH", "CSP script-src has wildcard *"))
    if "object-src" not in lower:
        issues.append(CspIssue("missing-object-src", "MEDIUM", "CSP missing object-src 'none'"))
    if "base-uri" not in lower:
        issues.append(CspIssue("missing-base-uri", "MEDIUM", "CSP missing base-uri restriction"))
    if "frame-ancestors" not in lower:
        issues.append(CspIssue("no-frame-ancestors", "MEDIUM", "No frame embedding restriction"))
    return issues
