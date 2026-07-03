"""Deterministic disclosure detectors — strict, high-confidence patterns tuned for ZERO false
positives. The DisclosureValidator runs these over the actual response bytes to promote (or
refute) an LLM-proposed disclosure hypothesis. All matches are redacted before they leave here.

Deliberately conservative: email addresses are NOT treated as PII (too common on legitimate
pages). Credit cards must pass the Luhn checksum. Stack-trace signatures are strings that
essentially never appear in benign responses.
"""
from __future__ import annotations

import re

# Server-side stack-trace / error signatures across common stacks.
_STACK_TRACE_PATTERNS: list[tuple[str, str]] = [
    (r"Traceback \(most recent call last\):", "python"),
    (r"\bat [\w.$]+\([\w.]+\.java:\d+\)", "java"),
    (r"Exception in thread \"", "java"),
    (r"\bat [\w.$<>]+ \([^)]*node_modules", "node"),
    (r"Fatal error:.*Stack trace:", "php"),
    (r"\.php on line \d+", "php"),
    (r"System\.[A-Za-z.]+Exception:", "dotnet"),
    (r"\bORA-\d{5}\b", "oracle"),
    (r"SQLSTATE\[", "sql"),
    (r"syntax error at or near \"", "postgres"),
    (r"You have an error in your SQL syntax", "mysql"),
]

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def find_stack_trace(text: str) -> str | None:
    """Return the detected stack type, or None."""
    for pattern, stack in _STACK_TRACE_PATTERNS:
        if re.search(pattern, text):
            return stack
    return None


def _luhn_ok(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_credit_cards(text: str) -> list[str]:
    out: list[str] = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            out.append(f"{digits[:6]}...{digits[-4:]}")   # redacted
    return out


def find_ssns(text: str) -> list[str]:
    return [f"{m.group()[:3]}-**-****" for m in _SSN_RE.finditer(text)]


def find_secrets(text: str) -> list[str]:
    """Reuse the main package's tested secret regexes (AWS/Stripe/GitHub/etc.) if available."""
    try:
        from pentora.security.secret_patterns import SECRET_PATTERNS
    except Exception:  # pragma: no cover - engine can run standalone
        return []
    return [entry["name"] for entry in SECRET_PATTERNS if re.search(entry["pattern"], text)]


def find_pii(text: str) -> list[str]:
    """High-confidence PII/secret indicators, redacted. Empty list = nothing conclusive."""
    hits: list[str] = []
    hits += [f"credit_card:{c}" for c in find_credit_cards(text)]
    hits += [f"ssn:{s}" for s in find_ssns(text)]
    hits += [f"secret:{name}" for name in find_secrets(text)]
    return hits
