"""Secret pattern definitions for DisclosureModule."""
from __future__ import annotations

SECRET_PATTERNS: list[dict[str, str]] = [
    {"name": "AWS Access Key ID", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "HIGH"},
    {
        "name": "Stripe Live Secret",
        "pattern": r"sk_LIVE_STRIPE_PREFIX_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
    },
    {
        "name": "Stripe Test Secret",
        "pattern": r"sk_TEST_STRIPE_PREFIX_[0-9a-zA-Z]{24,}",
        "severity": "MEDIUM",
    },
    {
        "name": "GitHub PAT classic",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "HIGH",
    },
    {
        "name": "GitHub fine-grained PAT",
        "pattern": r"github_pat_[A-Za-z0-9_]{82}",
        "severity": "HIGH",
    },
    {
        "name": "Slack Bot Token",
        "pattern": r"xox[baprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+",
        "severity": "HIGH",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "MEDIUM",
    },
    {
        "name": "Twilio Account SID",
        "pattern": r"AC[0-9a-fA-F]{32}",
        "severity": "MEDIUM",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "HIGH",
    },
    {"name": "Mapbox Token", "pattern": r"pk\.eyJ[A-Za-z0-9_-]{20,}", "severity": "LOW"},
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "LOW",
    },
    {
        "name": "Private SSH Key",
        "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "severity": "CRITICAL",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(?:api[_-]?key|apikey|secret)[\s:=]+['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "severity": "MEDIUM",
    },
    {"name": "NVIDIA API Key", "pattern": r"nvapi-[A-Za-z0-9_-]{80,}", "severity": "HIGH"},
]
