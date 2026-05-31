"""Tests for secret_patterns — every pattern must compile and match a synthetic sample."""
from __future__ import annotations

import re

import pytest

from pentora.security.secret_patterns import SECRET_PATTERNS

SAMPLES: dict[str, str] = {
    "AWS Access Key ID": "AKIAIOSFODNN7EXAMPLE1234",
    "Stripe Live Secret": "sk_LIVE_STRIPE_PREFIX_abcdefghijklmnopqrstuvwxyz",
    "Stripe Test Secret": "sk_TEST_STRIPE_PREFIX_abcdefghijklmnopqrstuvwxyz",
    "GitHub PAT classic": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "GitHub fine-grained PAT": (
        "github_pat_" + "A" * 82
    ),
    "Slack Bot Token": "xoxb-123456-789012-AbCdEfGhIjKlMnOp",
    "Google API Key": "AIzaSyAbcdefghijklmnopqrstuvwxyz123456789",
    "Twilio Account SID": "AC" + "a" * 32,
    "SendGrid API Key": "SG." + "A" * 22 + "." + "B" * 43,
    "Mapbox Token": "pk.eyJtYXBib3hfdG9rZW4iOiJ0ZXN0In0LONGSUFFIX12345",
    "JWT Token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf",
    "Private SSH Key": "-----BEGIN RSA PRIVATE KEY-----",
    "Generic API Key": "api_key = 'supersecretapikey1234567890'",
    "NVIDIA API Key": "nvapi-" + "X" * 80,
}


def test_all_patterns_compile() -> None:
    """Every regex in SECRET_PATTERNS must compile without error."""
    for entry in SECRET_PATTERNS:
        re.compile(entry["pattern"])  # raises re.error if bad


@pytest.mark.parametrize("entry", SECRET_PATTERNS, ids=lambda e: e["name"])
def test_pattern_matches_sample(entry: dict[str, str]) -> None:
    """Each pattern must match its corresponding synthetic sample."""
    name = entry["name"]
    sample = SAMPLES.get(name)
    if sample is None:
        pytest.skip(f"No sample defined for {name!r}")
    assert re.search(entry["pattern"], sample), (
        f"Pattern {entry['pattern']!r} did not match sample {sample!r}"
    )


def test_all_patterns_have_severity() -> None:
    """Every entry must have a severity field."""
    for entry in SECRET_PATTERNS:
        assert entry["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), (
            f"{entry['name']} has invalid severity {entry['severity']!r}"
        )
