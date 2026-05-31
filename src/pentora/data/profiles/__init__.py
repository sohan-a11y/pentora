"""Built-in scan profiles for Pentora."""
from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "generic": {
        "name": "generic",
        "description": "General-purpose web application",
    },
    "dating": {
        "name": "dating",
        "description": "Dating apps (Tinder, Bumble, Pure, etc.)",
        "extra_business_logic_tests": [
            "match_without_consent",
            "location_spoofing",
            "private_photo_access_without_match",
            "message_without_match",
            "age_verification_bypass",
            "subscription_bypass",
        ],
        "idor_priority_endpoints": [
            "/api/*/users/*",
            "/api/*/conversations/*",
            "/api/*/messages/*",
            "/api/*/photos/private",
        ],
    },
    "saas": {
        "name": "saas",
        "description": "SaaS platforms and B2B applications",
    },
    "fintech": {
        "name": "fintech",
        "description": "Financial technology and payment platforms",
    },
    "ecommerce": {
        "name": "ecommerce",
        "description": "E-commerce and retail platforms",
    },
}

__all__ = ["PROFILES"]
