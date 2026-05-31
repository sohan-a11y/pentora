"""Profile loading and validation."""
from __future__ import annotations

from typing import Any

from pentora.data.profiles import PROFILES


def load_profile(name: str) -> dict[str, Any]:
    """Load a profile by name. Raises ValueError for unknown profiles."""
    if name not in PROFILES:
        available = ", ".join(sorted(PROFILES.keys()))
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    return PROFILES[name]
