"""Recon result caching — avoid redundant subfinder/httpx runs."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def parse_duration(spec: str) -> timedelta:
    """Parse duration string like ''7d'', ''24h'', ''30m'', ''0'' into timedelta."""
    spec = spec.strip()
    if spec == "0":
        return timedelta(0)
    if spec.endswith("d"):
        return timedelta(days=int(spec[:-1]))
    if spec.endswith("h"):
        return timedelta(hours=int(spec[:-1]))
    if spec.endswith("m"):
        return timedelta(minutes=int(spec[:-1]))
    return timedelta(hours=int(spec))


class ReconCache:
    """Cache for recon results keyed by target URL slug."""

    def __init__(self, cache_dir: Path, max_age: timedelta) -> None:
        self._cache_dir = cache_dir
        self._max_age = max_age

    def _slug(self, target: str) -> str:
        return hashlib.sha256(target.encode()).hexdigest()[:16]

    def load(self, target: str) -> dict[str, Any] | None:
        """Return cached recon data if fresh, else None."""
        if self._max_age.total_seconds() == 0:
            return None
        cache_file = self._cache_dir / self._slug(target) / "recon.json"
        if not cache_file.exists():
            return None
        try:
            data: dict[str, Any] = json.loads(cache_file.read_text())
            ts = datetime.fromisoformat(data["timestamp"])
            if datetime.now(UTC) - ts > self._max_age:
                return None  # expired
            return data
        except (KeyError, ValueError, OSError):
            return None

    def save(self, target: str, data: dict[str, Any]) -> None:
        """Persist recon data with current timestamp."""
        cache_dir = self._cache_dir / self._slug(target)
        cache_dir.mkdir(parents=True, exist_ok=True)
        payload = {"timestamp": datetime.now(UTC).isoformat(), **data}
        (cache_dir / "recon.json").write_text(json.dumps(payload))


def default_cache(max_age: timedelta) -> ReconCache:
    """Return a ReconCache using the default ~/.pentora/cache/ directory."""
    default_dir = Path.home() / ".pentora" / "cache"
    return ReconCache(cache_dir=default_dir, max_age=max_age)
