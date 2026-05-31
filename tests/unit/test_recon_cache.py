"""Tests for recon result caching."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentora.recon_cache import ReconCache, parse_duration


def test_parse_duration_days() -> None:
    assert parse_duration("7d") == timedelta(days=7)


def test_parse_duration_hours() -> None:
    assert parse_duration("24h") == timedelta(hours=24)


def test_parse_duration_zero() -> None:
    assert parse_duration("0") == timedelta(0)


def test_parse_duration_minutes() -> None:
    assert parse_duration("30m") == timedelta(minutes=30)


def test_cache_miss_when_no_file(tmp_path: Path) -> None:
    cache = ReconCache(cache_dir=tmp_path, max_age=timedelta(days=7))
    result = cache.load("https://target.com")
    assert result is None


def test_cache_hit(tmp_path: Path) -> None:
    cache = ReconCache(cache_dir=tmp_path, max_age=timedelta(days=7))
    data = {"subs": ["api.target.com"], "live": ["https://api.target.com"]}
    cache.save("https://target.com", data)
    loaded = cache.load("https://target.com")
    assert loaded is not None
    assert loaded["subs"] == ["api.target.com"]


def test_cache_expires(tmp_path: Path) -> None:
    cache = ReconCache(cache_dir=tmp_path, max_age=timedelta(hours=1))
    # Save with old timestamp
    slug = cache._slug("https://target.com")
    cache_file = tmp_path / slug / "recon.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    old_ts = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    cache_file.write_text(json.dumps({"timestamp": old_ts, "subs": [], "live": []}))
    result = cache.load("https://target.com")
    assert result is None  # expired


def test_cache_zero_max_age_always_miss(tmp_path: Path) -> None:
    """max_age=0 means always skip cache."""
    cache = ReconCache(cache_dir=tmp_path, max_age=timedelta(0))
    data = {"subs": ["api.target.com"], "live": []}
    cache.save("https://target.com", data)
    result = cache.load("https://target.com")
    assert result is None
