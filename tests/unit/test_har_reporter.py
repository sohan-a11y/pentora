"""Tests for HAR (HTTP Archive) reporter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.har import HarReporter


def _make_finding(request_raw: str = "", response_raw: str = "") -> Finding:
    return Finding(
        module="sqli",
        title="SQL Injection",
        endpoint="https://target.com/api/users",
        method="POST",
        evidence="Database error",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        request_raw=request_raw,
        response_raw=response_raw,
    )


_SAMPLE_REQUEST = (
    "POST /api/users HTTP/1.1\n"
    "Host: target.com\n"
    "Content-Type: application/json\n"
    "\n"
    '{"id": "1 OR 1=1"}'
)

_SAMPLE_RESPONSE = (
    "HTTP/1.1 500 Internal Server Error\n"
    "Content-Type: application/json\n"
    "\n"
    '{"error": "Database error"}'
)


@pytest.mark.asyncio
async def test_har_reporter_creates_file(tmp_path: Path) -> None:
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "traffic.har"
    assert out.exists()


@pytest.mark.asyncio
async def test_har_reporter_top_level_structure(tmp_path: Path) -> None:
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    assert "log" in doc
    log = doc["log"]
    assert log["version"] == "1.2"
    assert "creator" in log
    assert "entries" in log


@pytest.mark.asyncio
async def test_har_reporter_creator(tmp_path: Path) -> None:
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    creator = doc["log"]["creator"]
    assert creator["name"] == "Pentora"
    assert "version" in creator


@pytest.mark.asyncio
async def test_har_reporter_entry_from_raw(tmp_path: Path) -> None:
    finding = _make_finding(request_raw=_SAMPLE_REQUEST, response_raw=_SAMPLE_RESPONSE)
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [finding], target="https://target.com")
    doc = json.loads(out.read_text())
    entries = doc["log"]["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert "request" in entry
    assert "response" in entry
    assert entry["request"]["method"] == "POST"
    assert "target.com" in entry["request"]["url"]


@pytest.mark.asyncio
async def test_har_reporter_stub_entry_no_raw(tmp_path: Path) -> None:
    """Finding with no raw data should create a minimal stub entry."""
    finding = _make_finding()
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [finding], target="https://target.com")
    doc = json.loads(out.read_text())
    entries = doc["log"]["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert "request" in entry
    assert entry["request"]["url"] == "https://target.com/api/users"


@pytest.mark.asyncio
async def test_har_reporter_empty(tmp_path: Path) -> None:
    reporter = HarReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    assert doc["log"]["entries"] == []
