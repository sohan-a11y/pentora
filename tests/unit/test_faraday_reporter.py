"""Tests for Faraday JSON import reporter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.faraday import FaradayReporter


def _make_finding(endpoint: str = "https://target.com/api/users") -> Finding:
    return Finding(
        module="sqli",
        title="SQL Injection",
        endpoint=endpoint,
        method="POST",
        evidence="Database error",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
    )


@pytest.mark.asyncio
async def test_faraday_reporter_creates_file(tmp_path: Path) -> None:
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "findings.faraday.json"
    assert out.exists()


@pytest.mark.asyncio
async def test_faraday_reporter_top_level_structure(tmp_path: Path) -> None:
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    assert "hosts" in doc
    assert len(doc["hosts"]) == 1


@pytest.mark.asyncio
async def test_faraday_reporter_host_structure(tmp_path: Path) -> None:
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    host = doc["hosts"][0]
    assert "ip" in host
    assert "hostnames" in host
    assert "vulnerabilities" in host
    assert host["ip"] == "target.com"


@pytest.mark.asyncio
async def test_faraday_reporter_vuln_structure(tmp_path: Path) -> None:
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    vuln = doc["hosts"][0]["vulnerabilities"][0]
    assert vuln["name"] == "SQL Injection"
    assert vuln["desc"] == "SQL injection vulnerability"
    assert "severity" in vuln
    assert vuln["refs"] == []
    assert vuln["resolution"] == "Use parameterized queries"


@pytest.mark.asyncio
async def test_faraday_reporter_groups_by_host(tmp_path: Path) -> None:
    """Findings from same host should be grouped."""
    findings = [
        _make_finding("https://target.com/api/users"),
        _make_finding("https://target.com/api/products"),
        _make_finding("https://other.com/api/items"),
    ]
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, findings, target="https://target.com")
    doc = json.loads(out.read_text())
    assert len(doc["hosts"]) == 2
    hosts_by_ip = {h["ip"]: h for h in doc["hosts"]}
    assert len(hosts_by_ip["target.com"]["vulnerabilities"]) == 2
    assert len(hosts_by_ip["other.com"]["vulnerabilities"]) == 1


@pytest.mark.asyncio
async def test_faraday_reporter_empty(tmp_path: Path) -> None:
    reporter = FaradayReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    assert doc["hosts"] == []
