"""Tests for SARIF 2.1.0 reporter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding, Severity
from pentora.reporters.sarif import SarifReporter


def _make_finding(severity_vector: str, title: str = "Test Finding") -> Finding:
    return Finding(
        module="sqli",
        title=title,
        endpoint="https://target.com/api/users",
        method="GET",
        evidence="SQL error in response",
        cvss=CVSS.from_vector(severity_vector),
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
    )


@pytest.mark.asyncio
async def test_sarif_reporter_creates_file(tmp_path: Path) -> None:
    findings = [_make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, findings, target="https://target.com")
    assert out == tmp_path / "findings.sarif"
    assert out.exists()


@pytest.mark.asyncio
async def test_sarif_reporter_schema_version(tmp_path: Path) -> None:
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc
    assert len(doc["runs"]) == 1


@pytest.mark.asyncio
async def test_sarif_reporter_tool_driver(tmp_path: Path) -> None:
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Pentora"
    assert "version" in driver


@pytest.mark.asyncio
async def test_sarif_reporter_severity_mapping(tmp_path: Path) -> None:
    findings = [
        _make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical Finding"),   # critical
        _make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High Finding"),        # high
        _make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium Finding"),      # medium
        _make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Info Finding"),        # info
    ]
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, findings, target="https://target.com")
    doc = json.loads(out.read_text())
    results = doc["runs"][0]["results"]
    assert len(results) == 4
    levels = {r["message"]["text"].split("\n")[0]: r["level"] for r in results}
    # Critical/High -> error, Medium -> warning, Info -> note
    assert any(r["level"] == "error" for r in results)
    assert any(r["level"] == "warning" for r in results)
    assert any(r["level"] == "note" for r in results)


@pytest.mark.asyncio
async def test_sarif_reporter_result_structure(tmp_path: Path) -> None:
    finding = _make_finding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, [finding], target="https://target.com")
    doc = json.loads(out.read_text())
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "sqli"
    assert "message" in result
    assert "locations" in result
    loc = result["locations"][0]
    assert "physicalLocation" in loc
    assert "https://target.com/api/users" in loc["physicalLocation"]["artifactLocation"]["uri"]


@pytest.mark.asyncio
async def test_sarif_reporter_empty_findings(tmp_path: Path) -> None:
    reporter = SarifReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["results"] == []
