"""Tests for DefectDojo reporter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.defectdojo import DefectDojoReporter


def _make_finding(sev_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") -> Finding:
    return Finding(
        module="sqli",
        title="SQL Injection",
        endpoint="https://target.com/api/users",
        method="POST",
        evidence="Database error",
        cvss=CVSS.from_vector(sev_vector),
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
    )


@pytest.mark.asyncio
async def test_defectdojo_reporter_creates_file(tmp_path: Path) -> None:
    reporter = DefectDojoReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "findings.defectdojo.json"
    assert out.exists()


@pytest.mark.asyncio
async def test_defectdojo_reporter_structure(tmp_path: Path) -> None:
    reporter = DefectDojoReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    assert "findings" in doc
    assert len(doc["findings"]) == 1


@pytest.mark.asyncio
async def test_defectdojo_reporter_finding_fields(tmp_path: Path) -> None:
    reporter = DefectDojoReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    doc = json.loads(out.read_text())
    f = doc["findings"][0]
    assert f["title"] == "SQL Injection"
    assert f["severity"] == "Critical"
    assert f["description"] == "SQL injection vulnerability"
    assert f["mitigation"] == "Use parameterized queries"
    assert "cvssv3" in f
    assert "date" in f
    assert f["active"] is True
    assert f["verified"] is False


@pytest.mark.asyncio
async def test_defectdojo_severity_capitalized(tmp_path: Path) -> None:
    """Severity must be Capitalized: Critical/High/Medium/Low/Info."""
    vectors = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "High"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "Medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "Info"),
    ]
    for vector, expected_sev in vectors:
        reporter = DefectDojoReporter()
        out = await reporter.write(tmp_path, [_make_finding(vector)], target="https://target.com")
        doc = json.loads(out.read_text())
        assert doc["findings"][0]["severity"] == expected_sev, f"Expected {expected_sev} for {vector}"


@pytest.mark.asyncio
async def test_defectdojo_reporter_empty(tmp_path: Path) -> None:
    reporter = DefectDojoReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    doc = json.loads(out.read_text())
    assert doc["findings"] == []
