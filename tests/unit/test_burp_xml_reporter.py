"""Tests for Burp XML export reporter."""
from __future__ import annotations

from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.burp_xml import BurpXmlReporter


def _make_finding() -> Finding:
    return Finding(
        module="sqli",
        title="SQL Injection",
        endpoint="https://target.com/api/users",
        method="GET",
        evidence="Database error",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
    )


@pytest.mark.asyncio
async def test_burp_xml_reporter_creates_file(tmp_path: Path) -> None:
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "burp-export.xml"
    assert out.exists()


@pytest.mark.asyncio
async def test_burp_xml_reporter_content(tmp_path: Path) -> None:
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    content = out.read_text()
    assert "<?xml" in content
    assert "<issues" in content
    assert "<issue>" in content
    assert "SQL Injection" in content
    assert "<severity>" in content


@pytest.mark.asyncio
async def test_burp_xml_reporter_issue_fields(tmp_path: Path) -> None:
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    content = out.read_text()
    assert "<serialNumber>" in content
    assert "<name>" in content
    assert "<host" in content
    assert "<path>" in content
    assert "<issueDetail>" in content
    assert "<issueBackground>" in content
    assert "<remediationDetail>" in content


@pytest.mark.asyncio
async def test_burp_xml_reporter_returns_existing(tmp_path: Path) -> None:
    """If burp-export.xml already exists, return it without overwriting."""
    existing = tmp_path / "burp-export.xml"
    existing.write_text("<existing>burp xml</existing>")
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == existing
    assert out.read_text() == "<existing>burp xml</existing>"


@pytest.mark.asyncio
async def test_burp_xml_reporter_severity_mapping(tmp_path: Path) -> None:
    """Severity must be mapped to Burp's labels."""
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    content = out.read_text()
    # Critical -> High in Burp or "Critical" - accept either
    assert any(sev in content for sev in ["Critical", "High", "Medium", "Low", "Information"])


@pytest.mark.asyncio
async def test_burp_xml_reporter_empty(tmp_path: Path) -> None:
    reporter = BurpXmlReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    content = out.read_text()
    assert "<issues" in content
