"""Tests for ZAP XML export reporter."""
from __future__ import annotations

from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.zap_xml import ZapXmlReporter


def _make_finding() -> Finding:
    return Finding(
        module="xss",
        title="Cross-Site Scripting",
        endpoint="https://target.com/search",
        method="GET",
        evidence="<script>alert(1)</script> reflected",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        description="XSS vulnerability",
        remediation="Sanitize user input",
    )


@pytest.mark.asyncio
async def test_zap_xml_reporter_creates_file(tmp_path: Path) -> None:
    reporter = ZapXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "zap-export.xml"
    assert out.exists()


@pytest.mark.asyncio
async def test_zap_xml_reporter_content(tmp_path: Path) -> None:
    reporter = ZapXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    content = out.read_text()
    assert "OWASPZAPReport" in content
    assert "<site" in content
    assert "<alerts>" in content
    assert "<alertitem>" in content
    assert "Cross-Site Scripting" in content


@pytest.mark.asyncio
async def test_zap_xml_reporter_alertitem_fields(tmp_path: Path) -> None:
    reporter = ZapXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    content = out.read_text()
    assert "<name>" in content
    assert "<riskcode>" in content
    assert "<desc>" in content
    assert "<solution>" in content
    assert "<evidence>" in content


@pytest.mark.asyncio
async def test_zap_xml_reporter_returns_existing(tmp_path: Path) -> None:
    """If zap-export.xml already exists, return it without overwriting."""
    existing = tmp_path / "zap-export.xml"
    existing.write_text("<existing>zap xml</existing>")
    reporter = ZapXmlReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == existing
    assert out.read_text() == "<existing>zap xml</existing>"


@pytest.mark.asyncio
async def test_zap_xml_reporter_empty(tmp_path: Path) -> None:
    reporter = ZapXmlReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    content = out.read_text()
    assert "OWASPZAPReport" in content
