"""Tests for external scanner importers (Burp / ZAP XML) including round-trips."""
from __future__ import annotations

from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.importers import import_burp_xml, import_results, import_zap_xml
from pentora.reporters.burp_xml import BurpXmlReporter
from pentora.reporters.zap_xml import ZapXmlReporter

_BURP_XML = """<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="Thu Jun 19 00:00:00 UTC 2026">
  <issue>
    <serialNumber>1</serialNumber>
    <type>0</type>
    <name>SQL injection</name>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <host ip="1.2.3.4">https://example.com</host>
    <path>/login</path>
    <issueDetail>Parameter username is injectable &amp; exploitable</issueDetail>
    <issueBackground>SQLi background</issueBackground>
    <remediationDetail>Use parameterized queries</remediationDetail>
  </issue>
</issues>
"""

_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="Thu, 19 Jun 2026 00:00:00">
  <site name="https://example.com" host="example.com" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>40018</pluginid>
        <alert>SQL Injection</alert>
        <name>SQL Injection</name>
        <riskcode>3</riskcode>
        <riskdesc>High</riskdesc>
        <desc>SQLi description</desc>
        <solution>Parameterize</solution>
        <evidence>error-based</evidence>
        <instances>
          <instance>
            <uri>https://example.com/login</uri>
            <method>POST</method>
          </instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""


def test_import_burp_xml_parses_issue(tmp_path: Path) -> None:
    p = tmp_path / "burp.xml"
    p.write_text(_BURP_XML, encoding="utf-8")
    findings = import_burp_xml(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "SQL injection"
    assert f.endpoint == "https://example.com/login"
    assert f.source == "burp"
    assert f.severity.value == "high"
    assert "exploitable" in f.evidence  # XML entity decoded


def test_import_zap_xml_parses_instance(tmp_path: Path) -> None:
    p = tmp_path / "zap.xml"
    p.write_text(_ZAP_XML, encoding="utf-8")
    findings = import_zap_xml(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "SQL Injection"
    assert f.endpoint == "https://example.com/login"
    assert f.method == "POST"
    assert f.source == "zap"
    assert f.severity.value == "high"


def test_import_results_dispatch(tmp_path: Path) -> None:
    bp = tmp_path / "b.xml"
    bp.write_text(_BURP_XML, encoding="utf-8")
    assert len(import_results("burp", bp)) == 1


def test_import_results_unknown_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown import source"):
        import_results("nessus", tmp_path / "x.xml")


def test_import_empty_or_no_issues(tmp_path: Path) -> None:
    p = tmp_path / "empty.xml"
    p.write_text('<?xml version="1.0"?><issues></issues>', encoding="utf-8")
    assert import_burp_xml(p) == []


@pytest.mark.asyncio
async def test_burp_roundtrip_preserves_unicode(tmp_path: Path) -> None:
    """A finding with a Unicode em dash survives reporter -> file -> importer."""
    findings = [
        Finding(
            module="recon.subdomain",
            title="Live subdomain discovered",
            endpoint="https://example.com",
            method="GET",
            evidence="HTTP 200 — Example Domain — tech: nginx",  # noqa: RUF001
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        )
    ]
    out = await BurpXmlReporter().write(tmp_path, findings, "https://example.com")
    imported = import_burp_xml(out)
    assert len(imported) == 1
    assert "—" in imported[0].evidence  # noqa: RUF001


@pytest.mark.asyncio
async def test_zap_roundtrip(tmp_path: Path) -> None:
    findings = [
        Finding(
            module="headers.csp",
            title="Missing CSP",
            endpoint="https://example.com",
            method="GET",
            evidence="absent",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        )
    ]
    out = await ZapXmlReporter().write(tmp_path, findings, "https://example.com")
    imported = import_zap_xml(out)
    assert len(imported) == 1
    assert imported[0].title == "Missing CSP"
