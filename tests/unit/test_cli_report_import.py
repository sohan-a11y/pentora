"""CLI-level tests for the `report` and `import-results` subcommands."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pentora.cli import main

_BURP_XML = """<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="Thu Jun 19 00:00:00 UTC 2026">
  <issue>
    <serialNumber>1</serialNumber>
    <type>0</type>
    <name>Reflected XSS</name>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <host ip="1.2.3.4">https://example.com</host>
    <path>/search</path>
    <issueDetail>q parameter reflected</issueDetail>
    <issueBackground>XSS background</issueBackground>
    <remediationDetail>Encode output</remediationDetail>
  </issue>
</issues>
"""


def test_import_results_burp_creates_store(tmp_path: Path) -> None:
    xml = tmp_path / "burp.xml"
    xml.write_text(_BURP_XML, encoding="utf-8")
    out = tmp_path / "imported"
    runner = CliRunner()
    result = runner.invoke(
        main, ["import-results", "burp", str(xml), "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert (out / "findings.db").exists()
    assert "Imported 1 finding" in result.output


def test_import_results_bad_xml_errors_cleanly(tmp_path: Path) -> None:
    xml = tmp_path / "bad.xml"
    xml.write_text("<issues><issue><unclosed>", encoding="utf-8")
    out = tmp_path / "imported"
    runner = CliRunner()
    result = runner.invoke(
        main, ["import-results", "burp", str(xml), "--output", str(out)]
    )
    assert result.exit_code != 0
    assert "Failed to parse" in result.output


def test_report_regenerates_from_imported_db(tmp_path: Path) -> None:
    # First import to create a populated store, then regenerate reports from it.
    xml = tmp_path / "burp.xml"
    xml.write_text(_BURP_XML, encoding="utf-8")
    out = tmp_path / "scan"
    runner = CliRunner()
    imp = runner.invoke(main, ["import-results", "burp", str(xml), "--output", str(out)])
    assert imp.exit_code == 0, imp.output

    rep = runner.invoke(main, ["report", str(out)])
    assert rep.exit_code == 0, rep.output
    assert (out / "summary.html").exists()
    assert (out / "summary.json").exists()
    assert (out / "summary.md").exists()
    assert "Regenerated" in rep.output


def test_report_missing_db_errors(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(main, ["report", str(empty)])
    assert result.exit_code != 0
    assert "No findings.db" in result.output
