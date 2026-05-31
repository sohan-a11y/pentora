"""Tests for all-reporters registry and --reporter CLI flag."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from pentora.cli import main
from pentora.reporters import ALL_REPORTERS, REPORTER_MAP


def test_all_reporters_count() -> None:
    assert len(ALL_REPORTERS) == 11


def test_all_reporters_names() -> None:
    names = {r.name for r in ALL_REPORTERS}
    expected = {
        "json", "markdown", "html", "finding_folder",
        "sarif", "csv", "defectdojo", "faraday",
        "burp_xml", "zap_xml", "har",
    }
    assert names == expected


def test_reporter_map_has_all_reporters() -> None:
    assert len(REPORTER_MAP) == 11
    for name, rep in REPORTER_MAP.items():
        assert rep.name == name


def test_scan_produces_all_11_files(tmp_path: Path) -> None:
    """Integration: scanning with all reporters produces all 11 output files."""
    out = tmp_path / "report"
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=[])
        Http.return_value.run = AsyncMock(return_value=[])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://target.com",
            "--output", str(out),
            "--phases", "recon",
            "--reporter", "all",
        ])
    assert result.exit_code == 0, result.output
    # Verify key output files
    assert (out / "summary.json").exists()
    assert (out / "summary.html").exists()
    assert (out / "summary.md").exists()
    assert (out / "findings").is_dir()
    assert (out / "findings.sarif").exists()
    assert (out / "findings.csv").exists()
    assert (out / "findings.defectdojo.json").exists()
    assert (out / "findings.faraday.json").exists()
    assert (out / "burp-export.xml").exists()
    assert (out / "zap-export.xml").exists()
    assert (out / "traffic.har").exists()


def test_scan_reporter_filter(tmp_path: Path) -> None:
    """--reporter json,sarif should only produce those 2 files."""
    out = tmp_path / "report"
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=[])
        Http.return_value.run = AsyncMock(return_value=[])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://target.com",
            "--output", str(out),
            "--phases", "recon",
            "--reporter", "json,sarif",
        ])
    assert result.exit_code == 0, result.output
    assert (out / "summary.json").exists()
    assert (out / "findings.sarif").exists()
    # CSV should NOT exist
    assert not (out / "findings.csv").exists()
