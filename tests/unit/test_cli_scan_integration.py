from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import respx
from click.testing import CliRunner

from pentora.cli import main
from pentora.wrappers.httpx_tool import HttpxResult


def test_scan_ai_mode_requires_llm_provider(tmp_path: Path) -> None:
    """--ai-mode without --llm-provider should error."""
    out = tmp_path / "report"
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "https://x.com",
        "--output", str(out),
        "--phases", "recon",
        "--ai-mode",
    ])
    assert result.exit_code != 0
    assert "llm-provider" in result.output.lower() or "UsageError" in str(result.exception)


def test_scan_no_ai_mode_skips_ai_modules(tmp_path: Path) -> None:
    """Without --ai-mode, AI modules must not be loaded."""
    out = tmp_path / "report"
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=[])
        Http.return_value.run = AsyncMock(return_value=[])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://x.com",
            "--output", str(out),
            "--phases", "recon",
            "--scope-include", "x.com",
        ])
    assert result.exit_code == 0, result.output


def test_scan_command_produces_report(tmp_path: Path) -> None:
    out = tmp_path / "report"
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=["api.x.com"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.x.com", status_code=200, title="API", tech=["nginx"]),
        ])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://x.com",
            "--output", str(out),
            "--phases", "recon",
            "--scope-include", "x.com,*.x.com",
        ])
    assert result.exit_code == 0, result.output
    assert (out / "summary.json").exists()
    assert (out / "summary.html").exists()
    assert (out / "summary.md").exists()
    assert (out / "findings").is_dir()


@respx.mock
def test_scan_with_discovery_phase(tmp_path: Path) -> None:
    out = tmp_path / "report"
    respx.get("https://api.x.com/.env").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http, \
         patch("pentora.modules.discovery.FfufWrapper") as Ffuf, \
         patch("pentora.modules.discovery.ArjunWrapper") as Arjun, \
         patch("pentora.modules.discovery.KatanaWrapper") as Katana:
        Sub.return_value.run = AsyncMock(return_value=["api.x.com"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.x.com", status_code=200, title="API"),
        ])
        Ffuf.return_value.run = AsyncMock(return_value=[])
        Arjun.return_value.run = AsyncMock(return_value=[])
        Katana.return_value.run = AsyncMock(return_value=[])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://x.com",
            "--output", str(out),
            "--phases", "recon,discovery",
            "--scope-include", "x.com,*.x.com",
        ])
    assert result.exit_code == 0, result.output
    summary = (out / "summary.md").read_text()
    assert "Environment file" in summary or "discovery" in summary.lower()
