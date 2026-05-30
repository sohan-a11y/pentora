from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from pentora.cli import main
from pentora.wrappers.httpx_tool import HttpxResult


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
