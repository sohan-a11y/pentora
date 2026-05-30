from click.testing import CliRunner

from pentora.cli import main


def test_dry_run_prints_plan_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "https://example.com", "--dry-run"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.output
    assert "recon" in result.output  # mentions phases that would run
