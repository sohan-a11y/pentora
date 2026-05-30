from click.testing import CliRunner

from pentora.cli import main
from pentora.version import __version__


def test_cli_version_flag_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    subcommands = (
        "scan",
        "setup",
        "doctor",
        "update",
        "report",
        "import-results",
        "list-profiles",
        "list-modules",
    )
    for sub in subcommands:
        assert sub in result.output
