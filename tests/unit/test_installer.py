"""Tests for pentora setup/doctor/update installer."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pentora.cli import main
from pentora.installer import GO_TOOLS, PIP_TOOLS, run_doctor, run_installer


def test_go_tools_not_empty() -> None:
    assert len(GO_TOOLS) >= 5
    assert "subfinder" in GO_TOOLS
    assert "nuclei" in GO_TOOLS


def test_pip_tools_not_empty() -> None:
    assert len(PIP_TOOLS) >= 3
    assert "arjun" in PIP_TOOLS


def test_run_doctor_returns_count(tmp_path):
    """run_doctor returns count of missing tools."""
    with patch("pentora.installer.shutil.which") as which_mock:
        which_mock.return_value = None  # all tools missing
        missing = run_doctor()
    assert isinstance(missing, int)
    assert missing > 0


def test_run_doctor_all_present():
    with patch("pentora.installer.shutil.which") as which_mock:
        which_mock.return_value = "/usr/bin/tool"  # all tools found
        missing = run_doctor()
    assert missing == 0


def test_run_installer_skips_if_present():
    with patch("pentora.installer.shutil.which") as which_mock, \
         patch("pentora.installer.subprocess.run") as sub_mock:
        which_mock.return_value = "/usr/bin/tool"  # all present
        run_installer(skip_go=False, skip_docker=True)
        # subprocess.run should NOT be called for already-present tools
        assert sub_mock.call_count == 0


def test_setup_command() -> None:
    runner = CliRunner()
    with patch("pentora.installer.shutil.which") as which_mock, \
         patch("pentora.installer.subprocess.run") as sub_mock:
        which_mock.return_value = "/usr/bin/tool"
        result = runner.invoke(main, ["setup"])
    assert result.exit_code == 0


def test_doctor_command() -> None:
    runner = CliRunner()
    with patch("pentora.installer.shutil.which") as which_mock:
        which_mock.return_value = "/usr/bin/tool"
        result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "ok" in result.output.lower() or "missing" in result.output.lower() or "tool" in result.output.lower()


def test_update_command() -> None:
    runner = CliRunner()
    with patch("pentora.installer.subprocess.run") as sub_mock:
        sub_mock.return_value = MagicMock(returncode=0)
        result = runner.invoke(main, ["update"])
    assert result.exit_code == 0
