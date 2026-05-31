import sys
from pathlib import Path

import pytest

from pentora.wrappers.base import ToolNotInstalled, ToolWrapper


class FakeTool(ToolWrapper):
    """Uses the Python interpreter to echo args — works cross-platform."""

    tool_name = "python-fake"
    install_check_argv = [sys.executable, "--version"]

    def installed(self) -> bool:
        # Python is always available; bypass shutil.which on the alias name.
        return True

    def build_argv(self, *args: str, **kwargs: object) -> list[str]:
        # Print args joined by space; no echo.exe dependency.
        return [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(' '.join(sys.argv[1:]) + '\\n')",
            *args,
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:
        return [stdout.strip()]


@pytest.mark.asyncio
async def test_wrapper_runs_command_and_parses(tmp_path: Path) -> None:
    tool = FakeTool(log_dir=tmp_path)
    result = await tool.run("hello", "world")
    assert result == ["hello world"]


@pytest.mark.asyncio
async def test_wrapper_raises_when_tool_missing(tmp_path: Path) -> None:
    class Missing(ToolWrapper):
        tool_name = "this-tool-does-not-exist-xyz123"
        install_check_argv = ["this-tool-does-not-exist-xyz123", "--version"]

        def build_argv(self, *args, **kwargs):
            return [self.tool_name]

        def parse(self, stdout, stderr, returncode):
            return []

    with pytest.raises(ToolNotInstalled):
        await Missing(log_dir=tmp_path).run()
