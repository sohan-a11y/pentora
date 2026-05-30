"""LinkFinder — discover endpoints in JavaScript files."""
from __future__ import annotations

from pentora.wrappers.base import ToolWrapper


class LinkFinderWrapper(ToolWrapper):
    tool_name = "linkfinder"
    install_check_argv = ["linkfinder", "-h"]

    def build_argv(self, url: str) -> list[str]:
        # LinkFinder is distributed as a script; run it via python3 with CLI output.
        return ["python3", "LinkFinder.py", "-i", url, "-o", "cli"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:
        return [line.strip() for line in stdout.splitlines() if line.strip()]
