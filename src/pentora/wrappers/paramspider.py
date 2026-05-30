"""ParamSpider — mine parameter URLs from web archives."""
from __future__ import annotations

from pentora.wrappers.base import ToolWrapper


class ParamSpiderWrapper(ToolWrapper):
    tool_name = "paramspider"
    install_check_argv = ["paramspider", "--help"]

    def build_argv(self, domain: str) -> list[str]:
        return [self.tool_name, "-d", domain, "--stream"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:
        return [line.strip() for line in stdout.splitlines() if line.strip()]
