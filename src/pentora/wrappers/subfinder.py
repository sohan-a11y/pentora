"""subfinder — passive subdomain enumeration (ProjectDiscovery)."""
from __future__ import annotations

from pentora.wrappers.base import ToolWrapper


class SubfinderWrapper(ToolWrapper):
    tool_name = "subfinder"
    install_check_argv = ["subfinder", "-version"]

    def build_argv(self, domain: str) -> list[str]:  # type: ignore[override]
        return [self.tool_name, "-d", domain, "-silent", "-all"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:  # type: ignore[override]
        return [line.strip() for line in stdout.splitlines() if line.strip()]
