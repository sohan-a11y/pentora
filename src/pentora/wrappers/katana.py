"""katana — fast web crawler (ProjectDiscovery)."""
from __future__ import annotations

import json

from pentora.wrappers.base import ToolWrapper


class KatanaWrapper(ToolWrapper):
    tool_name = "katana"
    install_check_argv = ["katana", "-version"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "-u", url, "-jsonl", "-silent"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:
        out: list[str] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = doc.get("request", {}).get("endpoint") or doc.get("endpoint")
            if endpoint:
                out.append(endpoint)
        return out
