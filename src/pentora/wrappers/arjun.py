"""Arjun — HTTP parameter discovery."""
from __future__ import annotations

import json
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class ArjunParam:
    endpoint: str
    name: str
    method: str


class ArjunWrapper(ToolWrapper):
    tool_name = "arjun"
    install_check_argv = ["arjun", "--help"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "-u", url, "-oJ", "/dev/stdout"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ArjunParam]:
        if not stdout.strip():
            return []
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        out: list[ArjunParam] = []
        for endpoint, info in doc.items():
            method = info.get("method", "GET")
            for name in info.get("params", []):
                out.append(ArjunParam(endpoint=endpoint, name=name, method=method))
        return out
