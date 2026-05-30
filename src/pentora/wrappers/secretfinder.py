"""SecretFinder — discover secrets/API keys in JavaScript files."""
from __future__ import annotations

import json
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class Secret:
    type: str
    value: str
    file_url: str


class SecretFinderWrapper(ToolWrapper):
    tool_name = "secretfinder"
    install_check_argv = ["secretfinder", "-h"]

    def build_argv(self, url: str) -> list[str]:
        # SecretFinder is distributed as a script; emit JSON to stdout.
        return ["python3", "SecretFinder.py", "-i", url, "-o", "json"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Secret]:
        if not stdout.strip():
            return []
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        file_url = doc.get("url", "")
        out: list[Secret] = []
        for entry in doc.get("results", []):
            name = entry.get("name", "unknown")
            for value in entry.get("matches", []):
                out.append(Secret(type=name, value=value, file_url=file_url))
        return out
