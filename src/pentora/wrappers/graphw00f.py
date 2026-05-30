"""graphw00f — GraphQL server engine fingerprinting."""
from __future__ import annotations

import json
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class Graphw00fResult:
    url: str
    engine: str
    implementation: str


class Graphw00fWrapper(ToolWrapper):
    tool_name = "graphw00f"
    install_check_argv = ["graphw00f", "--help"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "-d", "-t", url, "-o", "/dev/stdout"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Graphw00fResult]:
        if not stdout.strip():
            return []
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        engine = doc.get("detected_engine")
        if not engine:
            return []
        return [
            Graphw00fResult(
                url=doc.get("url", ""),
                engine=engine,
                implementation=doc.get("detected_implementation", ""),
            )
        ]
