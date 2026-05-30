"""tplmap — server-side template injection (SSTI) detection."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

_MARKER = "identified the following injection point"
_PARAM_RE = re.compile(r"parameter:\s*(\S+)")
_ENGINE_RE = re.compile(r"Engine:\s*(\S+)")


@dataclass
class TplmapFinding:
    parameter: str
    engine: str
    evidence: str


class TplmapWrapper(ToolWrapper):
    tool_name = "tplmap"
    install_check_argv = ["tplmap", "--help"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "-u", url]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[TplmapFinding]:
        if _MARKER not in stdout:
            return []
        block = stdout.split(_MARKER, 1)[1]
        param = _PARAM_RE.search(block)
        engine = _ENGINE_RE.search(block)
        if param is None:
            return []
        return [
            TplmapFinding(
                parameter=param.group(1),
                engine=engine.group(1) if engine else "unknown",
                evidence=f"SSTI injection point in '{param.group(1)}'.",
            )
        ]
