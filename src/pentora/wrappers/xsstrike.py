"""XSStrike — advanced XSS detection (DOM, reflected, stored)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# "[+] Vector for q: <ScRipT>confirm(1)</sCrIpT>"
_VECTOR_RE = re.compile(r"Vector for ([^:]+):\s*(.+)")


@dataclass
class XsstrikeHit:
    param: str
    payload: str


class XsstrikeWrapper(ToolWrapper):
    tool_name = "xsstrike"
    install_check_argv = ["xsstrike", "--help"]

    def build_argv(self, url: str) -> list[str]:
        # XSStrike is distributed as a script; --skip-dom keeps runs bounded.
        return [self.tool_name, "-u", url, "--skip-poc"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[XsstrikeHit]:
        if not stdout.strip():
            return []
        out: list[XsstrikeHit] = []
        for match in _VECTOR_RE.finditer(stdout):
            out.append(XsstrikeHit(param=match.group(1).strip(), payload=match.group(2).strip()))
        return out
