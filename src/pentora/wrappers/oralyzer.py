"""oralyzer — open redirect scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class OralyzerHit:
    url: str
    redirect_to: str


class OralyzerWrapper(ToolWrapper):
    tool_name = "oralyzer"
    install_check_argv = ["oralyzer", "--help"]
    _VULN = re.compile(r'\[VULNERABLE\]\s+(\S+)\s+\[redirect to:\s+([^\]]+)\]')

    def build_argv(self, url: str) -> list[str]:  # type: ignore[override]
        return [self.tool_name, "-u", url]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[OralyzerHit]:  # type: ignore[override]
        hits: list[OralyzerHit] = []
        for m in self._VULN.finditer(stdout):
            hits.append(OralyzerHit(url=m.group(1), redirect_to=m.group(2).strip()))
        return hits
