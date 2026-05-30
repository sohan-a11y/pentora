"""ghauri — fast SQL injection detection (alternative to sqlmap)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# "GET parameter 'id' is vulnerable to time-based blind injection"
_VULN_RE = re.compile(r"parameter '([^']+)' is vulnerable to ([^\n]+?) injection")
_DBMS_RE = re.compile(r"the back-end DBMS is (.+)")


@dataclass
class GhauriFinding:
    parameter: str
    dbms: str
    technique: str
    evidence: str


class GhauriWrapper(ToolWrapper):
    tool_name = "ghauri"
    install_check_argv = ["ghauri", "--version"]

    def build_argv(self, request_file: str) -> list[str]:
        return [self.tool_name, "-r", request_file, "--batch", "--level=3"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[GhauriFinding]:
        if not stdout.strip():
            return []
        dbms = self._extract_dbms(stdout)
        out: list[GhauriFinding] = []
        for match in _VULN_RE.finditer(stdout):
            param, technique = match.group(1), match.group(2).strip()
            existing = next((f for f in out if f.parameter == param), None)
            if existing is None:
                out.append(
                    GhauriFinding(
                        parameter=param,
                        dbms=dbms,
                        technique=technique,
                        evidence=match.group(0),
                    )
                )
        return out

    @staticmethod
    def _extract_dbms(stdout: str) -> str:
        match = _DBMS_RE.search(stdout)
        return match.group(1).strip() if match else "unknown"
