"""sqlmap — automatic SQL injection detection and exploitation."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# "GET parameter 'id' is '... time-based blind ...' injectable"
_INJECTABLE_RE = re.compile(r"parameter '([^']+)' is '([^']+)' injectable")
# "back-end DBMS: MySQL >= 5.0.12"  (preferred) or "the back-end DBMS is MySQL"
_DBMS_LINE_RE = re.compile(r"back-end DBMS:\s*(.+)")
_DBMS_INLINE_RE = re.compile(r"the back-end DBMS is (.+)")


@dataclass
class SqlmapFinding:
    parameter: str
    dbms: str
    technique: str
    evidence: str


class SqlmapWrapper(ToolWrapper):
    tool_name = "sqlmap"
    install_check_argv = ["sqlmap", "--version"]

    def build_argv(self, request_file: str) -> list[str]:
        return [
            self.tool_name,
            "-r",
            request_file,
            "--batch",
            "--crawl=2",
            "--level=3",
            "--risk=2",
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[SqlmapFinding]:
        if not stdout.strip():
            return []
        dbms = self._extract_dbms(stdout)
        out: list[SqlmapFinding] = []
        for match in _INJECTABLE_RE.finditer(stdout):
            param, technique = match.group(1), match.group(2)
            existing = next((f for f in out if f.parameter == param), None)
            if existing is None:
                out.append(
                    SqlmapFinding(
                        parameter=param,
                        dbms=dbms,
                        technique=technique,
                        evidence=match.group(0),
                    )
                )
        return out

    @staticmethod
    def _extract_dbms(stdout: str) -> str:
        line = _DBMS_LINE_RE.search(stdout)
        if line:
            return line.group(1).strip()
        inline = _DBMS_INLINE_RE.search(stdout)
        if inline:
            return inline.group(1).strip()
        return "unknown"
