"""smuggler — HTTP request smuggling detection (CL.TE / TE.CL / TE.TE)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# "[!] Issue Found   : CL.TE timeout differential detected on https://t.example/"
_ISSUE_RE = re.compile(r"Issue Found\s*:\s*((?:CL\.TE|TE\.CL|TE\.TE)[^\n]*)")


@dataclass
class SmugglerFinding:
    technique: str
    evidence: str


class SmugglerWrapper(ToolWrapper):
    tool_name = "smuggler"
    install_check_argv = ["smuggler", "--help"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "-u", url]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[SmugglerFinding]:
        if not stdout.strip():
            return []
        out: list[SmugglerFinding] = []
        for match in _ISSUE_RE.finditer(stdout):
            detail = match.group(1).strip()
            technique = detail.split()[0]
            out.append(SmugglerFinding(technique=technique, evidence=detail))
        return out
