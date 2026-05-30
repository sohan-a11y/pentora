"""commix — automated OS command injection detection and exploitation."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# "The GET parameter 'addr' is vulnerable to results-based command injection."
_VULN_RE = re.compile(r"parameter '([^']+)' is vulnerable to ([^.\n]*command injection)")


@dataclass
class CommixFinding:
    parameter: str
    technique: str
    evidence: str


class CommixWrapper(ToolWrapper):
    tool_name = "commix"
    install_check_argv = ["commix", "--version"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "--url", url, "--batch"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[CommixFinding]:
        if not stdout.strip():
            return []
        out: list[CommixFinding] = []
        for match in _VULN_RE.finditer(stdout):
            param = match.group(1)
            if any(f.parameter == param for f in out):
                continue
            out.append(
                CommixFinding(
                    parameter=param,
                    technique=match.group(2).strip(),
                    evidence=match.group(0),
                )
            )
        return out
