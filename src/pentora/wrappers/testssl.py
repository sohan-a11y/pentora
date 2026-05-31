"""testssl.sh -- TLS/SSL scanner wrapper (JSON output mode)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pentora.wrappers.base import ToolWrapper


@dataclass
class TlsIssue:
    id: str
    severity: str
    finding: str
    cve: str


class TlsScanWrapper(ToolWrapper):
    tool_name = "testssl.sh"
    install_check_argv = ["testssl.sh", "--version"]

    def build_argv(self, host: str, json_out: str) -> list[str]:
        return [self.tool_name, "--jsonfile", json_out, "--quiet", host]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[TlsIssue]:
        """Parse testssl JSON array output into TlsIssue list."""
        text = stdout.strip()
        if not text:
            return []
        try:
            data: list[dict[str, Any]] = json.loads(text)
        except json.JSONDecodeError:
            return []

        issues: list[TlsIssue] = []
        bad_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"}
        for item in data:
            sev = str(item.get("severity", "")).upper()
            if sev in bad_severities:
                issues.append(
                    TlsIssue(
                        id=str(item.get("id", "")),
                        severity=sev,
                        finding=str(item.get("finding", "")),
                        cve=str(item.get("cve", "")),
                    )
                )
        return issues
