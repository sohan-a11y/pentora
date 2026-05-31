"""subzy -- subdomain takeover scanner wrapper."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pentora.wrappers.base import ToolWrapper


@dataclass
class SubzyFinding:
    subdomain: str
    service: str
    fingerprint: str


class SubzyWrapper(ToolWrapper):
    tool_name = "subzy"
    install_check_argv = ["subzy", "version"]

    def build_argv(self, targets_file: str) -> list[str]:
        return [self.tool_name, "run", "--targets", targets_file, "--output", "json"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[SubzyFinding]:
        """Parse subzy JSON array output, return vulnerable findings."""
        text = stdout.strip()
        if not text:
            return []
        try:
            data: list[dict[str, Any]] = json.loads(text)
        except json.JSONDecodeError:
            return []

        findings: list[SubzyFinding] = []
        for item in data:
            if item.get("vulnerable"):
                findings.append(
                    SubzyFinding(
                        subdomain=str(item.get("subdomain", "")),
                        service=str(item.get("service", "")),
                        fingerprint=str(item.get("fingerprint", "")),
                    )
                )
        return findings
