"""httpx — HTTP probing (ProjectDiscovery). Aliased to avoid clash with stdlib name."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from pentora.wrappers.base import ToolWrapper


@dataclass
class HttpxResult:
    url: str
    status_code: int
    title: str
    tech: list[str] = field(default_factory=list)


class HttpxWrapper(ToolWrapper):
    tool_name = "httpx"
    install_check_argv = ["httpx", "-version"]

    def build_argv(self, hosts: list[str]) -> list[str]:
        # httpx reads stdin when no -l/-u flag; we'll feed via stdin in the orchestrator,
        # but for direct invocation just use -u with comma-joined hosts.
        return [
            self.tool_name,
            "-u", ",".join(hosts),
            "-json", "-silent", "-tech-detect", "-title",
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[HttpxResult]:
        out: list[HttpxResult] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("failed") or not doc.get("url"):
                continue
            out.append(
                HttpxResult(
                    url=doc["url"],
                    status_code=int(doc.get("status_code", 0)),
                    title=doc.get("title", ""),
                    tech=list(doc.get("tech", [])),
                )
            )
        return out
