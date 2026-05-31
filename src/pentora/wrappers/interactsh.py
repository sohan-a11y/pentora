"""interactsh-client — OOB interaction detection (ProjectDiscovery)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from pentora.wrappers.base import ToolWrapper


@dataclass
class InteractshSession:
    token: str
    interactions: list[str] = field(default_factory=list)


class InteractshWrapper(ToolWrapper):
    tool_name = "interactsh-client"
    install_check_argv = ["interactsh-client", "-version"]
    _TOKEN_RE = re.compile(r'Your unique interactsh.subdomain:\s*(\S+)', re.I)
    _HIT_RE = re.compile(r'Received interaction.*?from\s+(\S+)', re.I)

    def build_argv(self) -> list[str]:  # type: ignore[override]
        return [self.tool_name, "-v", "-o", "/dev/null"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[InteractshSession]:  # type: ignore[override]
        combined = stdout + stderr
        token_m = self._TOKEN_RE.search(combined)
        token = token_m.group(1) if token_m else "unknown.oast.fun"
        hits = [m.group(1) for m in self._HIT_RE.finditer(combined)]
        return [InteractshSession(token=token, interactions=hits)]
