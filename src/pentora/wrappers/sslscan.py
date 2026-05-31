"""sslscan -- TLS/SSL scanner wrapper (XML output mode)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# Protocols considered weak/insecure
_WEAK_PROTOCOLS = {("ssl", "2"), ("ssl", "3"), ("tls", "1.0"), ("tls", "1.1")}


@dataclass
class SslIssue:
    protocol: str
    version: str
    finding: str
    severity: str


class SslscanWrapper(ToolWrapper):
    tool_name = "sslscan"
    install_check_argv = ["sslscan", "--version"]

    def build_argv(self, host: str) -> list[str]:
        return [self.tool_name, "--xml=-", host]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[SslIssue]:
        """Parse sslscan XML output, return issues for weak/legacy protocols."""
        text = stdout.strip()
        if not text:
            return []
        try:
            root = ET.fromstring(text)  # noqa: S314 - input is from local tool, not user
        except ET.ParseError:
            return []

        issues: list[SslIssue] = []
        for proto in root.iter("protocol"):
            ptype = proto.get("type", "").lower()
            version = proto.get("version", "")
            enabled = proto.get("enabled", "0")
            if enabled == "1" and (ptype, version) in _WEAK_PROTOCOLS:
                label = f"{ptype.upper()}v{version}"
                issues.append(
                    SslIssue(
                        protocol=ptype,
                        version=version,
                        finding=f"Weak protocol {label} is enabled",
                        severity="HIGH" if ptype == "ssl" else "MEDIUM",
                    )
                )
        return issues
