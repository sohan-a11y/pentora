"""hydra — network login brute-forcer (gated behind --allow-brute in modules)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

# Matches hydra success lines: "[443][http-post-form] host: x  login: a  password: b"
_CRED_RE = re.compile(
    r"host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)"
)


@dataclass
class HydraCredential:
    host: str
    login: str
    password: str


class HydraWrapper(ToolWrapper):
    tool_name = "hydra"
    install_check_argv = ["hydra", "-h"]

    def build_argv(
        self,
        host: str,
        userlist: str,
        passlist: str,
        form_path: str,
        service: str,
    ) -> list[str]:
        return [
            self.tool_name,
            "-L", userlist,
            "-P", passlist,
            host,
            service,
            form_path,
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[HydraCredential]:
        out: list[HydraCredential] = []
        for m in _CRED_RE.finditer(stdout):
            out.append(
                HydraCredential(
                    host=m.group("host"),
                    login=m.group("login"),
                    password=m.group("password"),
                )
            )
        return out
