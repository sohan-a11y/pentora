"""ffuf — fast web fuzzer for content/directory discovery."""
from __future__ import annotations

import json
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class FfufHit:
    url: str
    status: int
    length: int


class FfufWrapper(ToolWrapper):
    tool_name = "ffuf"
    install_check_argv = ["ffuf", "-V"]

    def build_argv(self, fuzz_url: str, wordlist: str) -> list[str]:
        return [
            self.tool_name,
            "-u", fuzz_url,
            "-w", wordlist,
            "-of", "json",
            "-o", "/dev/stdout",
            "-s",
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[FfufHit]:
        if not stdout.strip():
            return []
        try:
            doc = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        out: list[FfufHit] = []
        for r in doc.get("results", []):
            url = r.get("url")
            if not url:
                continue
            out.append(
                FfufHit(
                    url=url,
                    status=int(r.get("status", 0)),
                    length=int(r.get("length", 0)),
                )
            )
        return out
