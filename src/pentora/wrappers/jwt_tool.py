"""jwt_tool — JWT tampering / cracking (ticarpi/jwt_tool)."""
from __future__ import annotations

from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

_WORDLIST = "wordlists/jwt-secrets.txt"

# CLI flags for each supported attack mode.
_MODE_ARGS: dict[str, list[str]] = {
    "alg-none": ["-X", "a"],
    "brute-secret": ["-C", "-d", _WORDLIST],
    "kid-injection": ["-I", "-hc", "kid", "-hv", "../../../../dev/null"],
}


@dataclass
class JwtAttackResult:
    attack: str
    vulnerable: bool
    evidence: str


class JwtToolWrapper(ToolWrapper):
    tool_name = "jwt_tool"
    install_check_argv = ["jwt_tool", "--help"]

    def build_argv(self, token: str, mode: str) -> list[str]:
        return [self.tool_name, token, *_MODE_ARGS[mode]]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[JwtAttackResult]:
        text = stdout
        lower = text.lower()
        if "alg:none" in lower:
            forged = "forged token" in lower
            evidence = self._line_containing(text, "forged") or "alg:none exploit attempted"
            return [JwtAttackResult(attack="alg-none", vulnerable=forged, evidence=evidence)]
        if "correct key" in lower or "passwords" in lower:
            cracked = "correct key" in lower
            evidence = self._line_containing(text, "CORRECT key") or "secret not recovered"
            return [JwtAttackResult(attack="brute-secret", vulnerable=cracked, evidence=evidence)]
        if "kid" in lower:
            injected = "injected" in lower or "signed" in lower
            evidence = self._line_containing(text, "kid") or "kid injection attempted"
            return [JwtAttackResult(attack="kid-injection", vulnerable=injected, evidence=evidence)]
        return []

    @staticmethod
    def _line_containing(text: str, needle: str) -> str:
        for line in text.splitlines():
            if needle.lower() in line.lower():
                return line.strip()
        return ""
