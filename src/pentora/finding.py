"""Finding data model + CVSS scoring."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

# CVSS v3.1 metric values (Base score only — Temporal/Environmental not used here).
# Reference: https://www.first.org/cvss/v3.1/specification-document
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score == 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


@dataclass(frozen=True)
class CVSS:
    vector: str
    score: float

    @classmethod
    def from_vector(cls, vector: str) -> CVSS:
        score = _calc_base_score(vector)
        return cls(vector=vector, score=round(score, 1))

    @property
    def severity(self) -> Severity:
        return Severity.from_score(self.score)


def _calc_base_score(vector: str) -> float:
    # Parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parts = dict(
        p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS")
    )
    av = _AV[parts["AV"]]
    ac = _AC[parts["AC"]]
    ui = _UI[parts["UI"]]
    scope_changed = parts["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
    iss = 1 - ((1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]]))
    impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) if not scope_changed else 1.08 * (impact + exploitability)
    return min(raw, 10.0)


@dataclass
class Finding:
    module: str
    title: str
    endpoint: str
    method: str
    evidence: str
    cvss: CVSS
    description: str = ""
    remediation: str = ""
    request_raw: str = ""
    response_raw: str = ""
    screenshot_path: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = "pentora"  # pentora | burp | zap | nuclei
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Deterministic ID based on canonical fields."""
        key = f"{self.module}|{self.endpoint}|{self.method}|{self.title}|{self.evidence}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def severity(self) -> Severity:
        return self.cvss.severity
