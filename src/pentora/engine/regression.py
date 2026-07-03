"""Continuous/regression layer — save a baseline of findings and, on a later run, alert only on the
delta. This is what turns a one-shot scan into Continuous Automated Red Teaming: a nightly run
against the same target should be SILENT unless something changed. Findings are identified by their
content ``dedup_key`` (title + endpoint + evidence), so the same vuln seen twice is PERSISTING, a
vuln that disappeared is RESOLVED, and only genuinely new exposure is NEW — the thing to page on.

Core-only (stdlib + pydantic): a baseline can be diffed in CI without the optional playbook deps.
"""
from __future__ import annotations

import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import Finding


class FindingRecord(BaseModel):
    """A finding's stable identity + enough display info to describe it even once it's resolved."""

    model_config = ConfigDict(frozen=True)

    key: str                                                  # Finding.dedup_key
    title: str
    severity: str = "info"
    cvss_score: float = 0.0
    evidence: str = ""

    @classmethod
    def of(cls, f: Finding) -> FindingRecord:
        return cls(
            key=f.dedup_key, title=f.title, severity=f.severity,
            cvss_score=f.cvss_score, evidence=f.evidence,
        )


class Baseline(BaseModel):
    """A persisted snapshot of the known/accepted findings for a target."""

    model_config = ConfigDict(frozen=True)

    target: str = ""
    created_at: float = Field(default_factory=time.time)
    findings: list[FindingRecord] = Field(default_factory=list)

    @property
    def keys(self) -> set[str]:
        return {r.key for r in self.findings}

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, text: str) -> Baseline:
        return cls.model_validate_json(text)


class Delta(BaseModel):
    """The difference between a baseline and the current blackboard."""

    model_config = ConfigDict(frozen=True)

    new: list[FindingRecord] = Field(default_factory=list)
    resolved: list[FindingRecord] = Field(default_factory=list)
    persisting: list[FindingRecord] = Field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        """True when something NEW appeared — the signal a continuous run should alert on."""
        return bool(self.new)


def _records(bb: Blackboard) -> list[FindingRecord]:
    """Current findings as records, highest CVSS first (deterministic order)."""
    return sorted(
        (FindingRecord.of(f) for f in bb.query("finding") if isinstance(f, Finding)),
        key=lambda r: -r.cvss_score,
    )


def snapshot(bb: Blackboard, target: str = "") -> Baseline:
    return Baseline(target=target, findings=_records(bb))


def save_baseline(bb: Blackboard, path: str | Path, target: str = "") -> Path:
    p = Path(path)
    p.write_text(snapshot(bb, target).to_json(), encoding="utf-8")
    return p


def load_baseline(path: str | Path) -> Baseline:
    return Baseline.from_json(Path(path).read_text(encoding="utf-8"))


def diff(baseline: Baseline, bb: Blackboard) -> Delta:
    """New vs. resolved vs. persisting, comparing the blackboard against a saved baseline."""
    current = {r.key: r for r in _records(bb)}
    base = baseline.keys
    return Delta(
        new=[r for k, r in current.items() if k not in base],
        persisting=[r for k, r in current.items() if k in base],
        resolved=[r for r in baseline.findings if r.key not in current],
    )


def _section(title: str, recs: list[FindingRecord]) -> list[str]:
    out = [f"## {title}", ""]
    if not recs:
        out.append("_None._")
    for r in recs:
        out.append(f"- **{r.title}** — {r.severity.upper()} (CVSS {r.cvss_score}) — {r.evidence}")
    out.append("")
    return out


def render_markdown(delta: Delta, target: str = "") -> str:
    lines = [f"# Pentora CART — Regression Delta ({target or 'engagement'})", ""]
    lines += [
        f"**New:** {len(delta.new)}  |  **Resolved:** {len(delta.resolved)}  |  "
        f"**Persisting:** {len(delta.persisting)}",
        "",
    ]
    lines += _section("New (alert)", delta.new)
    lines += _section("Resolved", delta.resolved)
    lines += _section("Persisting", delta.persisting)
    return "\n".join(lines) + "\n"
