"""Engine reporting — turn the blackboard's findings AND its tested-negatives into a deliverable.

Unlike a scanner that only lists what it found, this reports provable COVERAGE: every hypothesis
the engine tested and refuted is a recorded ``tested_negative``, so the report answers "did we
test for X?" — the thing a human red-team report can't give you. Core-only (stdlib), so a report
can be produced from any blackboard without the optional playbook deps.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import Finding, TestedNegative


def _findings(bb: Blackboard) -> list[Finding]:
    return sorted(
        (f for f in bb.query("finding") if isinstance(f, Finding)),
        key=lambda f: -f.cvss_score,
    )


def _negatives(bb: Blackboard) -> list[TestedNegative]:
    return [n for n in bb.query("tested_negative") if isinstance(n, TestedNegative)]


def _describe(bb: Blackboard, fact_id: str) -> str:
    f = bb.get(fact_id)
    return f"{f.kind}:{f.id}" if f is not None else fact_id


def build_report(bb: Blackboard, target: str = "") -> dict[str, object]:
    """A structured, JSON-serializable report from the blackboard."""
    findings = _findings(bb)
    negatives = _negatives(bb)
    by_sev = Counter(f.severity for f in findings)
    return {
        "target": target,
        "summary": {
            "findings": len(findings),
            "tested_negative": len(negatives),
            "by_severity": dict(by_sev),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "evidence": f.evidence,
                "poc": f.poc,
                "chain": [_describe(bb, cid) for cid in f.chain],
            }
            for f in findings
        ],
        "coverage": [{"what": n.what, "reason": n.reason} for n in negatives],
    }


def write_json(bb: Blackboard, path: Path, target: str = "") -> Path:
    path.write_text(json.dumps(build_report(bb, target), indent=2), encoding="utf-8")
    return path


def write_markdown(bb: Blackboard, path: Path, target: str = "") -> Path:
    findings = _findings(bb)
    negatives = _negatives(bb)
    by_sev = Counter(f.severity for f in findings)

    lines = [f"# Pentora CART Report — {target or 'engagement'}", ""]
    sev_bits = " · ".join(f"{k}: {v}" for k, v in by_sev.items()) or "none"
    lines += [
        f"**Findings:** {len(findings)} ({sev_bits})  |  "
        f"**Coverage (tested, not vulnerable):** {len(negatives)}",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("_No confirmed findings._\n")
    for f in findings:
        chain = " -> ".join(_describe(bb, cid) for cid in f.chain)
        lines += [
            f"### {f.title} — {f.severity.upper()} (CVSS {f.cvss_score})",
            f"- **Vector:** `{f.cvss_vector}`",
            f"- **Evidence:** {f.evidence}",
            f"- **PoC:** {f.poc}",
            f"- **Chain:** {chain}",
            "",
        ]
    lines += ["## Coverage — tested, not vulnerable", ""]
    if not negatives:
        lines.append("_None recorded._")
    for n in negatives:
        reason = f" ({n.reason})" if n.reason else ""
        lines.append(f"- {n.what}{reason}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
