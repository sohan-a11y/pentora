"""Engine reporting: findings sorted by severity + provable coverage from tested-negatives."""
from __future__ import annotations

import json
from pathlib import Path

from pentora.engine import (
    Blackboard,
    Finding,
    TestedNegative,
    build_report,
    write_json,
    write_markdown,
)


def _seed(bb: Blackboard) -> None:
    bb.assert_fact(Finding(source="v", title="JWT_FORGE", cvss_score=9.1, severity="critical",
                           cvss_vector="CVSS:3.1/...", evidence="forged admin accepted", poc="replay"))
    bb.assert_fact(Finding(source="v", title="IDOR", cvss_score=6.4, severity="medium",
                           evidence="cross-user read", poc="swap id"))
    bb.assert_fact(TestedNegative(source="pb", what="jwt alg=none", reason="rejected"))


def test_build_report_summary_and_order() -> None:
    bb = Blackboard()
    _seed(bb)
    r = build_report(bb, target="app.acme.com")
    assert r["target"] == "app.acme.com"
    assert r["summary"] == {  # type: ignore[comparison-overlap]
        "findings": 2, "tested_negative": 1,
        "by_severity": {"critical": 1, "medium": 1},
    }
    titles = [f["title"] for f in r["findings"]]  # type: ignore[index,union-attr]
    assert titles == ["JWT_FORGE", "IDOR"]        # sorted by CVSS desc
    assert r["coverage"][0]["what"] == "jwt alg=none"  # type: ignore[index]


def test_write_json_roundtrips(tmp_path: Path) -> None:
    bb = Blackboard()
    _seed(bb)
    out = write_json(bb, tmp_path / "report.json", target="t")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["findings"] == 2
    assert doc["coverage"][0]["reason"] == "rejected"


def test_write_markdown_shows_findings_and_coverage(tmp_path: Path) -> None:
    bb = Blackboard()
    _seed(bb)
    out = write_markdown(bb, tmp_path / "report.md", target="app.acme.com")
    text = out.read_text(encoding="utf-8")
    assert "# Pentora CART Report — app.acme.com" in text
    assert "JWT_FORGE — CRITICAL (CVSS 9.1)" in text
    assert "Coverage — tested, not vulnerable" in text
    assert "jwt alg=none (rejected)" in text


def test_report_empty_blackboard(tmp_path: Path) -> None:
    bb = Blackboard()
    r = build_report(bb)
    assert r["summary"] == {"findings": 0, "tested_negative": 0, "by_severity": {}}  # type: ignore[comparison-overlap]
    text = write_markdown(bb, tmp_path / "r.md").read_text(encoding="utf-8")
    assert "_No confirmed findings._" in text
