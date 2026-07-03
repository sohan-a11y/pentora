"""Continuous/regression layer: baseline snapshot + new/resolved/persisting delta."""
from __future__ import annotations

from pathlib import Path

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import Finding
from pentora.engine.regression import (
    Baseline,
    diff,
    load_baseline,
    render_markdown,
    save_baseline,
    snapshot,
)


def _finding(title: str, evidence: str, score: float = 7.5, sev: str = "high") -> Finding:
    return Finding(
        source="test", title=title, endpoint_id="ep1",
        evidence=evidence, cvss_score=score, severity=sev,
    )


def _bb(*findings: Finding) -> Blackboard:
    bb = Blackboard()
    for f in findings:
        bb.assert_fact(f)
    return bb


def test_snapshot_captures_findings_by_dedup_key() -> None:
    a = _finding("IDOR on /orders", "read another user's order")
    bb = _bb(a)
    base = snapshot(bb, target="app.example.com")
    assert base.target == "app.example.com"
    assert base.keys == {a.dedup_key}
    assert base.findings[0].title == "IDOR on /orders"


def test_baseline_json_roundtrip(tmp_path: Path) -> None:
    bb = _bb(_finding("JWT forge", "alg=none accepted", 9.1, "critical"))
    p = save_baseline(bb, tmp_path / "baseline.json", target="t")
    loaded = load_baseline(p)
    assert isinstance(loaded, Baseline)
    assert loaded.target == "t"
    assert loaded.findings[0].cvss_score == 9.1


def test_diff_classifies_new_resolved_persisting() -> None:
    a = _finding("A", "ev-a")
    b = _finding("B", "ev-b")
    c = _finding("C", "ev-c")
    baseline = snapshot(_bb(a, b))          # baseline had A + B
    current = _bb(b, c)                      # now B persists, C is new, A resolved
    delta = diff(baseline, current)
    assert {r.title for r in delta.new} == {"C"}
    assert {r.title for r in delta.resolved} == {"A"}
    assert {r.title for r in delta.persisting} == {"B"}


def test_has_regressions_only_on_new() -> None:
    a = _finding("A", "ev-a")
    baseline = snapshot(_bb(a))
    # identical current state -> persisting only -> no regression
    assert diff(baseline, _bb(a)).has_regressions is False
    # a brand-new finding -> regression
    assert diff(baseline, _bb(a, _finding("B", "ev-b"))).has_regressions is True
    # only a resolved finding -> no regression to alert on
    assert diff(baseline, _bb()).has_regressions is False


def test_clean_baseline_diff_is_silent() -> None:
    """The CART promise: a second run against an unchanged target surfaces nothing."""
    bb = _bb(_finding("X", "ev-x"), _finding("Y", "ev-y"))
    base = snapshot(bb)
    delta = diff(base, bb)
    assert not delta.new and not delta.resolved
    assert len(delta.persisting) == 2


def test_render_markdown_lists_titles() -> None:
    baseline = snapshot(_bb(_finding("Old", "gone")))
    delta = diff(baseline, _bb(_finding("Fresh", "here")))
    md = render_markdown(delta, target="app")
    assert "New (alert)" in md
    assert "Fresh" in md            # new finding surfaced
    assert "Old" in md              # resolved finding still described
