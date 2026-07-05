"""SQLi playbook: confirmed (boolean divergence) on a vulnerable server, refuted on a
parameterized one, and self-assembling reactively from a captured parameterized request."""
from __future__ import annotations

import pytest

pytest.importorskip("py_trees")

from py_trees.common import Status  # noqa: E402

from pentora.engine import (  # noqa: E402
    Blackboard,
    DeterministicValidator,
    Governor,
    HttpTransaction,
    Hypothesis,
    RuleEngine,
)
from pentora.engine.playbook_sqli import (  # noqa: E402
    SqliPlaybookContext,
    dispatch_sqli_from_facts,
    run_sqli_playbook,
    sqli_rule,
)


def _ctx(bb: Blackboard, hyp: Hypothesis, base: str) -> SqliPlaybookContext:
    return SqliPlaybookContext(
        bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
        target_url=f"{base}/search?q=alpha", param="q", seed="alpha",
    )


def test_sqli_confirmed_against_vulnerable_server(sqli_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="sqli"))
    with sqli_server(vulnerable=True) as base:
        status = run_sqli_playbook(_ctx(bb, hyp, base))
    assert status == Status.SUCCESS
    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "SQLI"


def test_sqli_refuted_against_parameterized_server(sqli_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="sqli"))
    with sqli_server(vulnerable=False) as base:
        status = run_sqli_playbook(_ctx(bb, hyp, base))
    assert status == Status.FAILURE
    assert not bb.query("finding")
    assert bb.query("tested_negative")            # provable coverage recorded


def test_sqli_reactive_dispatch_from_capture(sqli_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="sqli"))
    with sqli_server(vulnerable=True) as base:
        bb.assert_fact(HttpTransaction(
            source="capture", method="GET", url=f"{base}/search?q=alpha", status=200,
        ))
        status = dispatch_sqli_from_facts(bb, Governor(), DeterministicValidator(), hyp)
    assert status == Status.SUCCESS
    assert len(bb.query("finding")) == 1


def test_sqli_rule_fires_on_a_parameterized_request() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(sqli_rule())
    bb.assert_fact(HttpTransaction(source="capture", method="GET", url="http://t/s?q=x", status=200))
    eng.run_to_fixpoint()
    assert any(h.claim == "sqli" for h in bb.query("hypothesis"))
    assert any(t.playbook == "sqli_playbook" for t in bb.query("task"))
