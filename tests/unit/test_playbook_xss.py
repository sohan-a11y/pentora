"""XSS playbook: confirmed on a server that reflects markup unescaped, refuted on one that
HTML-escapes it, and self-assembling reactively from a captured parameterized request."""
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
from pentora.engine.playbook_xss import (  # noqa: E402
    XssPlaybookContext,
    dispatch_xss_from_facts,
    run_xss_playbook,
    xss_rule,
)


def _ctx(bb: Blackboard, hyp: Hypothesis, base: str) -> XssPlaybookContext:
    return XssPlaybookContext(
        bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
        target_url=f"{base}/echo?name=foo", param="name",
    )


def test_xss_confirmed_against_reflecting_server(xss_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="xss"))
    with xss_server(vulnerable=True) as base:
        status = run_xss_playbook(_ctx(bb, hyp, base))
    assert status == Status.SUCCESS
    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "XSS"


def test_xss_refuted_against_escaping_server(xss_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="xss"))
    with xss_server(vulnerable=False) as base:
        status = run_xss_playbook(_ctx(bb, hyp, base))
    assert status == Status.FAILURE
    assert not bb.query("finding")
    assert bb.query("tested_negative")


def test_xss_reactive_dispatch_from_capture(xss_server) -> None:  # noqa: ANN001
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="xss"))
    with xss_server(vulnerable=True) as base:
        bb.assert_fact(HttpTransaction(
            source="capture", method="GET", url=f"{base}/echo?name=foo", status=200,
        ))
        status = dispatch_xss_from_facts(bb, Governor(), DeterministicValidator(), hyp)
    assert status == Status.SUCCESS
    assert len(bb.query("finding")) == 1


def test_xss_rule_fires_on_a_parameterized_request() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(xss_rule())
    bb.assert_fact(HttpTransaction(source="capture", method="GET", url="http://t/e?name=x", status=200))
    eng.run_to_fixpoint()
    assert any(h.claim == "xss" for h in bb.query("hypothesis"))
    assert any(t.playbook == "xss_playbook" for t in bb.query("task"))
