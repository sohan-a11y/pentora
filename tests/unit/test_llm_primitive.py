"""LLM classifier primitive: proposes Hypotheses, never crashes on bad output, routes via CartEngine."""
from __future__ import annotations

import asyncio
from typing import Any

from pentora.engine import (
    Blackboard,
    CartEngine,
    DeterministicValidator,
    Governor,
    HttpTransaction,
    LlmClassifierPrimitive,
    RuleEngine,
    RunContext,
    RunScope,
    llm_heuristic_runner,
    llm_route_rule,
)


class _FakeClassifier:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        self.calls = 0

    def classify(self, system: str, user: str) -> dict[str, Any]:
        self.calls += 1
        return self.result


class _RaisingClassifier:
    def classify(self, system: str, user: str) -> dict[str, Any]:
        raise ValueError("model returned junk, not JSON")


def _run(prim: LlmClassifierPrimitive, tx: HttpTransaction):  # noqa: ANN202
    return asyncio.run(Governor().execute(prim, tx, RunContext(scope=RunScope())))


def test_llm_emits_hypothesis_on_pii_leak() -> None:
    fake = _FakeClassifier(
        {"is_vulnerable": True, "vuln_type": "pii_leak", "severity_score": 8, "reasoning": "email+ssn"}
    )
    tx = HttpTransaction(source="capture", method="GET", url="https://app/api/me", status=200,
                         resp_body_snippet='{"email":"victim@x.com","ssn":"123-45-6789"}')
    res = _run(LlmClassifierPrimitive(fake), tx)
    assert not res.is_error
    hyps = [f for f in res.facts if f.kind == "hypothesis"]
    assert len(hyps) == 1
    assert hyps[0].claim == "pii_leak"
    assert hyps[0].priority == 8
    assert hyps[0].source == "qwen_local_classifier"
    assert tx.id in hyps[0].derived_from


def test_llm_benign_emits_nothing() -> None:
    fake = _FakeClassifier({"is_vulnerable": False})
    tx = HttpTransaction(source="capture", method="GET", url="https://app/x", status=200,
                         resp_body_snippet="ok")
    res = _run(LlmClassifierPrimitive(fake), tx)
    assert res.facts == []
    assert not res.is_error


def test_llm_bad_output_is_graceful_not_crash() -> None:
    tx = HttpTransaction(source="capture", method="GET", url="https://app/x", status=500)
    res = _run(LlmClassifierPrimitive(_RaisingClassifier()), tx)
    assert res.is_error
    assert res.facts == []


def test_llm_skips_irrelevant_status() -> None:
    fake = _FakeClassifier({"is_vulnerable": True, "vuln_type": "x"})
    tx = HttpTransaction(source="capture", method="GET", url="https://app/x", status=301)
    res = _run(LlmClassifierPrimitive(fake), tx)
    assert res.facts == []
    assert fake.calls == 0                      # never even called the model


def test_llm_severity_out_of_range_clamped() -> None:
    fake = _FakeClassifier({"is_vulnerable": True, "vuln_type": "y", "severity_score": 99})
    tx = HttpTransaction(source="capture", method="GET", url="https://app/x", status=403,
                         resp_body_snippet="forbidden")
    res = _run(LlmClassifierPrimitive(fake), tx)
    assert [f for f in res.facts if f.kind == "hypothesis"][0].priority == 10


def test_cart_routes_capture_to_llm_and_drops_hypothesis() -> None:
    """Full loop: a captured 500 lands -> route rule queues -> runner classifies -> Hypothesis."""
    fake = _FakeClassifier(
        {"is_vulnerable": True, "vuln_type": "stack_trace_disclosure", "severity_score": 6}
    )
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(llm_route_rule())
    cart = CartEngine(bb=bb, chainer=eng, governor=Governor(),
                      validator=DeterministicValidator(), scope=RunScope(), config={"ollama": fake})
    cart.register("llm_heuristic_playbook", llm_heuristic_runner)

    bb.assert_fact(HttpTransaction(source="capture", method="GET", url="https://app/api/x",
                                   status=500, resp_body_snippet="Traceback (most recent call last):"))
    summary = cart.run()

    assert summary["dispatches"] == 1
    hyps = bb.query("hypothesis", claim="stack_trace_disclosure")
    assert len(hyps) == 1
    assert hyps[0].source == "qwen_local_classifier"
