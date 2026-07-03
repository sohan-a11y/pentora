"""DisclosureValidator: strict detectors, zero-false-positive promotion, and the full
LLM -> validation -> Finding loop (including rejecting an LLM hallucination)."""
from __future__ import annotations

from typing import Any

from pentora.engine import (
    Blackboard,
    CartEngine,
    DeterministicValidator,
    Finding,
    Governor,
    HttpTransaction,
    Hypothesis,
    RuleEngine,
    RunScope,
    TestedNegative,
    disclosure_verify_rule,
    disclosure_verify_runner,
    llm_heuristic_runner,
    llm_route_rule,
)
from pentora.engine.disclosure_patterns import (
    find_credit_cards,
    find_pii,
    find_stack_trace,
)

_VISA = "4111111111111111"          # canonical Luhn-valid test card
_NOT_A_CARD = "1234567812345678"     # 16 digits, fails Luhn


# ---- detectors -------------------------------------------------------------

def test_luhn_card_detected_invalid_rejected() -> None:
    assert find_credit_cards(f"card on file: {_VISA} exp 12/29")
    assert find_credit_cards(f"order id {_NOT_A_CARD}") == []   # not Luhn -> not flagged


def test_ssn_and_secret_detected() -> None:
    hits = find_pii('{"ssn":"123-45-6789"}')
    assert any(h.startswith("ssn:") for h in hits)


def test_stack_traces_detected_and_benign_ignored() -> None:
    assert find_stack_trace("Traceback (most recent call last):\n  File x") == "python"
    assert find_stack_trace("at com.acme.Svc.run(Svc.java:88)") == "java"
    assert find_stack_trace("welcome to your dashboard") is None


def test_pii_empty_on_benign() -> None:
    assert find_pii("just a friendly page with an email a@b.com") == []   # email alone != PII


# ---- validator strategies --------------------------------------------------

def test_validator_confirms_pii_with_real_card() -> None:
    v = DeterministicValidator()
    hyp = Hypothesis(source="llm", claim="pii_leak")
    out = v.promote(hyp, {"body": f'{{"cc":"{_VISA}"}}'})
    assert isinstance(out, Finding)
    assert out.severity == "high"
    assert "credit_card" in out.evidence


def test_validator_refutes_pii_hallucination() -> None:
    v = DeterministicValidator()
    hyp = Hypothesis(source="llm", claim="pii_leak")
    out = v.promote(hyp, {"body": "nothing sensitive here"})
    assert isinstance(out, TestedNegative)      # LLM lead with no real PII -> not a finding


def test_validator_confirms_stack_trace() -> None:
    v = DeterministicValidator()
    hyp = Hypothesis(source="llm", claim="stack_trace_disclosure")
    out = v.promote(hyp, {"body": "Traceback (most recent call last):\n psycopg2.Error"})
    assert isinstance(out, Finding)
    assert out.severity in ("medium", "low")


# ---- full LLM -> validation -> Finding loop --------------------------------

class _Fake:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def classify(self, system: str, user: str) -> dict[str, Any]:
        return self.result


def _engine(fake: _Fake) -> tuple[CartEngine, Blackboard]:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(llm_route_rule())
    eng.add_rule(disclosure_verify_rule())
    cart = CartEngine(bb=bb, chainer=eng, governor=Governor(),
                      validator=DeterministicValidator(), scope=RunScope(), config={"ollama": fake})
    cart.register("llm_heuristic_playbook", llm_heuristic_runner)
    cart.register("disclosure_verify", disclosure_verify_runner)
    return cart, bb


def test_full_loop_llm_lead_confirmed_to_finding() -> None:
    cart, bb = _engine(_Fake({"is_vulnerable": True, "vuln_type": "pii_leak", "severity_score": 8}))
    bb.assert_fact(HttpTransaction(source="capture", method="GET", url="https://app/api/me",
                                   status=200, resp_body_snippet=f'{{"card":"{_VISA}"}}'))
    cart.run()
    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "PII_LEAK"
    assert findings[0].severity == "high"


def test_full_loop_llm_hallucination_produces_no_finding() -> None:
    cart, bb = _engine(_Fake({"is_vulnerable": True, "vuln_type": "pii_leak", "severity_score": 9}))
    bb.assert_fact(HttpTransaction(source="capture", method="GET", url="https://app/api/home",
                                   status=200, resp_body_snippet="welcome, here is your dashboard"))
    cart.run()
    assert bb.query("finding") == []                # deterministic layer blocked the hallucination
    assert bb.query("tested_negative")              # recorded as coverage
