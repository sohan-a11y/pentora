"""Disclosure verification — closes the LLM -> validation -> Finding loop.

A disclosure hypothesis (from the LLM classifier) is deterministically re-checked against the
actual response bytes. If the strict patterns confirm real PII/secret/stack-trace data, it
becomes a Finding; if the LLM hallucinated, it becomes a tested-negative. The LLM proposes; the
regex disposes — an LLM lead can never become a false-positive Finding.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import Fact, HttpTransaction, Hypothesis, Task

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine

_DISCLOSURE_CLAIMS = ("pii_leak", "stack_trace_disclosure")


def _is_disclosure_hyp(f: Fact) -> bool:
    return isinstance(f, Hypothesis) and f.claim in _DISCLOSURE_CLAIMS


def disclosure_verify_rule() -> Rule:
    """SOCKET: a disclosure hypothesis. TAB: queue a deterministic verification task."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        h = b["h"]
        engine.assert_fact(Task(
            source="disclosure_rule", playbook="disclosure_verify",
            args={"hyp_id": h.id}, derived_from=[h.id],
        ))

    return Rule(
        name="disclosure_verify",
        patterns=[Pattern(kind="hypothesis", where=_is_disclosure_hyp, as_="h")],
        action=action,
    )


def disclosure_verify_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: re-check the hypothesis's source body with the DisclosureValidator."""
    hyp_id = task.args.get("hyp_id")
    hyp = engine.bb.get(str(hyp_id)) if hyp_id else None
    if not isinstance(hyp, Hypothesis):
        return
    body = ""
    for src_id in hyp.derived_from:
        src = engine.bb.get(src_id)
        if isinstance(src, HttpTransaction) and src.resp_body_snippet:
            body = src.resp_body_snippet
            break
    fact = engine.validator.promote(hyp, {"body": body, "evidence_ids": list(hyp.derived_from)})
    if fact is not None:
        engine.bb.assert_fact(fact)
