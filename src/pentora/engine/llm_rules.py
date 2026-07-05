"""LLM routing — send ambiguous captured transactions to the local classifier.

The blueprint's Experta ``@Rule``/``MATCH``/``self.declare`` was retired with Experta; this uses
the native chainer's ``Pattern``/``Rule`` and the CartEngine runner registry instead.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pentora.engine.asyncrun import run_sync
from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import Fact, HttpTransaction, Task
from pentora.engine.llm_primitive import Classifier, LlmClassifierPrimitive
from pentora.engine.primitive import RunContext, RunScope

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine

_RELEVANT_STATUS = (200, 403, 500)


def _llm_candidate(f: Fact) -> bool:
    return (
        isinstance(f, HttpTransaction)
        and f.source == "capture"
        and f.status in _RELEVANT_STATUS
    )


def llm_route_rule() -> Rule:
    """SOCKET: a captured transaction with an interesting status.
    TAB: queue an llm_heuristic_playbook task for it."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        tx = b["tx"]
        engine.assert_fact(Task(
            source="llm_route", playbook="llm_heuristic_playbook",
            args={"txn_id": tx.id}, derived_from=[tx.id],
        ))

    return Rule(
        name="llm_route",
        patterns=[Pattern(kind="http_txn", where=_llm_candidate, as_="tx")],
        action=action,
    )


def llm_heuristic_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: classify the task's transaction with the local LLM; emit its Hypothesis.

    The classifier is provided via ``engine.config['ollama']``; if absent, the runner no-ops so
    the engine runs fine with the LLM layer disabled.
    """
    ollama = engine.config.get("ollama")
    if not isinstance(ollama, Classifier):
        return
    txn_id = task.args.get("txn_id")
    tx = engine.bb.get(str(txn_id)) if txn_id else None
    if not isinstance(tx, HttpTransaction):
        return
    res = run_sync(engine.governor.execute(
        LlmClassifierPrimitive(ollama), tx,
        RunContext(scope=engine.scope or RunScope(), blackboard=engine.bb),
    ))
    for f in res.facts:
        engine.bb.assert_fact(f)
