"""SQL-injection playbook — boolean-based, proven by response divergence, not by a scanner's word.

Payload SYNTAX comes from the RAG ``PayloadOracle`` (never hand-rolled here). The playbook fires
three real requests through the Governor — a benign control, a boolean-TRUE injection, and a
boolean-FALSE injection — and hands the three bodies to the deterministic ``SqliValidator``. The
validator confirms only if TRUE resembles the control while FALSE diverges from it (the signature
of a query whose WHERE clause we actually influenced). A parameterized endpoint treats the payload
as a literal, so TRUE and FALSE both diverge equally → refuted. All requests are read-only GETs.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status

from pentora.engine.blackboard import Blackboard
from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import Fact, HttpTransaction, Hypothesis, Task, TestedNegative
from pentora.engine.injection import inject_param, split_query_target
from pentora.engine.oracle import PayloadOracle
from pentora.engine.primitive import Governor, RunContext, RunScope
from pentora.engine.replay import HttpReplayPrimitive, ReplayInput
from pentora.engine.validator import DeterministicValidator

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine


@dataclass
class SqliPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    target_url: str                                     # a captured URL with the injectable param
    param: str
    seed: str = "1"                                     # benign baseline value for the param
    token: str | None = None
    scope: RunScope | None = None

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="sqli_playbook", what=what, derived_from=[self.hypothesis.id])
        )


def _replay(pctx: SqliPlaybookContext, url: str, role: str) -> str:
    scope = pctx.scope or RunScope(read_only=True)
    res = asyncio.run(
        pctx.governor.execute(
            HttpReplayPrimitive(),
            ReplayInput(url=url, token=pctx.token, role_label=role),
            RunContext(scope=scope, budget_requests=50),
        )
    )
    for f in res.facts:
        pctx.bb.assert_fact(f)
    return str(res.data.get("body", ""))


class _SqliLeaf(Behaviour):
    def __init__(self, pctx: SqliPlaybookContext) -> None:
        super().__init__("sqli_boolean")
        self.pctx = pctx

    def update(self) -> Status:
        p = self.pctx
        true_p, false_p = PayloadOracle().sqli_boolean_pair(p.seed)
        control = _replay(p, inject_param(p.target_url, p.param, p.seed), "sqli_control")
        true_resp = _replay(p, inject_param(p.target_url, p.param, true_p.value), "sqli_true")
        false_resp = _replay(p, inject_param(p.target_url, p.param, false_p.value), "sqli_false")

        fact = p.validator.promote(p.hypothesis, {
            "true_resp": true_resp,
            "false_resp": false_resp,
            "control_resp": control,
            "evidence_ids": [],
        })
        if fact is None:
            p.record_negative("sqli inconclusive")
            return Status.FAILURE
        p.bb.assert_fact(fact)
        return Status.SUCCESS if fact.kind == "finding" else Status.FAILURE


def build_sqli_playbook(pctx: SqliPlaybookContext) -> Behaviour:
    root = py_trees.composites.Sequence(name="sqli", memory=False)
    root.add_children([_SqliLeaf(pctx)])
    return root


def run_sqli_playbook(pctx: SqliPlaybookContext) -> Status:
    tree = build_sqli_playbook(pctx)
    tree.tick_once()
    return tree.status


def _has_query(f: Fact) -> bool:
    return isinstance(f, HttpTransaction) and split_query_target(f.url) is not None


def sqli_rule() -> Rule:
    """SOCKET: a captured request that carries a query parameter (an injection point).
    TAB: a sqli hypothesis + a queued sqli_playbook task."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        txn = b["txn"]
        engine.assert_fact(Hypothesis(source="sqli_rule", claim="sqli", derived_from=[txn.id]))
        engine.assert_fact(
            Task(source="sqli_rule", playbook="sqli_playbook", derived_from=[txn.id])
        )

    return Rule(
        name="sqli_candidate",
        patterns=[Pattern(kind="http_txn", where=_has_query, as_="txn")],
        action=action,
    )


def dispatch_sqli_from_facts(
    bb: Blackboard,
    governor: Governor,
    validator: DeterministicValidator,
    hypothesis: Hypothesis,
    scope: RunScope | None = None,
) -> Status | None:
    """Resolve a parameterized target from captured traffic and run the boolean probe. ``None`` if
    no captured request carries an injectable query parameter."""
    for t in bb.query("http_txn"):
        if not isinstance(t, HttpTransaction):
            continue
        split = split_query_target(t.url)
        if split is None:
            continue
        _base, param, seed = split
        return run_sqli_playbook(SqliPlaybookContext(
            bb=bb, governor=governor, validator=validator, hypothesis=hypothesis,
            target_url=t.url, param=param, seed=seed, scope=scope,
        ))
    return None


def sqli_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: resolve the sqli hypothesis and dispatch the probe from the board."""
    hyp = next(
        (h for h in engine.bb.query("hypothesis")
         if isinstance(h, Hypothesis) and h.claim == "sqli"),
        None,
    )
    if hyp is None:
        return
    dispatch_sqli_from_facts(engine.bb, engine.governor, engine.validator, hyp, scope=engine.scope)
