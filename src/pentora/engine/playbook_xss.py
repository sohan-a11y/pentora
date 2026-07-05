"""XSS playbook — reflection vs. execution, proven by a byte-exact unescaped round-trip.

Reflection payloads come from the RAG ``PayloadOracle``, each carrying a unique marker. The
playbook injects them one at a time through the Governor and hands the response body + content-type
to the deterministic ``XssValidator``, which confirms ONLY when the markup is returned VERBATIM in
an HTML context (would execute) — not when it is reflected but HTML-escaped. We stop at the first
payload that executes; if none do, the escaped/absent result is recorded as provable coverage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status

from pentora.engine.asyncrun import run_sync
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
class XssPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    target_url: str
    param: str
    token: str | None = None
    scope: RunScope | None = None

    @property
    def marker(self) -> str:
        """A unique, deterministic reflection marker tied to this hypothesis."""
        return f"pentoraXSS{self.hypothesis.id[:8]}()"

    def effective_scope(self) -> RunScope:
        """Fall back to the target host — never an empty (allow-all) scope — when none is given."""
        if self.scope is not None:
            return self.scope
        host = urlsplit(self.target_url).hostname or self.target_url
        return RunScope(include=[host], read_only=True)

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="xss_playbook", what=what, derived_from=[self.hypothesis.id])
        )


def _replay(pctx: XssPlaybookContext, url: str, role: str) -> tuple[str, str]:
    scope = pctx.effective_scope()
    res = run_sync(
        pctx.governor.execute(
            HttpReplayPrimitive(),
            ReplayInput(url=url, token=pctx.token, role_label=role),
            RunContext(scope=scope, budget_requests=50),
        )
    )
    for f in res.facts:
        pctx.bb.assert_fact(f)
    return str(res.data.get("body", "")), str(res.data.get("content_type", ""))


class _XssLeaf(Behaviour):
    def __init__(self, pctx: XssPlaybookContext) -> None:
        super().__init__("xss_reflection")
        self.pctx = pctx

    def update(self) -> Status:
        p = self.pctx
        last_fact: Fact | None = None
        for payload in PayloadOracle().xss_reflection(p.marker):
            url = inject_param(p.target_url, p.param, payload.value)
            body, ctype = _replay(p, url, "xss")
            fact = p.validator.promote(p.hypothesis, {
                "payload": payload.value,
                "body": body,
                "content_type": ctype,
                "evidence_ids": [],
            })
            if fact is not None and fact.kind == "finding":
                p.bb.assert_fact(fact)
                return Status.SUCCESS
            last_fact = fact
        if last_fact is not None:
            p.bb.assert_fact(last_fact)                 # record the escaped/absent coverage
        else:
            p.record_negative("xss inconclusive")
        return Status.FAILURE


def build_xss_playbook(pctx: XssPlaybookContext) -> Behaviour:
    root = py_trees.composites.Sequence(name="xss", memory=False)
    root.add_children([_XssLeaf(pctx)])
    return root


def run_xss_playbook(pctx: XssPlaybookContext) -> Status:
    tree = build_xss_playbook(pctx)
    tree.tick_once()
    return tree.status


def _has_query(f: Fact) -> bool:
    return isinstance(f, HttpTransaction) and split_query_target(f.url) is not None


def xss_rule() -> Rule:
    """SOCKET: a captured request with a query parameter (a reflection surface).
    TAB: an xss hypothesis + a queued xss_playbook task."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        txn = b["txn"]
        engine.assert_fact(Hypothesis(source="xss_rule", claim="xss", derived_from=[txn.id]))
        engine.assert_fact(Task(source="xss_rule", playbook="xss_playbook", derived_from=[txn.id]))

    return Rule(
        name="xss_candidate",
        patterns=[Pattern(kind="http_txn", where=_has_query, as_="txn")],
        action=action,
    )


def dispatch_xss_from_facts(
    bb: Blackboard,
    governor: Governor,
    validator: DeterministicValidator,
    hypothesis: Hypothesis,
    scope: RunScope | None = None,
) -> Status | None:
    """Resolve a reflection surface from captured traffic and run the probe. ``None`` if no
    captured request carries an injectable query parameter."""
    for t in bb.query("http_txn"):
        if not isinstance(t, HttpTransaction):
            continue
        split = split_query_target(t.url)
        if split is None:
            continue
        _base, param, _seed = split
        return run_xss_playbook(XssPlaybookContext(
            bb=bb, governor=governor, validator=validator, hypothesis=hypothesis,
            target_url=t.url, param=param, scope=scope,
        ))
    return None


def xss_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: resolve the xss hypothesis and dispatch the probe from the board."""
    hyp = next(
        (h for h in engine.bb.query("hypothesis")
         if isinstance(h, Hypothesis) and h.claim == "xss"),
        None,
    )
    if hyp is None:
        return
    dispatch_xss_from_facts(engine.bb, engine.governor, engine.validator, hyp, scope=engine.scope)
