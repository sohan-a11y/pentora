"""BOLA playbook — Broken Object Level Authorization, the state-based cousin of IDOR.

The distinction from the path-guessing IDOR playbook is PROVENANCE: the object under test was
created by the victim in prior traffic (a captured write), and its id + secret are STATE we
observed, not a value we guessed. The attack itself is a safe read: the attacker's session GETs
the victim's object id. If the victim's secret comes back to the attacker (present in the attack
response, absent from the attacker's own object) and it reproduces, the ``BolaValidator`` promotes
the Finding. Object creation is never performed by the engine — writes come from observed traffic,
so the engine stays read-only. All attack requests go through the Governor.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status

from pentora.engine.blackboard import Blackboard
from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import (
    Fact,
    HttpTransaction,
    Hypothesis,
    SecurityContext,
    Task,
    TestedNegative,
)
from pentora.engine.playbook_idor import _distinguishing_marker
from pentora.engine.primitive import Governor, RunContext, RunScope
from pentora.engine.replay import HttpReplayPrimitive, ReplayInput
from pentora.engine.validator import DeterministicValidator

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine

_WRITE_METHODS = {"POST", "PUT", "PATCH"}


@dataclass
class BolaPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    object_url: str                                     # victim-created object (a captured write)
    victim_body: str                                    # the victim object's bytes, from that write
    attacker_token: str
    attacker_control_url: str                           # the attacker's OWN object (control)
    scope: RunScope | None = None

    def effective_scope(self) -> RunScope:
        """Fall back to the object host — never an empty (allow-all) scope — when none is given."""
        if self.scope is not None:
            return self.scope
        host = urlsplit(self.object_url).hostname or self.object_url
        return RunScope(include=[host], read_only=True)

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="bola_playbook", what=what, derived_from=[self.hypothesis.id])
        )


def _replay(pctx: BolaPlaybookContext, url: str, token: str, role: str) -> tuple[int, str]:
    scope = pctx.effective_scope()
    res = asyncio.run(
        pctx.governor.execute(
            HttpReplayPrimitive(),
            ReplayInput(url=url, token=token, role_label=role),
            RunContext(scope=scope, budget_requests=50),
        )
    )
    for f in res.facts:
        pctx.bb.assert_fact(f)
    return int(res.data.get("status", 0)), str(res.data.get("body", ""))


class _BolaLeaf(Behaviour):
    def __init__(self, pctx: BolaPlaybookContext) -> None:
        super().__init__("bola_cross_object")
        self.pctx = pctx

    def update(self) -> Status:
        p = self.pctx
        # Control: the attacker reads their OWN object — what they are meant to see.
        _, control_body = _replay(p, p.attacker_control_url, p.attacker_token, "bola_control")
        # Distill a compact victim-only token from the observed object bytes, so the proof
        # survives field reordering / formatting differences between the write and the read.
        marker = _distinguishing_marker(p.victim_body, control_body)

        reps = 0
        attack_body = ""
        for _ in range(2):
            status, attack_body = _replay(p, p.object_url, p.attacker_token, "bola_attacker")
            if status == 200 and marker in attack_body:
                reps += 1

        fact = p.validator.promote(p.hypothesis, {
            "victim_marker": marker,
            "attacker_response_body": attack_body,
            "attacker_control_body": control_body,
            "repetitions": reps,
            "evidence_ids": [],
        })
        if fact is None:
            p.record_negative("bola inconclusive")
            return Status.FAILURE
        p.bb.assert_fact(fact)
        return Status.SUCCESS if fact.kind == "finding" else Status.FAILURE


def build_bola_playbook(pctx: BolaPlaybookContext) -> Behaviour:
    root = py_trees.composites.Sequence(name="bola", memory=False)
    root.add_children([_BolaLeaf(pctx)])
    return root


def run_bola_playbook(pctx: BolaPlaybookContext) -> Status:
    tree = build_bola_playbook(pctx)
    tree.tick_once()
    return tree.status


def _is_write(f: Fact) -> bool:
    return isinstance(f, HttpTransaction) and f.method.upper() in _WRITE_METHODS


def _has_jwt(f: Fact) -> bool:
    return isinstance(f, SecurityContext) and f.has_jwt


def bola_rule() -> Rule:
    """SOCKET: an observed object-creating WRITE + two distinct authenticated roles.
    TAB: a bola hypothesis + a queued bola_playbook task. The write is the state that makes
    this BOLA rather than a blind IDOR guess."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        engine.assert_fact(Hypothesis(
            source="bola_rule", claim="bola", derived_from=[b["write"].id, b["a"].id, b["b"].id],
        ))
        engine.assert_fact(Task(
            source="bola_rule", playbook="bola_playbook",
            derived_from=[b["write"].id, b["a"].id, b["b"].id],
        ))

    def _distinct(b: dict[str, Fact]) -> bool:
        a, other = b["a"], b["b"]
        if not isinstance(a, SecurityContext) or not isinstance(other, SecurityContext):
            return False
        return a.role_label < other.role_label

    return Rule(
        name="bola_candidate",
        patterns=[
            Pattern(kind="http_txn", where=_is_write, as_="write"),
            Pattern(kind="security_context", where=_has_jwt, as_="a"),
            Pattern(kind="security_context", where=_has_jwt, as_="b"),
        ],
        join=_distinct,
        action=action,
    )


def dispatch_bola_from_facts(
    bb: Blackboard,
    governor: Governor,
    validator: DeterministicValidator,
    hypothesis: Hypothesis,
    scope: RunScope | None = None,
) -> Status | None:
    """Reconstruct a BOLA probe from captured state: a victim WRITE (object url + secret marker in
    its snippet), the attacker's own object read (control), and the attacker session token.
    ``None`` if that state can't be resolved from the blackboard."""
    contexts: dict[str, SecurityContext] = {}
    for f in bb.query("security_context"):
        if isinstance(f, SecurityContext) and f.has_jwt and f.jwt and f.role_label not in contexts:
            contexts[f.role_label] = f
    if len(contexts) < 2:
        return None
    roles = sorted(contexts)
    victim_role, attacker_role = roles[0], roles[1]

    write = next(
        (t for t in bb.query("http_txn")
         if isinstance(t, HttpTransaction) and _is_write(t)
         and t.role_label == victim_role and t.resp_body_snippet),
        None,
    )
    control = next(
        (t for t in bb.query("http_txn")
         if isinstance(t, HttpTransaction) and t.role_label == attacker_role and t.url),
        None,
    )
    attacker = contexts[attacker_role]
    if write is None or control is None or not attacker.jwt or not write.resp_body_snippet:
        return None
    return run_bola_playbook(BolaPlaybookContext(
        bb=bb, governor=governor, validator=validator, hypothesis=hypothesis,
        object_url=write.url, victim_body=write.resp_body_snippet,
        attacker_token=attacker.jwt, attacker_control_url=control.url, scope=scope,
    ))


def bola_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: resolve the bola hypothesis and dispatch the probe from the board."""
    hyp = next(
        (h for h in engine.bb.query("hypothesis")
         if isinstance(h, Hypothesis) and h.claim == "bola"),
        None,
    )
    if hyp is None:
        return
    dispatch_bola_from_facts(engine.bb, engine.governor, engine.validator, hyp, scope=engine.scope)
