"""IDOR / BOLA playbook — proves the Blackboard pattern generalizes past JWT.

Reuses the exact ``HttpReplayPrimitive`` as the JWT chain, but across two role tokens:

  1. victim token @ victim's own resource      -> establishes what the victim's data looks like
  2. attacker token @ attacker's own resource   -> control (what the attacker is meant to see)
  3. attacker token @ VICTIM's resource (x2)     -> the attack

If the attacker's response to the victim's resource carries a value that provably belongs to the
victim (present in the victim baseline, absent from the attacker's control) and it reproduces,
the deterministic ``IdorValidator`` promotes the Finding. All requests go through the Governor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status

from pentora.engine.asyncrun import run_sync
from pentora.engine.blackboard import Blackboard
from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import (
    Fact,
    HttpTransaction,
    Hypothesis,
    ObservedEndpoint,
    SecurityContext,
    Task,
    TestedNegative,
)
from pentora.engine.primitive import Governor, RunContext, RunScope
from pentora.engine.replay import HttpReplayPrimitive, ReplayInput
from pentora.engine.validator import DeterministicValidator

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine

_TOKEN_RE = re.compile(r"[A-Za-z0-9_@.:-]{4,}")


@dataclass
class IdorPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    victim_url: str
    victim_token: str
    attacker_token: str
    attacker_own_url: str
    scope: RunScope | None = None

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="idor_playbook", what=what, derived_from=[self.hypothesis.id])
        )


def _replay(pctx: IdorPlaybookContext, url: str, token: str, role: str) -> tuple[int, str]:
    scope = pctx.scope or RunScope(read_only=True)
    res = run_sync(
        pctx.governor.execute(
            HttpReplayPrimitive(),
            ReplayInput(url=url, token=token, role_label=role),
            RunContext(scope=scope, budget_requests=50),
        )
    )
    for f in res.facts:
        pctx.bb.assert_fact(f)
    return int(res.data.get("status", 0)), str(res.data.get("body", ""))


def _distinguishing_marker(victim_body: str, control_body: str) -> str:
    """A token present in the victim's data but not the attacker's own — the IDOR signal."""
    ctrl = set(_TOKEN_RE.findall(control_body))
    diff = [w for w in _TOKEN_RE.findall(victim_body) if w not in ctrl]
    return max(diff, key=len) if diff else victim_body.strip()


class _IdorLeaf(Behaviour):
    def __init__(self, pctx: IdorPlaybookContext) -> None:
        super().__init__("idor_cross_user")
        self.pctx = pctx

    def update(self) -> Status:
        p = self.pctx
        _, victim_body = _replay(p, p.victim_url, p.victim_token, "victim")
        _, control_body = _replay(p, p.attacker_own_url, p.attacker_token, "attacker_control")
        marker = _distinguishing_marker(victim_body, control_body)

        reps = 0
        attack_body = ""
        for _ in range(2):
            status, attack_body = _replay(p, p.victim_url, p.attacker_token, "attacker")
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
            p.record_negative("idor inconclusive")
            return Status.FAILURE
        p.bb.assert_fact(fact)
        return Status.SUCCESS if fact.kind == "finding" else Status.FAILURE


def build_idor_playbook(pctx: IdorPlaybookContext) -> Behaviour:
    root = py_trees.composites.Sequence(name="idor", memory=False)
    root.add_children([_IdorLeaf(pctx)])
    return root


def run_idor_playbook(pctx: IdorPlaybookContext) -> Status:
    tree = build_idor_playbook(pctx)
    tree.tick_once()
    return tree.status


def _has_jwt(f: Fact) -> bool:
    return isinstance(f, SecurityContext) and f.has_jwt


def _id_templated(f: Fact) -> bool:
    return isinstance(f, ObservedEndpoint) and "{id}" in f.template


def _distinct_roles(b: dict[str, Fact]) -> bool:
    a, other = b["a"], b["b"]
    if not isinstance(a, SecurityContext) or not isinstance(other, SecurityContext):
        return False
    return a.role_label < other.role_label   # canonical order -> fires once per pair


def idor_rule() -> Rule:
    """SOCKET: two distinct-role authenticated sessions + an id-templated endpoint.
    TAB: an idor hypothesis + a queued idor_playbook task."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        engine.assert_fact(Hypothesis(
            source="idor_rule", claim="idor", target_endpoint_id=b["ep"].id,
            derived_from=[b["a"].id, b["b"].id],
        ))
        engine.assert_fact(Task(
            source="idor_rule", playbook="idor_playbook", derived_from=[b["a"].id, b["b"].id],
        ))

    return Rule(
        name="idor_candidate",
        patterns=[
            Pattern(kind="security_context", where=_has_jwt, as_="a"),
            Pattern(kind="security_context", where=_has_jwt, as_="b"),
            Pattern(kind="endpoint", where=_id_templated, as_="ep"),
        ],
        join=_distinct_roles,
        action=action,
    )


def dispatch_idor_from_facts(
    bb: Blackboard,
    governor: Governor,
    validator: DeterministicValidator,
    hypothesis: Hypothesis,
    scope: RunScope | None = None,
) -> Status | None:
    """Build an IdorPlaybookContext from captured facts and run it. Returns None if the two
    role sessions and their own accessed resources can't be resolved from the blackboard."""
    by_role: dict[str, SecurityContext] = {}
    for f in bb.query("security_context"):
        if isinstance(f, SecurityContext) and f.has_jwt and f.jwt and f.role_label not in by_role:
            by_role[f.role_label] = f
    if len(by_role) < 2:
        return None
    roles = sorted(by_role)
    victim, attacker = by_role[roles[0]], by_role[roles[1]]

    def url_for(role: str) -> str | None:
        for t in bb.query("http_txn"):
            if isinstance(t, HttpTransaction) and t.role_label == role and t.url:
                return t.url
        return None

    victim_url = url_for(roles[0])
    attacker_url = url_for(roles[1])
    if not victim_url or not attacker_url or not victim.jwt or not attacker.jwt:
        return None
    return run_idor_playbook(IdorPlaybookContext(
        bb=bb, governor=governor, validator=validator, hypothesis=hypothesis,
        victim_url=victim_url, victim_token=victim.jwt, attacker_token=attacker.jwt,
        attacker_own_url=attacker_url, scope=scope,
    ))


def idor_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: resolve the idor hypothesis and dispatch the playbook from the board."""
    hyp = next(
        (h for h in engine.bb.query("hypothesis")
         if isinstance(h, Hypothesis) and h.claim == "idor"),
        None,
    )
    if hyp is None:
        return
    dispatch_idor_from_facts(engine.bb, engine.governor, engine.validator, hyp, scope=engine.scope)
