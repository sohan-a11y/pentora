"""Proof the native forward-chainer works: fire, join, dedup, chaining, runaway guard."""
from __future__ import annotations

from pentora.engine import Blackboard, Hypothesis, Parameter, SecurityContext, Task
from pentora.engine.chainer import Pattern, Rule, RuleEngine


def _jwt_rule() -> Rule:
    def action(eng: RuleEngine, b: dict) -> None:  # noqa: ANN001
        eng.assert_fact(Hypothesis(source="jwt_rule", claim="jwt_forge",
                                   derived_from=[b["sc"].id]))

    return Rule(
        name="jwt_seen",
        patterns=[Pattern(kind="security_context", where=lambda f: f.has_jwt, as_="sc")],
        action=action,
    )


def test_single_pattern_rule_fires() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(_jwt_rule())
    bb.assert_fact(SecurityContext(source="t", role_label="user_a", has_jwt=True))
    fired = eng.run_to_fixpoint()
    assert fired == 1
    hyps = bb.query("hypothesis", claim="jwt_forge")
    assert len(hyps) == 1
    assert hyps[0].derived_from  # provenance links back to the security context


def test_no_fire_when_predicate_false() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(_jwt_rule())
    bb.assert_fact(SecurityContext(source="t", role_label="user_a", has_jwt=False))
    assert eng.run_to_fixpoint() == 0
    assert bb.query("hypothesis") == []


def test_join_across_three_facts() -> None:
    """IDOR socket: an id-param endpoint + TWO distinct roles -> one hypothesis."""
    bb = Blackboard()
    eng = RuleEngine(bb)

    def action(eng: RuleEngine, b: dict) -> None:  # noqa: ANN001
        eng.assert_fact(Hypothesis(source="idor_rule", claim="idor",
                                   target_endpoint_id=b["p"].endpoint_id))

    rule = Rule(
        name="idor_candidate",
        patterns=[
            Pattern(kind="parameter", where=lambda f: f.semantic == "resource_id", as_="p"),
            Pattern(kind="security_context", where=lambda f: f.role_label == "user_a", as_="a"),
            Pattern(kind="security_context", where=lambda f: f.role_label == "user_b", as_="b"),
        ],
        action=action,
    )
    eng.add_rule(rule)
    bb.assert_fact(Parameter(source="t", endpoint_id="e1", location="path",
                             name="id", semantic="resource_id"))
    bb.assert_fact(SecurityContext(source="t", role_label="user_a"))
    bb.assert_fact(SecurityContext(source="t", role_label="user_b"))
    assert eng.run_to_fixpoint() == 1
    hyps = bb.query("hypothesis", claim="idor")
    assert len(hyps) == 1
    assert hyps[0].target_endpoint_id == "e1"


def test_no_fire_with_only_one_role() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)

    def action(eng: RuleEngine, b: dict) -> None:  # noqa: ANN001
        eng.assert_fact(Hypothesis(source="idor_rule", claim="idor"))

    rule = Rule(
        name="idor_candidate",
        patterns=[
            Pattern(kind="security_context", where=lambda f: f.role_label == "user_a", as_="a"),
            Pattern(kind="security_context", where=lambda f: f.role_label == "user_b", as_="b"),
        ],
        action=action,
    )
    eng.add_rule(rule)
    bb.assert_fact(SecurityContext(source="t", role_label="user_a"))  # only one role present
    assert eng.run_to_fixpoint() == 0


def test_dedup_no_double_fire() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(_jwt_rule())
    bb.assert_fact(SecurityContext(source="t", role_label="user_a", has_jwt=True))
    eng.run_to_fixpoint()
    # running again must not re-fire the same binding
    assert eng.run_to_fixpoint() == 0
    assert len(bb.query("hypothesis")) == 1


def test_chain_self_assembles_to_fixpoint() -> None:
    """Rule A emits a hypothesis; rule B fires on THAT hypothesis and emits a task.
    Nobody wired A to B — the shared blackboard did. One run() closes the whole chain."""
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(_jwt_rule())

    def to_task(eng: RuleEngine, b: dict) -> None:  # noqa: ANN001
        eng.assert_fact(Task(source="sched", playbook="jwt_playbook",
                             derived_from=[b["h"].id]))

    eng.add_rule(Rule(
        name="queue_jwt_playbook",
        patterns=[Pattern(kind="hypothesis", where=lambda f: f.claim == "jwt_forge", as_="h")],
        action=to_task,
    ))
    bb.assert_fact(SecurityContext(source="t", role_label="user_a", has_jwt=True))
    fired = eng.run_to_fixpoint()
    assert fired == 2                                   # jwt_seen -> queue_jwt_playbook
    assert bb.query("hypothesis", claim="jwt_forge")
    assert bb.query("task", playbook="jwt_playbook")


def test_runaway_guard_caps_infinite_chains() -> None:
    """A rule that always emits a fresh fact would loop forever — the cap stops it."""
    bb = Blackboard()
    eng = RuleEngine(bb, max_firings=25)

    def spawn(eng: RuleEngine, b: dict) -> None:  # noqa: ANN001
        eng.assert_fact(Task(source="loop", playbook="again"))   # new id each time -> re-triggers

    eng.add_rule(Rule(
        name="loop",
        patterns=[Pattern(kind="task", where=lambda f: f.playbook == "again", as_="t")],
        action=spawn,
    ))
    bb.assert_fact(Task(source="seed", playbook="again"))
    eng.run_to_fixpoint()               # must terminate, not hang
    assert eng.firings <= 25
