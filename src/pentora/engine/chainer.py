"""Native forward-chaining rule engine — Artifex owns this logic loop, no Experta.

A rule is a set of *sockets* (``Pattern`` objects that match facts on the blackboard) plus an
*action* (the *tab* — it asserts new facts). Asserting a fact can satisfy other rules, so the
kill chain self-assembles. Every binding fires at most once (dedup by rule + matched fact ids),
and a hard ``max_firings`` cap makes runaway chaining impossible — the governor principle applied
at the rule layer.

Depends only on stdlib + the engine's own facts/blackboard. ~110 lines, fully testable.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import Fact


def _always(_f: Fact) -> bool:
    return True


@dataclass
class Pattern:
    """One socket: a fact ``kind`` + an optional field predicate, bound to a name."""

    kind: str
    where: Callable[[Fact], bool] = field(default=_always)
    as_: str = ""

    def bind_name(self) -> str:
        return self.as_ or self.kind


@dataclass
class Rule:
    """A rule = sockets (patterns) + an optional cross-fact ``join`` + an ``action`` (the tab).

    ``action(engine, binding)`` receives the RuleEngine and a dict {bind_name: Fact}; it asserts
    new facts via ``engine.assert_fact(...)``. ``join(binding)`` checks constraints that span the
    matched facts (e.g. two SecurityContexts with different roles).
    """

    name: str
    patterns: list[Pattern]
    action: Callable[[RuleEngine, dict[str, Fact]], None]
    join: Callable[[dict[str, Fact]], bool] | None = None
    priority: int = 0


class RuleEngine:
    def __init__(self, blackboard: Blackboard, max_firings: int = 10_000) -> None:
        self.bb = blackboard
        self.rules: list[Rule] = []
        self.firings = 0
        self.max_firings = max_firings
        self._fired: set[tuple[str, tuple[str, ...]]] = set()

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)
        self.rules.sort(key=lambda r: -r.priority)   # higher priority fires first

    def assert_fact(self, fact: Fact) -> Fact:
        return self.bb.assert_fact(fact)

    def _match(self, rule: Rule) -> list[dict[str, Fact]]:
        """All combinations of facts that satisfy every pattern + the join (nested-loop join)."""
        bindings: list[dict[str, Fact]] = [{}]
        for p in rule.patterns:
            candidates = [f for f in self.bb.query(p.kind) if p.where(f)]
            nxt: list[dict[str, Fact]] = []
            for b in bindings:
                used = {f.id for f in b.values()}
                for f in candidates:
                    if f.id in used:                 # one fact can't fill two sockets
                        continue
                    nb = dict(b)
                    nb[p.bind_name()] = f
                    nxt.append(nb)
            bindings = nxt
            if not bindings:
                return []
        if rule.join is not None:
            bindings = [b for b in bindings if rule.join(b)]
        return bindings

    def run_to_fixpoint(self) -> int:
        """Fire every newly-satisfied binding until nothing new fires (or the cap is hit).

        Returns the number of firings this call. Deterministic: same facts + rules -> same result.
        """
        total = 0
        changed = True
        while changed:
            changed = False
            for rule in self.rules:
                for b in self._match(rule):
                    key = (rule.name, tuple(sorted(f.id for f in b.values())))
                    if key in self._fired:
                        continue
                    self._fired.add(key)
                    rule.action(self, b)             # may assert facts -> new matches next pass
                    self.firings += 1
                    total += 1
                    changed = True
                    if self.firings >= self.max_firings:
                        return total
        return total
