"""The Blackboard — shared, append-only, typed fact store.

The engine's single source of truth. Rules subscribe to it; asserting a new fact wakes
the forward-chaining layer (that is what makes the kill chain self-assemble). Extends
Pentora's existing FindingsStore concept from findings to all fact kinds.
"""
from __future__ import annotations

from collections.abc import Callable

from pentora.engine.facts import Fact


class Blackboard:
    def __init__(self) -> None:
        self._facts: dict[str, Fact] = {}
        self._by_kind: dict[str, list[str]] = {}
        self._subs: list[Callable[[Fact], None]] = []

    def assert_fact(self, f: Fact) -> Fact:
        """Add a fact (idempotent by id) and notify subscribers. Returns the stored fact."""
        if f.id in self._facts:
            return self._facts[f.id]
        self._facts[f.id] = f
        self._by_kind.setdefault(f.kind, []).append(f.id)
        for cb in list(self._subs):
            cb(f)
        return f

    def get(self, fact_id: str) -> Fact | None:
        return self._facts.get(fact_id)

    def query(self, kind: str, **where: object) -> list[Fact]:
        """All facts of a kind, optionally filtered by exact field match."""
        out = [self._facts[i] for i in self._by_kind.get(kind, [])]
        for k, v in where.items():
            out = [f for f in out if getattr(f, k, None) == v]
        return out

    def all(self) -> list[Fact]:
        return list(self._facts.values())

    def subscribe(self, cb: Callable[[Fact], None]) -> None:
        """Register a callback fired on every newly asserted fact (the rules engine)."""
        self._subs.append(cb)

    def __len__(self) -> int:
        return len(self._facts)
