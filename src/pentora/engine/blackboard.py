"""The Blackboard — shared, append-only, typed fact store.

The engine's single source of truth. Rules subscribe to it; asserting a new fact wakes the
forward-chaining layer. Thread-safe (RLock) so a live-proxy ingestion thread can write facts
while the main thread drives the loop and reads.
"""
from __future__ import annotations

import threading
from collections.abc import Callable

from pentora.engine.facts import Fact


class Blackboard:
    def __init__(self) -> None:
        self._facts: dict[str, Fact] = {}
        self._by_kind: dict[str, list[str]] = {}
        self._by_dedup: dict[str, str] = {}                   # dedup_key -> fact id
        self._subs: list[Callable[[Fact], None]] = []
        self._lock = threading.RLock()

    def assert_fact(self, f: Fact) -> Fact:
        """Add a fact and notify subscribers. Idempotent by id AND by content ``dedup_key``.
        Thread-safe. Returns the stored fact (the existing one on a duplicate)."""
        with self._lock:
            if f.id in self._facts:
                return self._facts[f.id]
            existing = self._by_dedup.get(f.dedup_key)
            if existing is not None:
                return self._facts[existing]
            self._facts[f.id] = f
            self._by_dedup[f.dedup_key] = f.id
            self._by_kind.setdefault(f.kind, []).append(f.id)
            subs = list(self._subs)
        for cb in subs:                                       # fire outside the lock
            cb(f)
        return f

    def get(self, fact_id: str) -> Fact | None:
        with self._lock:
            return self._facts.get(fact_id)

    def query(self, kind: str, **where: object) -> list[Fact]:
        """All facts of a kind, optionally filtered by exact field match."""
        with self._lock:
            out = [self._facts[i] for i in self._by_kind.get(kind, [])]
        for k, v in where.items():
            out = [f for f in out if getattr(f, k, None) == v]
        return out

    def all(self) -> list[Fact]:
        with self._lock:
            return list(self._facts.values())

    def subscribe(self, cb: Callable[[Fact], None]) -> None:
        with self._lock:
            self._subs.append(cb)

    def __len__(self) -> int:
        with self._lock:
            return len(self._facts)
