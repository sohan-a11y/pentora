"""CartEngine — the autonomous loop that makes this a Continuous Automated Red Teaming engine.

The loop: run the forward-chainer to a fixpoint (rules fire, queue ``Task`` facts) -> dispatch
every queued Task to its registered playbook runner (which asserts new facts) -> repeat until no
new tasks fire. Newly asserted facts can trigger more rules, so a whole engagement self-drives
from a single seed. A global ``max_dispatches`` cap is the runaway guard.

Core-only (no py_trees): playbook runners are REGISTERED by the caller, so this module imports
cleanly without the optional playbook dependencies.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from pentora.engine.blackboard import Blackboard
from pentora.engine.chainer import RuleEngine
from pentora.engine.facts import Fact, Task
from pentora.engine.primitive import Governor, RunScope
from pentora.engine.validator import DeterministicValidator

Runner = Callable[["CartEngine", Task], None]


@dataclass
class CartEngine:
    bb: Blackboard
    chainer: RuleEngine
    governor: Governor
    validator: DeterministicValidator
    scope: RunScope | None = None
    config: dict[str, object] = field(default_factory=dict)
    max_dispatches: int = 100
    dispatches: int = 0
    _registry: dict[str, Runner] = field(default_factory=dict)
    _dispatched: set[str] = field(default_factory=set)

    def register(self, playbook: str, runner: Runner) -> None:
        self._registry[playbook] = runner

    def seed(self, fact: Fact) -> Fact:
        return self.bb.assert_fact(fact)

    def _pending(self) -> list[Task]:
        return [
            t
            for t in self.bb.query("task")
            if isinstance(t, Task)
            and t.id not in self._dispatched
            and t.playbook in self._registry
        ]

    def run(self) -> dict[str, int]:
        """Drive rules -> dispatch -> repeat until fixpoint or the cap. Returns a summary."""
        while self.dispatches < self.max_dispatches:
            self.chainer.run_to_fixpoint()
            pending = self._pending()
            if not pending:
                break
            for task in pending:
                if self.dispatches >= self.max_dispatches:
                    break
                self._dispatched.add(task.id)
                self.dispatches += 1
                self._registry[task.playbook](self, task)
        return {
            "findings": len(self.bb.query("finding")),
            "tested_negative": len(self.bb.query("tested_negative")),
            "dispatches": self.dispatches,
        }
