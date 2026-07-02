"""The Primitive contract + Governor.

Every tool — embedded (mitmproxy), built (repeater), or wrapped (sqlmap via JSON) — wears
the same uniform so the engine drives them identically and receives typed Facts, never
stdout. The Governor is the only path to running a primitive; it enforces scope, dry-run,
read-only, and request budget BEFORE a packet is sent.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from pentora.engine.facts import Fact


class BlastRadius(StrEnum):
    PASSIVE = "passive"                     # observe only, no packets to target
    ACTIVE_SAFE = "active_safe"             # sends requests, no state change
    ACTIVE_INTRUSIVE = "active_intrusive"   # may change target state (POST/DELETE)


class Capability(BaseModel):
    """Self-declared side-effect + cost profile. The metadata a raw CLI can never give."""

    read_only: bool                         # engine may run these concurrently
    destructive: bool                       # blocked in read-only scans
    idempotent: bool                        # safe to retry
    blast_radius: BlastRadius
    est_requests: int = 1                   # budgeted BEFORE firing
    rate_limit_rps: float = 5.0


class ScopeViolation(RuntimeError):
    """Raised when a primitive tries to touch a URL outside the engagement scope."""


@dataclass
class RunScope:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    read_only: bool = False

    def in_scope(self, url: str) -> bool:
        if any(x and x in url for x in self.exclude):
            return False
        if not self.include:
            return True
        return any(x in url for x in self.include)

    def assert_in_scope(self, url: str) -> None:
        if not self.in_scope(url):
            raise ScopeViolation(url)


@dataclass
class RunContext:
    """Everything a primitive is allowed to touch. Carries the safety envelope."""

    scope: RunScope
    budget_requests: int = 200
    dry_run: bool = False
    cancel: Any = None            # asyncio.Event or None — cooperative cancellation
    rate_limiter: Any = None
    llm: Any = None               # OllamaClassifier (routing/intent)
    rag: Any = None               # PayloadOracle (concrete payloads)
    blackboard: Any = None        # read sibling facts if needed

    def cancelled(self) -> bool:
        return bool(self.cancel is not None and self.cancel.is_set())


@dataclass
class PrimitiveResult:
    """Splits machine-facing facts from a human/LLM summary; carries error/partial state."""

    facts: list[Fact] = field(default_factory=list)
    summary: str = ""
    is_error: bool = False
    partial: bool = False          # cancelled/timed-out but returned results so far
    requests_made: int = 0
    duration_s: float = 0.0


class Primitive(ABC):
    """Base every primitive inherits. Identity + typed input + capability + async run."""

    name: str = "primitive"
    version: str = "0.1"
    input_schema: type[BaseModel] = BaseModel
    capability: Capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.PASSIVE
    )

    @abstractmethod
    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        """Do the work. MUST honor ctx.scope, ctx.dry_run, ctx.cancel, ctx.budget_requests."""

    async def stream(self, inp: BaseModel, ctx: RunContext) -> Any:
        """Optional: yield Facts as they land (long primitives). Default: batch then yield."""
        res = await self.run(inp, ctx)
        for f in res.facts:
            yield f


@dataclass
class GovernorDecision:
    allowed: bool
    reason: str = ""


class Governor:
    """Wraps every primitive execution. Non-negotiable safety layer."""

    def check(self, prim: Primitive, ctx: RunContext) -> GovernorDecision:
        cap = prim.capability
        if ctx.dry_run and cap.blast_radius != BlastRadius.PASSIVE:
            return GovernorDecision(False, f"dry-run: would run {prim.name}")
        if cap.destructive and ctx.scope.read_only:
            return GovernorDecision(
                False, f"blocked: {prim.name} is destructive in a read-only scan"
            )
        if cap.est_requests > ctx.budget_requests:
            return GovernorDecision(
                False,
                f"blocked: {prim.name} needs {cap.est_requests} > budget {ctx.budget_requests}",
            )
        return GovernorDecision(True)

    async def execute(
        self, prim: Primitive, inp: BaseModel, ctx: RunContext
    ) -> PrimitiveResult:
        decision = self.check(prim, ctx)
        if not decision.allowed:
            return PrimitiveResult(summary=decision.reason, is_error=True)
        t0 = time.monotonic()
        try:
            res = await prim.run(inp, ctx)
        except ScopeViolation as e:
            return PrimitiveResult(summary=f"scope violation: {e}", is_error=True)
        except Exception as e:  # noqa: BLE001 - isolate a misbehaving primitive
            return PrimitiveResult(summary=f"{prim.name} errored: {e}", is_error=True)
        if not res.duration_s:
            res.duration_s = time.monotonic() - t0
        ctx.budget_requests -= res.requests_made
        return res
