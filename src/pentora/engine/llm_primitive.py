"""LLM classifier primitive — the fuzzy layer of the engine.

The local model PROPOSES hypotheses the deterministic rules can't anticipate (PII/sensitive-data
leaks, stack-trace disclosure, business-logic smells). It only ever emits a ``Hypothesis`` fact;
the deterministic Validator still disposes, so a hallucination can never become a Finding on its
own — the LLM is on the proposal path, never the promotion path.

``blast_radius=PASSIVE``: it calls the LOCAL Ollama server, never the target, so the Governor's
target-request budget and rate limiter (which govern target traffic) correctly don't apply.
LLM-cost throttling, if wanted, is a separate concern and not conflated with target budget.

Never crashes the engine on bad model output: transport errors, non-JSON, and schema drift all
degrade to an ``is_error`` result with no facts.
"""
from __future__ import annotations

import asyncio
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from pentora.engine.facts import HttpTransaction, Hypothesis
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Primitive,
    PrimitiveResult,
    RunContext,
)


@runtime_checkable
class Classifier(Protocol):
    """Structural type for anything that classifies (OllamaClassifier or a test double)."""

    def classify(self, system: str, user: str) -> dict[str, Any]: ...


_SYSTEM = (
    "You are a strict web-security classifier. Given one HTTP response, decide if it exposes a "
    "vulnerability (sensitive-data/PII leak, stack-trace or error disclosure, or a business-logic "
    "smell). Output ONLY this JSON object — no prose, no markdown:\n"
    '{"is_vulnerable": true|false, "vuln_type": "<snake_case>", '
    '"severity_score": <int 1-10>, "reasoning": "<=15 words"}'
)

_RELEVANT_STATUS = (200, 403, 500)


def _clamp_priority(score: Any) -> int:
    try:
        return max(1, min(10, int(score)))
    except (TypeError, ValueError):
        return 5


class LlmClassifierPrimitive(Primitive):
    name = "llm_classifier"
    version = "0.1"
    input_schema = HttpTransaction
    capability = Capability(
        read_only=True,
        destructive=False,
        idempotent=True,
        blast_radius=BlastRadius.PASSIVE,   # calls local Ollama, not the target
        est_requests=0,
    )

    def __init__(self, ollama: Classifier) -> None:
        self.ollama = ollama

    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        if not isinstance(inp, HttpTransaction):
            return PrimitiveResult(summary="bad input", is_error=True)
        if inp.status not in _RELEVANT_STATUS:
            return PrimitiveResult(summary=f"skipped: status {inp.status} not relevant")
        try:
            analysis = await asyncio.to_thread(self.ollama.classify, _SYSTEM, self._user_msg(inp))
        except Exception as e:  # noqa: BLE001 - never crash the engine on bad LLM output
            return PrimitiveResult(summary=f"LLM classify failed: {e}", is_error=True)
        if not isinstance(analysis, dict):
            return PrimitiveResult(summary="LLM returned non-object JSON", is_error=True)
        if not analysis.get("is_vulnerable"):
            return PrimitiveResult(summary="LLM classified transaction as benign")
        hyp = Hypothesis(
            id=f"hyp_llm_{inp.id}",                 # deterministic -> idempotent per transaction
            source="qwen_local_classifier",
            claim=str(analysis.get("vuln_type") or "unknown_heuristic_flaw"),
            priority=_clamp_priority(analysis.get("severity_score")),
            derived_from=[inp.id],
        )
        return PrimitiveResult(facts=[hyp], summary=f"LLM hypothesis: {hyp.claim}")

    @staticmethod
    def _user_msg(tx: HttpTransaction) -> str:
        body = (tx.resp_body_snippet or "")[:1000]
        return f"URL: {tx.url}\nStatus: {tx.status}\nBody:\n{body}"
