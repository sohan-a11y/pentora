"""The Deterministic Validator — the load-bearing reliability layer.

Principle (XBOW's deterministic validators; LogicScan's noise-aware aggregation): the LLM
PROPOSES hypotheses; a deterministic, evidence-driven check DISPOSES. A ``Hypothesis`` becomes
a ``Finding`` ONLY when a class-specific predicate confirms it against concrete, reproducible
evidence — leaked bytes that provably belong to another user, a forged token that actually
grants access, a measurable injection signal. Never on the model's opinion. Anything short of
proof becomes a ``TestedNegative`` (recorded coverage) or ``None`` (escalate to human review).

The validator is deterministic: same evidence in, same verdict out. The LLM is nowhere in
this path — that separation is the whole reason findings are trustworthy.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import StrEnum
from typing import Any

from pentora.engine.facts import Finding, Hypothesis, TestedNegative

try:  # reuse the tested CVSS calculator from the core package
    from pentora.finding import CVSS

    def _cvss(vector: str) -> tuple[str, float, str]:
        c = CVSS.from_vector(vector)
        return c.vector, c.score, c.severity.value
except Exception:  # pragma: no cover - engine can run standalone
    def _cvss(vector: str) -> tuple[str, float, str]:
        return vector, 0.0, "info"


class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ValidationResult:
    verdict: Verdict
    rationale: str
    cvss_vector: str = ""
    poc: str = ""
    evidence_ids: list[str] = field(default_factory=list)


def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()


class ValidatorStrategy(ABC):
    """One deterministic proof predicate per vulnerability class."""

    claim: str

    @abstractmethod
    def validate(self, hypo: Hypothesis, ev: dict[str, Any]) -> ValidationResult: ...


class IdorValidator(ValidatorStrategy):
    """Confirmed only if a value provably owned by the victim is returned to the attacker
    session AND absent from a control request AND the leak reproduced."""

    claim = "idor"
    MIN_REPRO = 2

    def validate(self, hypo: Hypothesis, ev: dict[str, Any]) -> ValidationResult:
        marker = str(ev.get("victim_marker", ""))
        attack = str(ev.get("attacker_response_body", ""))
        control = str(ev.get("attacker_control_body", ""))
        reps = int(ev.get("repetitions", 0))
        ids = list(ev.get("evidence_ids", []))
        if not marker:
            return ValidationResult(Verdict.INCONCLUSIVE, "no distinguishing victim marker")
        leaked = marker in attack
        control_clean = marker not in control
        if leaked and control_clean and reps >= self.MIN_REPRO:
            return ValidationResult(
                Verdict.CONFIRMED,
                f"victim marker '{marker[:16]}' returned to attacker session {reps}x; "
                "absent in control",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                poc="As user_b, request user_a's resource; response contains user_a's data.",
                evidence_ids=ids,
            )
        if not leaked:
            return ValidationResult(Verdict.REFUTED, "victim marker absent from attacker response")
        return ValidationResult(
            Verdict.INCONCLUSIVE, "leak unstable, or control also contained the marker"
        )


class JwtForgeValidator(ValidatorStrategy):
    """Confirmed only by ACCESS: the forged token is accepted where the low-priv token is denied."""

    claim = "jwt_forge"

    def validate(self, hypo: Hypothesis, ev: dict[str, Any]) -> ValidationResult:
        forged_ok = bool(ev.get("forged_token_authorized"))
        original_denied = not bool(ev.get("original_token_authorized"))
        marker = bool(ev.get("authorized_marker_present"))
        ids = list(ev.get("evidence_ids", []))
        if forged_ok and original_denied and marker:
            return ValidationResult(
                Verdict.CONFIRMED,
                "forged token granted access the low-priv token was denied",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                poc="Forge a token via the recovered weak secret; replay to a protected endpoint.",
                evidence_ids=ids,
            )
        if not forged_ok:
            return ValidationResult(Verdict.REFUTED, "forged token was not accepted")
        return ValidationResult(Verdict.INCONCLUSIVE, "forged accepted but original not denied")


class SqliValidator(ValidatorStrategy):
    """Confirmed by a reproducible signal: boolean divergence or an injected time delay —
    not by trusting a scanner's word."""

    claim = "sqli"
    BOOL_DIVERGENCE = 0.15
    TIME_FACTOR = 0.8

    def validate(self, hypo: Hypothesis, ev: dict[str, Any]) -> ValidationResult:
        ids = list(ev.get("evidence_ids", []))
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if ev.get("mode") == "time":
            base = float(ev.get("baseline_ms", 0))
            delayed = float(ev.get("delayed_ms", 0))
            expected = float(ev.get("expected_delay_ms", 5000))
            reps = int(ev.get("repetitions", 0))
            if delayed - base >= expected * self.TIME_FACTOR and reps >= 2:
                return ValidationResult(
                    Verdict.CONFIRMED,
                    f"time-based delay {int(delayed - base)}ms matches injected "
                    f"{int(expected)}ms, {reps}x",
                    cvss_vector=vector,
                    poc="Inject a time-delay payload; response stalls by the injected interval.",
                    evidence_ids=ids,
                )
            return ValidationResult(Verdict.REFUTED, "no reproducible injected delay")
        t = _sim(str(ev.get("true_resp", "")), str(ev.get("control_resp", "")))
        f = _sim(str(ev.get("false_resp", "")), str(ev.get("control_resp", "")))
        if t - f >= self.BOOL_DIVERGENCE:
            return ValidationResult(
                Verdict.CONFIRMED,
                f"boolean divergence: true~control={t:.2f}, false~control={f:.2f}",
                cvss_vector=vector,
                poc="TRUE and FALSE conditions yield distinct responses (boolean-based SQLi).",
                evidence_ids=ids,
            )
        return ValidationResult(Verdict.REFUTED, "no boolean divergence (true vs false)")


class DeterministicValidator:
    """Registry + promotion. ``promote`` returns the fact to assert on the blackboard."""

    def __init__(self) -> None:
        self._strats: dict[str, ValidatorStrategy] = {}
        for s in (IdorValidator(), JwtForgeValidator(), SqliValidator()):
            self.register(s)

    def register(self, strat: ValidatorStrategy) -> None:
        self._strats[strat.claim] = strat

    def judge(self, hypo: Hypothesis, ev: dict[str, Any]) -> ValidationResult:
        strat = self._strats.get(hypo.claim)
        if strat is None:
            return ValidationResult(
                Verdict.INCONCLUSIVE, f"no validator for claim '{hypo.claim}' — escalate to human"
            )
        return strat.validate(hypo, ev)

    def promote(
        self, hypo: Hypothesis, ev: dict[str, Any]
    ) -> Finding | TestedNegative | None:
        """CONFIRMED -> Finding; REFUTED -> TestedNegative; INCONCLUSIVE -> None (human review)."""
        r = self.judge(hypo, ev)
        if r.verdict is Verdict.CONFIRMED:
            vector, score, sev = _cvss(r.cvss_vector) if r.cvss_vector else ("", 0.0, "info")
            return Finding(
                source="validator",
                derived_from=[hypo.id, *r.evidence_ids],
                title=hypo.claim.upper(),
                endpoint_id=hypo.target_endpoint_id,
                cvss_vector=vector,
                cvss_score=score,
                severity=sev,
                evidence=r.rationale,
                poc=r.poc,
                chain=[hypo.id, *r.evidence_ids],
            )
        if r.verdict is Verdict.REFUTED:
            return TestedNegative(
                source="validator",
                derived_from=[hypo.id],
                what=hypo.claim,
                endpoint_id=hypo.target_endpoint_id,
                reason=r.rationale,
            )
        return None
