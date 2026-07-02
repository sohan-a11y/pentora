"""Artifex reactive engine: Blackboard + typed Facts + Primitive contract + Validator.

The core (facts, primitive, blackboard, validator, ollama_client) depends only on stdlib +
pydantic, so it imports cleanly in tests and CI. The rules layer (Experta or a custom
forward-chainer) and playbooks (py_trees) sit on top and are wired separately — keeping the
heavy/unmaintained deps out of the importable core.
"""
from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import (
    FACT_TYPES,
    AppIntentModel,
    AttackAttempt,
    Fact,
    Finding,
    HttpTransaction,
    Hypothesis,
    ObservedEndpoint,
    Parameter,
    Secret,
    SecurityContext,
    Target,
    Task,
    TechFingerprint,
    TestedNegative,
    new_id,
)
from pentora.engine.ollama_client import OllamaClassifier, smoke_test
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Governor,
    GovernorDecision,
    Primitive,
    PrimitiveResult,
    RunContext,
    RunScope,
    ScopeViolation,
)
from pentora.engine.validator import (
    DeterministicValidator,
    IdorValidator,
    JwtForgeValidator,
    SqliValidator,
    ValidationResult,
    ValidatorStrategy,
    Verdict,
)

__all__ = [
    "FACT_TYPES",
    "AppIntentModel",
    "AttackAttempt",
    "Blackboard",
    "BlastRadius",
    "Capability",
    "DeterministicValidator",
    "Fact",
    "Finding",
    "Governor",
    "GovernorDecision",
    "HttpTransaction",
    "Hypothesis",
    "IdorValidator",
    "JwtForgeValidator",
    "ObservedEndpoint",
    "OllamaClassifier",
    "Parameter",
    "Primitive",
    "PrimitiveResult",
    "RunContext",
    "RunScope",
    "ScopeViolation",
    "Secret",
    "SecurityContext",
    "SqliValidator",
    "Target",
    "Task",
    "TechFingerprint",
    "TestedNegative",
    "ValidationResult",
    "ValidatorStrategy",
    "Verdict",
    "new_id",
    "smoke_test",
]
