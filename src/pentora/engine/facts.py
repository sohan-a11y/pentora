"""Blackboard fact schema for the Artifex reactive engine.

Every observation, hypothesis, and result is an immutable, typed ``Fact`` carrying
provenance (``source``, ``derived_from``) and a ``confidence`` score. Rules match on
``kind`` + fields (the socket); rules and primitives assert new Facts (the tab). Facts
are never mutated — a changed belief is a new Fact that supersedes the old one.

Depends only on stdlib + pydantic. No Experta/py_trees import here, so this module loads
cleanly in tests and CI regardless of the rules layer.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def new_id() -> str:
    """Short unique id for a fact."""
    return uuid.uuid4().hex[:12]


class Fact(BaseModel):
    """Base for everything on the blackboard: immutable + traceable."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=new_id)
    kind: str
    created_at: float = Field(default_factory=time.time)
    source: str = "unknown"                                   # primitive/rule that emitted it
    confidence: float = 1.0                                   # 0..1
    derived_from: list[str] = Field(default_factory=list)     # parent fact ids (provenance)


class Target(Fact):
    kind: Literal["target"] = "target"
    root: str
    scope_include: list[str] = Field(default_factory=list)
    scope_exclude: list[str] = Field(default_factory=list)


class HttpTransaction(Fact):
    """Raw captured request/response pair from the mitmproxy primitive."""

    kind: Literal["http_txn"] = "http_txn"
    method: str
    url: str
    req_headers: dict[str, str] = Field(default_factory=dict)
    req_body: str | None = None
    status: int = 0
    resp_headers: dict[str, str] = Field(default_factory=dict)
    resp_body_sha: str | None = None                       # body stored out-of-band by hash
    role_label: str | None = None                          # which test identity made it


class ObservedEndpoint(Fact):
    """A canonical application action (deduped, path-templated)."""

    kind: Literal["endpoint"] = "endpoint"
    method: str
    template: str                                             # /orders/{id}
    seen_count: int = 1
    auth_required: bool | None = None


class Parameter(Fact):
    """An input point with an inferred semantic type."""

    kind: Literal["parameter"] = "parameter"
    endpoint_id: str
    location: Literal["path", "query", "header", "body", "cookie"]
    name: str
    semantic: str | None = None                            # resource_id | price | email | token
    example_values: list[str] = Field(default_factory=list)


class SecurityContext(Fact):
    """An authenticated identity: role, token, cookies. The 'who am I' fact."""

    kind: Literal["security_context"] = "security_context"
    role_label: str                                           # visitor | user_a | user_b | admin
    rank: int = 0                                             # privilege ordering
    has_jwt: bool = False
    jwt: str | None = None
    cookies: dict[str, str] = Field(default_factory=dict)


class TechFingerprint(Fact):
    kind: Literal["tech"] = "tech"
    endpoint_id: str | None = None
    stack: list[str] = Field(default_factory=list)            # ["nginx", "express", "cloudflare"]
    waf: str | None = None


class AppIntentModel(Fact):
    """The reconstructed 'what this app is supposed to do' — the crown jewel."""

    kind: Literal["intent_model"] = "intent_model"
    roles: list[str] = Field(default_factory=list)
    ownership_rules: list[str] = Field(default_factory=list)
    workflow_states: list[str] = Field(default_factory=list)
    workflow_edges: list[tuple[str, str]] = Field(default_factory=list)


class Hypothesis(Fact):
    """A testable security claim + which primitive can test it."""

    kind: Literal["hypothesis"] = "hypothesis"
    claim: str                                               # "idor" | "jwt_forge" | "sqli" ...
    target_endpoint_id: str | None = None
    suggested_primitive: str | None = None
    priority: int = 5


class AttackAttempt(Fact):
    """A recorded action taken by a playbook step, with evidence pointers."""

    kind: Literal["attempt"] = "attempt"
    hypothesis_id: str | None = None
    primitive: str
    request_ref: str | None = None
    response_ref: str | None = None
    outcome: Literal["success", "fail", "inconclusive"] = "inconclusive"


class Finding(Fact):
    """A CONFIRMED vulnerability. Only the deterministic validator may mint this."""

    kind: Literal["finding"] = "finding"
    title: str
    endpoint_id: str | None = None
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = "info"
    evidence: str = ""
    poc: str = ""
    chain: list[str] = Field(default_factory=list)           # fact ids forming the kill chain


class TestedNegative(Fact):
    """A recorded dead-end: tested X, NOT vulnerable. Provable coverage."""

    __test__ = False  # stop pytest from collecting this domain class as a test

    kind: Literal["tested_negative"] = "tested_negative"
    what: str
    endpoint_id: str | None = None
    reason: str = ""


class Task(Fact):
    """Engine control fact: a queued/running playbook with a budget + depth guard."""

    kind: Literal["task"] = "task"
    playbook: str
    args: dict[str, Any] = Field(default_factory=dict)
    status: Literal["queued", "running", "done", "cancelled"] = "queued"
    budget_requests: int = 200
    depth: int = 0                                            # chain depth, runaway protection


class Secret(Fact):
    kind: Literal["secret"] = "secret"
    kind_of: str                                             # aws_key | jwt | api_key
    endpoint_id: str | None = None
    redacted: str = ""                                       # never store the raw secret


FACT_TYPES: dict[str, type[Fact]] = {
    "target": Target,
    "http_txn": HttpTransaction,
    "endpoint": ObservedEndpoint,
    "parameter": Parameter,
    "security_context": SecurityContext,
    "tech": TechFingerprint,
    "intent_model": AppIntentModel,
    "hypothesis": Hypothesis,
    "attempt": AttackAttempt,
    "finding": Finding,
    "tested_negative": TestedNegative,
    "task": Task,
    "secret": Secret,
}
