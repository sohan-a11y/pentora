"""Proof the Artifex reactive-engine core runs: facts, blackboard, governor, validator."""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from pentora.engine import (
    BlastRadius,
    Blackboard,
    Capability,
    DeterministicValidator,
    Finding,
    Governor,
    Hypothesis,
    Primitive,
    PrimitiveResult,
    RunContext,
    RunScope,
    SecurityContext,
    TestedNegative,
)


class _In(BaseModel):
    url: str = "https://x.com"


class PassivePrim(Primitive):
    name = "passive"
    capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.PASSIVE
    )

    async def run(self, inp, ctx):  # noqa: ANN001, ANN201
        return PrimitiveResult(
            facts=[SecurityContext(source=self.name, role_label="user_a")], summary="ok"
        )


class DestructivePrim(Primitive):
    name = "destructive"
    capability = Capability(
        read_only=False,
        destructive=True,
        idempotent=False,
        blast_radius=BlastRadius.ACTIVE_INTRUSIVE,
    )

    async def run(self, inp, ctx):  # noqa: ANN001, ANN201
        return PrimitiveResult(summary="deleted stuff")


def test_fact_provenance() -> None:
    sc = SecurityContext(source="t", role_label="user_a", derived_from=["abc"])
    assert sc.kind == "security_context"
    assert sc.confidence == 1.0
    assert sc.derived_from == ["abc"]
    assert sc.id  # auto-generated


def test_blackboard_assert_query_subscribe() -> None:
    bb = Blackboard()
    seen: list[str] = []
    bb.subscribe(lambda f: seen.append(f.kind))
    a = bb.assert_fact(SecurityContext(source="t", role_label="user_a"))
    bb.assert_fact(a)  # dedup by id
    assert len(bb) == 1
    assert len(seen) == 1
    assert bb.query("security_context", role_label="user_a")
    assert bb.query("security_context", role_label="nobody") == []


@pytest.mark.asyncio
async def test_governor_blocks_destructive_in_read_only() -> None:
    res = await Governor().execute(DestructivePrim(), _In(), RunContext(scope=RunScope(read_only=True)))
    assert res.is_error
    assert "destructive" in res.summary


@pytest.mark.asyncio
async def test_governor_allows_passive() -> None:
    res = await Governor().execute(PassivePrim(), _In(), RunContext(scope=RunScope(read_only=True)))
    assert not res.is_error
    assert res.facts and res.facts[0].kind == "security_context"


@pytest.mark.asyncio
async def test_governor_dry_run_blocks_active() -> None:
    res = await Governor().execute(DestructivePrim(), _In(), RunContext(scope=RunScope(), dry_run=True))
    assert res.is_error
    assert "dry-run" in res.summary


@pytest.mark.asyncio
async def test_governor_blocks_over_budget() -> None:
    ctx = RunContext(scope=RunScope(), budget_requests=0)
    res = await Governor().execute(PassivePrim(), _In(), ctx)
    # passive est_requests default is 1 > budget 0
    assert res.is_error
    assert "budget" in res.summary


def test_validator_confirms_idor() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="idor", target_endpoint_id="e1")
    ev = {
        "victim_marker": "victim@x.com",
        "attacker_response_body": '{"email":"victim@x.com"}',
        "attacker_control_body": '{"email":"me@x.com"}',
        "repetitions": 3,
    }
    out = v.promote(h, ev)
    assert isinstance(out, Finding)
    assert out.cvss_score > 0
    assert "idor" in out.title.lower()
    assert h.id in out.chain


def test_validator_refutes_idor() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="idor")
    ev = {
        "victim_marker": "victim@x.com",
        "attacker_response_body": "403 forbidden",
        "attacker_control_body": "",
        "repetitions": 0,
    }
    out = v.promote(h, ev)
    assert isinstance(out, TestedNegative)
    assert out.what == "idor"


def test_validator_confirms_jwt_forge() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="jwt_forge")
    ev = {
        "forged_token_authorized": True,
        "original_token_authorized": False,
        "authorized_marker_present": True,
    }
    out = v.promote(h, ev)
    assert isinstance(out, Finding)


def test_validator_confirms_sqli_boolean() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="sqli")
    ev = {
        "mode": "bool",
        "true_resp": "A" * 500,
        "control_resp": "A" * 500,
        "false_resp": "unexpected error page",
    }
    out = v.promote(h, ev)
    assert isinstance(out, Finding)


def test_validator_confirms_sqli_time() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="sqli")
    ev = {"mode": "time", "baseline_ms": 120, "delayed_ms": 5300, "expected_delay_ms": 5000, "repetitions": 2}
    out = v.promote(h, ev)
    assert isinstance(out, Finding)


def test_validator_unknown_claim_escalates() -> None:
    v = DeterministicValidator()
    h = Hypothesis(source="rule", claim="mystery")
    assert v.promote(h, {}) is None
