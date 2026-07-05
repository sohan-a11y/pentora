"""IDOR/BOLA playbook: confirmed on a vulnerable server, refuted on a secure one, and proven to
self-assemble reactively from captured traffic."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

import pytest

pytest.importorskip("py_trees")

from py_trees.common import Status  # noqa: E402

from pentora.engine import (  # noqa: E402
    Blackboard,
    CapturedTxn,
    CaptureInput,
    CapturePrimitive,
    DeterministicValidator,
    Governor,
    Hypothesis,
    RuleEngine,
    RunContext,
    RunScope,
)
from pentora.engine.playbook_idor import (  # noqa: E402
    IdorPlaybookContext,
    dispatch_idor_from_facts,
    idor_rule,
    run_idor_playbook,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str, sub: str) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps({"sub": sub, "role": "user"}, separators=(",", ":")).encode())
    return f"{h}.{p}." + _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


def test_idor_confirmed_against_vulnerable_server(idor_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="idor"))
    with idor_server(secret, vulnerable=True) as base:
        status = run_idor_playbook(IdorPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            victim_url=f"{base}/api/orders/1", victim_token=jwt_a,
            attacker_token=jwt_b, attacker_own_url=f"{base}/api/orders/2",
        ))
    assert status == Status.SUCCESS
    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "IDOR"
    assert findings[0].cvss_score >= 6.0
    assert findings[0].severity in ("medium", "high")


def test_idor_playbook_runs_from_inside_a_running_event_loop(idor_server) -> None:  # noqa: ANN001
    """Reproduces the exact Colab/Jupyter failure: the kernel executes cell code as a coroutine
    on an already-running event loop, so a playbook's internal ``asyncio.run()`` used to raise
    ``RuntimeError: asyncio.run() cannot be called from a running event loop``."""
    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="idor"))

    async def _drive_from_notebook_like_loop(base: str) -> Status:
        asyncio.get_running_loop()                        # sanity: a loop really is running here
        return run_idor_playbook(IdorPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            victim_url=f"{base}/api/orders/1", victim_token=jwt_a,
            attacker_token=jwt_b, attacker_own_url=f"{base}/api/orders/2",
        ))

    with idor_server(secret, vulnerable=True) as base:
        status = asyncio.run(_drive_from_notebook_like_loop(base))
    assert status == Status.SUCCESS
    assert len(bb.query("finding")) == 1


def test_idor_refuted_against_secure_server(idor_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="idor"))
    with idor_server(secret, vulnerable=False) as base:
        status = run_idor_playbook(IdorPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            victim_url=f"{base}/api/orders/1", victim_token=jwt_a,
            attacker_token=jwt_b, attacker_own_url=f"{base}/api/orders/2",
        ))
    assert status == Status.FAILURE
    assert bb.query("finding") == []
    assert bb.query("tested_negative")


def test_idor_reactive_funnel_from_capture(idor_server) -> None:  # noqa: ANN001
    """Capture both users' own accesses -> the rule fires the idor hypothesis -> playbook -> finding."""
    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    with idor_server(secret, vulnerable=True) as base:
        bb = Blackboard()
        eng = RuleEngine(bb)
        gov = Governor()
        val = DeterministicValidator()
        eng.add_rule(idor_rule())

        txns = [
            CapturedTxn(method="GET", url=f"{base}/api/orders/1",
                        req_headers={"Authorization": f"Bearer {jwt_a}"}, status=200,
                        role_label="user_a"),
            CapturedTxn(method="GET", url=f"{base}/api/orders/2",
                        req_headers={"Authorization": f"Bearer {jwt_b}"}, status=200,
                        role_label="user_b"),
        ]
        asyncio.run(gov.execute(CapturePrimitive(), CaptureInput(transactions=txns),
                                RunContext(scope=RunScope(), blackboard=bb)))

        eng.run_to_fixpoint()
        hyps = bb.query("hypothesis", claim="idor")
        assert hyps                                   # the rule generalized and fired
        status = dispatch_idor_from_facts(bb, gov, val, hyps[0])

    assert status == Status.SUCCESS
    assert any(f.title == "IDOR" for f in bb.query("finding"))
