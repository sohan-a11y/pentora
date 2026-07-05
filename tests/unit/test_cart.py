"""CartEngine: the autonomous loop drives capture -> rules -> dispatch -> findings on its own."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

import pytest

from pentora.engine import (
    Blackboard,
    CapturedTxn,
    CaptureInput,
    CapturePrimitive,
    CartEngine,
    DeterministicValidator,
    Governor,
    RuleEngine,
    RunContext,
    RunScope,
    Task,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str, payload: dict) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}." + _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


def _capture(bb: Blackboard, gov: Governor, txns: list[CapturedTxn]) -> None:
    asyncio.run(gov.execute(CapturePrimitive(), CaptureInput(transactions=txns),
                            RunContext(scope=RunScope(), blackboard=bb)))


def test_cart_autonomously_finds_idor(idor_server) -> None:  # noqa: ANN001
    pytest.importorskip("py_trees")
    from pentora.engine.playbook_idor import idor_rule, idor_runner

    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, {"sub": "user_a", "role": "user"}), _jwt(secret, {"sub": "user_b", "role": "user"})
    with idor_server(secret, vulnerable=True) as base:
        bb = Blackboard()
        eng = RuleEngine(bb)
        eng.add_rule(idor_rule())
        cart = CartEngine(bb=bb, chainer=eng, governor=Governor(),
                          validator=DeterministicValidator(), scope=RunScope())
        cart.register("idor_playbook", idor_runner)

        _capture(bb, cart.governor, [
            CapturedTxn(method="GET", url=f"{base}/api/orders/1",
                        req_headers={"Authorization": f"Bearer {jwt_a}"}, status=200, role_label="user_a"),
            CapturedTxn(method="GET", url=f"{base}/api/orders/2",
                        req_headers={"Authorization": f"Bearer {jwt_b}"}, status=200, role_label="user_b"),
        ])

        summary = cart.run()   # fully autonomous: rules fire, task dispatched, playbook runs

    assert summary["findings"] >= 1
    assert summary["dispatches"] >= 1
    assert any(f.title == "IDOR" for f in bb.query("finding"))


def test_cart_autonomously_finds_jwt(jwt_server) -> None:  # noqa: ANN001
    pytest.importorskip("py_trees")
    from pentora.engine.playbook import jwt_rule, jwt_runner

    secret = "secret123"
    token = _jwt(secret, {"sub": "user_b", "role": "user"})
    with jwt_server(secret) as base:
        bb = Blackboard()
        eng = RuleEngine(bb)
        eng.add_rule(jwt_rule())
        cart = CartEngine(bb=bb, chainer=eng, governor=Governor(),
                          validator=DeterministicValidator(), scope=RunScope(),
                          config={"wordlist": ["password", "admin", "secret123"]})
        cart.register("jwt_playbook", jwt_runner)

        _capture(bb, cart.governor, [
            CapturedTxn(method="GET", url=f"{base}/api/orders",
                        req_headers={"Authorization": f"Bearer {token}"}, status=200, role_label="user_b"),
        ])

        summary = cart.run()

    assert summary["findings"] == 1
    assert any(f.title == "JWT_FORGE" and f.cvss_score == 9.1 for f in bb.query("finding"))


def test_cart_dispatch_cap_stops_runaway() -> None:
    bb = Blackboard()
    cart = CartEngine(bb=bb, chainer=RuleEngine(bb), governor=Governor(),
                      validator=DeterministicValidator(), max_dispatches=5)

    def loop_runner(engine: CartEngine, task: Task) -> None:
        engine.bb.assert_fact(Task(source="loop", playbook="loop"))   # spawns a fresh task each time

    cart.register("loop", loop_runner)
    cart.seed(Task(source="seed", playbook="loop"))
    cart.run()
    assert cart.dispatches == 5   # capped, did not hang


def test_cart_ignores_unregistered_playbook() -> None:
    bb = Blackboard()
    cart = CartEngine(bb=bb, chainer=RuleEngine(bb), governor=Governor(),
                      validator=DeterministicValidator())
    cart.seed(Task(source="seed", playbook="nonexistent"))
    summary = cart.run()
    assert summary["dispatches"] == 0
