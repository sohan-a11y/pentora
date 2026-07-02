"""The active replay primitive: real requests to a live server + strict Governor gating."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

from pentora.engine import (
    Governor,
    HttpReplayPrimitive,
    ReplayInput,
    RunContext,
    RunScope,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str, payload: dict) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}." + _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


def _run(inp: ReplayInput, ctx: RunContext):  # noqa: ANN202
    return asyncio.run(Governor().execute(HttpReplayPrimitive(), inp, ctx))


def test_replay_admin_token_returns_200(jwt_server) -> None:  # noqa: ANN001
    with jwt_server("s3cr3t") as url:
        token = _jwt("s3cr3t", {"role": "admin"})
        res = _run(ReplayInput(url=url + "/api/orders", token=token), RunContext(scope=RunScope()))
    assert not res.is_error
    assert res.data["status"] == 200
    assert "ADMIN" in res.data["body"]
    assert res.requests_made == 1
    txn = next(f for f in res.facts if f.kind == "http_txn")
    assert txn.status == 200
    assert txn.req_headers["authorization"] == "<redacted>"   # secret not stored


def test_replay_user_token_returns_403(jwt_server) -> None:  # noqa: ANN001
    with jwt_server("s3cr3t") as url:
        token = _jwt("s3cr3t", {"role": "user"})
        res = _run(ReplayInput(url=url + "/api/orders", token=token), RunContext(scope=RunScope()))
    assert res.data["status"] == 403


def test_replay_bad_signature_returns_401(jwt_server) -> None:  # noqa: ANN001
    with jwt_server("s3cr3t") as url:
        forged = _jwt("wrong-secret", {"role": "admin"})   # signed with the wrong key
        res = _run(ReplayInput(url=url + "/api/orders", token=forged), RunContext(scope=RunScope()))
    assert res.data["status"] == 401


def test_governor_blocks_replay_in_dry_run() -> None:
    # ACTIVE_SAFE primitive must be blocked in a dry-run scan, before any packet.
    res = _run(
        ReplayInput(url="http://127.0.0.1:9/x", token="x"),
        RunContext(scope=RunScope(), dry_run=True),
    )
    assert res.is_error
    assert "dry-run" in res.summary


def test_replay_blocked_out_of_scope(jwt_server) -> None:  # noqa: ANN001
    with jwt_server("s") as url:
        res = _run(
            ReplayInput(url=url + "/x", token="x"),
            RunContext(scope=RunScope(include=["allowed.example"])),   # 127.0.0.1 not in scope
        )
    assert res.is_error
    assert "out of scope" in res.summary


def test_governor_blocks_replay_over_budget() -> None:
    res = _run(
        ReplayInput(url="http://127.0.0.1:9/x", token="x"),
        RunContext(scope=RunScope(), budget_requests=0),   # est_requests=1 > 0
    )
    assert res.is_error
    assert "budget" in res.summary
