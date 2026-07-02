"""End-to-end: the JWT -> admin kill chain self-assembles from a single observed fact.

Seed one SecurityContext carrying a JWT signed with a weak secret. A rule fires, a playbook
runs (alg=none fails -> brute recovers the secret -> forge admin -> replay), and the deterministic
validator promotes a real Finding. Nothing wired the steps together — the blackboard did.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("py_trees")

from py_trees.common import Status  # noqa: E402

from pentora.engine import (  # noqa: E402
    Blackboard,
    DeterministicValidator,
    Governor,
    Hypothesis,
    Pattern,
    Rule,
    RuleEngine,
    SecurityContext,
    Task,
)
from pentora.engine.playbook import (  # noqa: E402
    DemoProtectedResource,
    JwtPlaybookContext,
    _b64url_encode,
    _sign_hs256,
    run_jwt_playbook,
)


def _make_jwt(secret: str, payload: dict) -> str:
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign_hs256(f"{header_b64}.{payload_b64}".encode(), secret)
    return f"{header_b64}.{payload_b64}.{sig}"


def test_full_jwt_to_admin_kill_chain() -> None:
    secret = "secret123"
    wordlist = ["password", "admin", "secret123", "letmein"]
    token = _make_jwt(secret, {"sub": "user_b", "role": "user"})

    bb = Blackboard()
    eng = RuleEngine(bb)
    validator = DeterministicValidator()
    governor = Governor()
    resource = DemoProtectedResource(secret=secret)

    # Rule — SOCKET: a SecurityContext with a JWT. TAB: a jwt_forge hypothesis + a queued task.
    def on_jwt(engine: RuleEngine, b: dict) -> None:  # noqa: ANN001
        sc = b["sc"]
        h = engine.assert_fact(
            Hypothesis(source="jwt_rule", claim="jwt_forge", derived_from=[sc.id])
        )
        engine.assert_fact(
            Task(source="jwt_rule", playbook="jwt_playbook", derived_from=[sc.id],
                 args={"sc_id": sc.id, "hyp_id": h.id})
        )

    eng.add_rule(Rule(
        name="jwt_seen",
        patterns=[Pattern(kind="security_context", where=lambda f: f.has_jwt, as_="sc")],
        action=on_jwt,
    ))

    # 1) one observed fact enters the blackboard
    bb.assert_fact(SecurityContext(source="capture", role_label="user_b",
                                   has_jwt=True, jwt=token, rank=1))

    # 2) rules fire -> hypothesis + task self-assemble
    eng.run_to_fixpoint()
    assert bb.query("hypothesis", claim="jwt_forge")
    assert bb.query("task", playbook="jwt_playbook")

    # 3) dispatch the queued playbook
    hyp = bb.query("hypothesis", claim="jwt_forge")[0]
    sc = bb.query("security_context")[0]
    pctx = JwtPlaybookContext(bb=bb, governor=governor, validator=validator, hypothesis=hyp,
                              jwt=sc.jwt, wordlist=wordlist, resource=resource)
    status = run_jwt_playbook(pctx)

    # 4) a real, validated Finding — with provenance back to the seed
    assert status == Status.SUCCESS
    findings = bb.query("finding")
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "JWT_FORGE"
    assert f.cvss_score > 0
    assert hyp.id in f.chain
    # alg=none was tried first and recorded as tested-negative (provable coverage)
    assert any("alg=none" in n.what for n in bb.query("tested_negative"))
    # the weak-secret Secret + a successful AttackAttempt were recorded
    assert bb.query("secret")
    assert bb.query("attempt")


def test_strong_secret_yields_no_finding() -> None:
    token = _make_jwt("S3cr3t-unguessable-9f2a", {"sub": "user_b", "role": "user"})
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="jwt_forge"))
    pctx = JwtPlaybookContext(
        bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
        jwt=token, wordlist=["password", "admin", "letmein"],
        resource=DemoProtectedResource(secret="S3cr3t-unguessable-9f2a"),
    )
    assert run_jwt_playbook(pctx) == Status.FAILURE
    assert bb.query("finding") == []
    assert bb.query("tested_negative")
