"""End-to-end: the JWT -> admin kill chain self-assembles and is proven against a REAL server.

Seed one SecurityContext carrying a JWT signed with a weak secret. A rule fires, a playbook runs
(alg=none fails -> brute recovers the secret -> forge admin -> replay against a live HTTP server),
and the deterministic validator promotes a real Finding from the real 200-vs-403 differential.
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


def test_full_jwt_to_admin_kill_chain(jwt_server) -> None:  # noqa: ANN001
    secret = "secret123"
    wordlist = ["password", "admin", "secret123", "letmein"]
    token = _make_jwt(secret, {"sub": "user_b", "role": "user"})

    with jwt_server(secret) as base_url:
        bb = Blackboard()
        eng = RuleEngine(bb)
        validator = DeterministicValidator()
        governor = Governor()

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

        # one observed fact -> rules fire -> hypothesis + task self-assemble
        bb.assert_fact(SecurityContext(source="capture", role_label="user_b",
                                       has_jwt=True, jwt=token, rank=1))
        eng.run_to_fixpoint()
        assert bb.query("hypothesis", claim="jwt_forge")
        assert bb.query("task", playbook="jwt_playbook")

        # dispatch the playbook against the LIVE server
        hyp = bb.query("hypothesis", claim="jwt_forge")[0]
        sc = bb.query("security_context")[0]
        status = run_jwt_playbook(JwtPlaybookContext(
            bb=bb, governor=governor, validator=validator, hypothesis=hyp,
            jwt=sc.jwt, wordlist=wordlist, target_url=base_url + "/api/orders",
        ))

        assert status == Status.SUCCESS
        findings = bb.query("finding")
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "JWT_FORGE"
        assert f.cvss_score == 9.1
        assert hyp.id in f.chain
        assert any("alg=none" in n.what for n in bb.query("tested_negative"))
        assert bb.query("secret")
        assert bb.query("attempt")


def test_strong_secret_yields_no_finding(jwt_server) -> None:  # noqa: ANN001
    secret = "S3cr3t-unguessable-9f2a"
    token = _make_jwt(secret, {"sub": "user_b", "role": "user"})
    with jwt_server(secret) as base_url:
        bb = Blackboard()
        hyp = bb.assert_fact(Hypothesis(source="t", claim="jwt_forge"))
        status = run_jwt_playbook(JwtPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            jwt=token, wordlist=["password", "admin", "letmein"], target_url=base_url + "/x",
        ))
        assert status == Status.FAILURE
        assert bb.query("finding") == []
        assert bb.query("tested_negative")
