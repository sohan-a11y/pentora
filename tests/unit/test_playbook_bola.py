"""BOLA playbook: state-based object authorization. Objects are created via real writes (state),
then the attacker reads the victim's object id. Confirmed on a vulnerable build, refuted on one
that enforces ownership, and self-assembling from captured write state."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

pytest.importorskip("py_trees")

import httpx  # noqa: E402
from py_trees.common import Status  # noqa: E402

from pentora.engine import (  # noqa: E402
    Blackboard,
    DeterministicValidator,
    Governor,
    HttpTransaction,
    Hypothesis,
    RuleEngine,
    SecurityContext,
)
from pentora.engine.playbook_bola import (  # noqa: E402
    BolaPlaybookContext,
    bola_rule,
    dispatch_bola_from_facts,
    run_bola_playbook,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str, sub: str) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps({"sub": sub, "role": "user"}, separators=(",", ":")).encode())
    return f"{h}.{p}." + _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


def _create(base: str, token: str) -> dict[str, str]:
    r = httpx.post(f"{base}/api/objects", headers={"Authorization": f"Bearer {token}"}, timeout=10.0)
    return dict(r.json())


def test_bola_confirmed_against_vulnerable_server(bola_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    ja, jb = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="bola"))
    with bola_server(secret, vulnerable=True) as base:
        oa, ob = _create(base, ja), _create(base, jb)
        status = run_bola_playbook(BolaPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            object_url=f"{base}/api/objects/{oa['id']}", victim_body=oa["secret"],
            attacker_token=jb, attacker_control_url=f"{base}/api/objects/{ob['id']}",
        ))
    assert status == Status.SUCCESS
    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "BOLA"


def test_bola_refuted_against_secure_server(bola_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    ja, jb = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="bola"))
    with bola_server(secret, vulnerable=False) as base:
        oa, ob = _create(base, ja), _create(base, jb)
        status = run_bola_playbook(BolaPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            object_url=f"{base}/api/objects/{oa['id']}", victim_body=oa["secret"],
            attacker_token=jb, attacker_control_url=f"{base}/api/objects/{ob['id']}",
        ))
    assert status == Status.FAILURE
    assert not bb.query("finding")
    assert bb.query("tested_negative")


def test_bola_confirmed_with_full_json_write_snippet(bola_server) -> None:  # noqa: ANN001
    """Regression: a live write snippet is the whole object body, not a bare token. The playbook
    must distill a distinguishing marker so the proof survives create-vs-read formatting drift."""
    secret = "s3cr3t"
    ja, jb = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="bola"))
    with bola_server(secret, vulnerable=True) as base:
        oa, ob = _create(base, ja), _create(base, jb)
        # Full create-response body with the fields in a different order than the read returns.
        victim_body = json.dumps({"owner": "user_a", "id": oa["id"], "secret": oa["secret"]})
        status = run_bola_playbook(BolaPlaybookContext(
            bb=bb, governor=Governor(), validator=DeterministicValidator(), hypothesis=hyp,
            object_url=f"{base}/api/objects/{oa['id']}", victim_body=victim_body,
            attacker_token=jb, attacker_control_url=f"{base}/api/objects/{ob['id']}",
        ))
    assert status == Status.SUCCESS
    assert len(bb.query("finding")) == 1


def test_bola_dispatch_from_captured_write_state(bola_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    ja, jb = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    bb = Blackboard()
    hyp = bb.assert_fact(Hypothesis(source="t", claim="bola"))
    with bola_server(secret, vulnerable=True) as base:
        oa, ob = _create(base, ja), _create(base, jb)
        # The observed write state: victim created oa (secret in the snippet); attacker read ob.
        bb.assert_fact(HttpTransaction(
            source="capture", method="POST", url=f"{base}/api/objects/{oa['id']}",
            status=201, resp_body_snippet=oa["secret"], role_label="user_a",
        ))
        bb.assert_fact(HttpTransaction(
            source="capture", method="GET", url=f"{base}/api/objects/{ob['id']}",
            status=200, role_label="user_b",
        ))
        bb.assert_fact(SecurityContext(source="c", role_label="user_a", has_jwt=True, jwt=ja))
        bb.assert_fact(SecurityContext(source="c", role_label="user_b", has_jwt=True, jwt=jb))
        status = dispatch_bola_from_facts(bb, Governor(), DeterministicValidator(), hyp)
    assert status == Status.SUCCESS
    assert len(bb.query("finding")) == 1


def test_bola_rule_fires_on_write_plus_two_roles() -> None:
    bb = Blackboard()
    eng = RuleEngine(bb)
    eng.add_rule(bola_rule())
    bb.assert_fact(HttpTransaction(
        source="c", method="POST", url="http://t/api/objects/1", status=201,
        resp_body_snippet="X", role_label="user_a",
    ))
    bb.assert_fact(SecurityContext(source="c", role_label="user_a", has_jwt=True, jwt="a"))
    bb.assert_fact(SecurityContext(source="c", role_label="user_b", has_jwt=True, jwt="b"))
    eng.run_to_fixpoint()
    assert any(h.claim == "bola" for h in bb.query("hypothesis"))
    assert any(t.playbook == "bola_playbook" for t in bb.query("task"))
