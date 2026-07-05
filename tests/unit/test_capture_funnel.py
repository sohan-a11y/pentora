"""The ingestion funnel: live-shaped traffic -> typed facts -> the same CVSS 9.1 kill chain.

Proves translation, the Primitive contract, the mitmproxy addon (duck-typed + real), and the
full end-to-end handoff where a captured JWT request triggers the JWT->admin playbook.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from pentora.engine import (
    Blackboard,
    CaptureAddon,
    CapturedTxn,
    CaptureInput,
    CapturePrimitive,
    Governor,
    RunContext,
    RunScope,
    translate,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_jwt(secret: str, payload: dict) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_translate_extracts_securitycontext_from_bearer_jwt() -> None:
    token = _make_jwt("k", {"sub": "user_b", "role": "user"})
    txn = CapturedTxn(method="GET", url="https://app/api/me",
                      req_headers={"Authorization": f"Bearer {token}"}, status=200)
    facts = translate(txn)
    scs = [f for f in facts if f.kind == "security_context"]
    assert len(scs) == 1
    assert scs[0].has_jwt and scs[0].jwt == token
    assert scs[0].role_label == "user"          # read from the (unverified) JWT payload
    assert any(f.kind == "endpoint" for f in facts)
    assert any(f.kind == "http_txn" for f in facts)


def test_path_templating_and_semantics() -> None:
    txn = CapturedTxn(method="GET", url="https://app/users/123/orders/8f2a1b9c4d5e?id=42")
    facts = translate(txn)
    ep = next(f for f in facts if f.kind == "endpoint")
    assert ep.template == "/users/{id}/orders/{id}"
    param = next(f for f in facts if f.kind == "parameter")
    assert param.name == "id" and param.semantic == "resource_id"


def test_http_transaction_redacts_secrets() -> None:
    token = _make_jwt("k", {"role": "user"})
    txn = CapturedTxn(method="GET", url="https://app/x",
                      req_headers={"Authorization": f"Bearer {token}", "Cookie": "sid=abc"})
    txn_fact = next(f for f in translate(txn) if f.kind == "http_txn")
    assert txn_fact.req_headers["authorization"] == "<redacted>"
    assert txn_fact.req_headers["cookie"] == "<redacted>"


def test_cookie_only_yields_securitycontext() -> None:
    txn = CapturedTxn(method="GET", url="https://app/x", req_headers={"Cookie": "session=xyz"})
    sc = next(f for f in translate(txn) if f.kind == "security_context")
    assert sc.has_jwt is False and sc.cookies == {"session": "xyz"}


def test_capture_primitive_asserts_to_blackboard_via_governor() -> None:
    token = _make_jwt("k", {"role": "user"})
    txn = CapturedTxn(method="GET", url="https://app/api/orders",
                      req_headers={"Authorization": f"Bearer {token}"}, status=200)
    bb = Blackboard()
    ctx = RunContext(scope=RunScope(read_only=True), blackboard=bb)
    res = asyncio.run(Governor().execute(CapturePrimitive(), CaptureInput(transactions=[txn]), ctx))
    assert not res.is_error
    assert bb.query("security_context")
    assert bb.query("endpoint")


def test_addon_with_fake_mitmproxy_flow() -> None:
    """Duck-typed flow proves the addon logic without mitmproxy installed."""
    token = _make_jwt("k", {"role": "admin"})
    req = SimpleNamespace(method="GET", pretty_url="https://app.acme.com/api/orders/7",
                          headers={"Authorization": f"Bearer {token}"},
                          get_text=lambda strict=False: "")
    resp = SimpleNamespace(status_code=200, headers={}, get_text=lambda strict=False: "{}")
    flow = SimpleNamespace(request=req, response=resp)
    bb = Blackboard()
    CaptureAddon(bb, scope_hosts=["acme.com"]).response(flow)
    assert bb.query("security_context")
    assert bb.query("endpoint")


def test_addon_with_real_mitmproxy_flow() -> None:
    """Runs only where mitmproxy is installed (e.g. the team's Colab); proves real compat."""
    pytest.importorskip("mitmproxy")
    from mitmproxy.test import tflow

    token = _make_jwt("k", {"role": "user"})
    f = tflow.tflow(resp=True)
    f.request.method = "GET"
    f.request.url = "https://app.acme.com/api/orders/9"
    f.request.headers["Authorization"] = f"Bearer {token}"
    f.response.status_code = 200
    bb = Blackboard()
    CaptureAddon(bb).response(f)
    scs = bb.query("security_context")
    assert scs and scs[0].has_jwt and scs[0].jwt == token


def test_capture_to_cvss91_finding_full_funnel(jwt_server) -> None:  # noqa: ANN001
    """THE handoff: a captured weak-JWT request -> facts -> rule -> playbook -> CVSS 9.1."""
    pytest.importorskip("py_trees")
    from pentora.engine import (
        DeterministicValidator,
        Hypothesis,
        Pattern,
        Rule,
        RuleEngine,
        Task,
    )
    from pentora.engine.playbook import JwtPlaybookContext, run_jwt_playbook

    secret = "secret123"
    wordlist = ["password", "admin", "secret123", "letmein"]
    token = _make_jwt(secret, {"sub": "user_b", "role": "user"})

    bb = Blackboard()
    eng = RuleEngine(bb)
    gov = Governor()
    val = DeterministicValidator()

    def on_jwt(engine: RuleEngine, b: dict) -> None:  # noqa: ANN001
        engine.assert_fact(Hypothesis(source="jwt_rule", claim="jwt_forge",
                                      derived_from=[b["sc"].id]))
        engine.assert_fact(Task(source="jwt_rule", playbook="jwt_playbook",
                                derived_from=[b["sc"].id]))

    eng.add_rule(Rule(
        name="jwt_seen",
        patterns=[Pattern(kind="security_context", where=lambda f: f.has_jwt, as_="sc")],
        action=on_jwt,
    ))

    # 1) CAPTURE a synthetic authenticated request through the primitive
    txn = CapturedTxn(method="GET", url="https://app.acme.com/api/orders?id=42",
                      req_headers={"Authorization": f"Bearer {token}"}, status=200)
    ctx = RunContext(scope=RunScope(read_only=True), blackboard=bb)
    asyncio.run(gov.execute(CapturePrimitive(), CaptureInput(transactions=[txn]), ctx))

    captured = [s for s in bb.query("security_context") if s.has_jwt]
    assert captured and captured[0].jwt == token          # the funnel entrance works

    # 2) rules fire -> 3) playbook -> 4) validated finding
    eng.run_to_fixpoint()
    hyp = bb.query("hypothesis", claim="jwt_forge")[0]
    with jwt_server(secret) as base_url:
        run_jwt_playbook(JwtPlaybookContext(
            bb=bb, governor=gov, validator=val, hypothesis=hyp,
            jwt=captured[0].jwt, wordlist=wordlist, target_url=base_url + "/api/orders",
        ))

    findings = bb.query("finding")
    assert len(findings) == 1
    assert findings[0].title == "JWT_FORGE"
    assert findings[0].cvss_score == 9.1
    assert findings[0].severity == "critical"
