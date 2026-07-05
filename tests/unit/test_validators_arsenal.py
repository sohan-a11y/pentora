"""Deterministic proof predicates for the expanded arsenal — BOLA + XSS, tested in isolation."""
from __future__ import annotations

from html import escape

from pentora.engine.facts import Hypothesis
from pentora.engine.validator import BolaValidator, Verdict, XssValidator

_XSS = "<script>pentoraXSS()</script>"


def test_xss_confirmed_on_verbatim_html_reflection() -> None:
    r = XssValidator().validate(
        Hypothesis(claim="xss"),
        {"payload": _XSS, "body": f"<html><body>{_XSS}</body></html>", "content_type": "text/html"},
    )
    assert r.verdict is Verdict.CONFIRMED
    assert r.cvss_vector


def test_xss_refuted_when_reflection_is_escaped() -> None:
    body = f"<html><body>{escape(_XSS)}</body></html>"
    r = XssValidator().validate(
        Hypothesis(claim="xss"), {"payload": _XSS, "body": body, "content_type": "text/html"}
    )
    assert r.verdict is Verdict.REFUTED
    assert "escaped" in r.rationale


def test_xss_refuted_when_not_reflected() -> None:
    r = XssValidator().validate(
        Hypothesis(claim="xss"),
        {"payload": _XSS, "body": "nothing here", "content_type": "text/html"},
    )
    assert r.verdict is Verdict.REFUTED


def test_xss_refuted_outside_html_context() -> None:
    # verbatim, but a JSON response won't execute markup
    r = XssValidator().validate(
        Hypothesis(claim="xss"),
        {"payload": _XSS, "body": _XSS, "content_type": "application/json"},
    )
    assert r.verdict is Verdict.REFUTED


def test_xss_json_body_with_html_substring_is_not_confirmed() -> None:
    # A JSON API that reflects the payload verbatim AND happens to contain "<html" elsewhere must
    # NOT be minted as XSS — the content-type, not a body sniff, decides executability.
    body = f'{{"tip": "wrap in <html> blocks", "q": "{_XSS}"}}'
    r = XssValidator().validate(
        Hypothesis(claim="xss"), {"payload": _XSS, "body": body, "content_type": "application/json"}
    )
    assert r.verdict is Verdict.REFUTED


def test_xss_plaintext_verbatim_is_not_confirmed() -> None:
    # text/plain renders markup as literal text; verbatim reflection there is not execution.
    r = XssValidator().validate(
        Hypothesis(claim="xss"),
        {"payload": _XSS, "body": f"echo: {_XSS}", "content_type": "text/plain"},
    )
    assert r.verdict is Verdict.REFUTED


def test_bola_confirmed_reuses_the_cross_user_leak_proof() -> None:
    r = BolaValidator().validate(
        Hypothesis(claim="bola"),
        {
            "victim_marker": "OBJ-1-SECRET",
            "attacker_response_body": "...OBJ-1-SECRET...",
            "attacker_control_body": "OBJ-2-SECRET",
            "repetitions": 2,
            "evidence_ids": [],
        },
    )
    assert r.verdict is Verdict.CONFIRMED
    assert "user_a" in r.poc                       # BOLA-specific wording, not IDOR's


def test_bola_refuted_when_marker_absent() -> None:
    r = BolaValidator().validate(
        Hypothesis(claim="bola"),
        {
            "victim_marker": "OBJ-1-SECRET",
            "attacker_response_body": "forbidden",
            "attacker_control_body": "OBJ-2-SECRET",
            "repetitions": 0,
            "evidence_ids": [],
        },
    )
    assert r.verdict is Verdict.REFUTED
