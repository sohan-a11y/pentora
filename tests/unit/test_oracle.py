"""PayloadOracle — deterministic retrieval of vetted injection syntax."""
from __future__ import annotations

from pentora.engine.oracle import Payload, PayloadOracle


def test_boolean_pair_uses_seed() -> None:
    t, f = PayloadOracle().sqli_boolean_pair("abc")
    assert t.value == "abc' OR '1'='1"
    assert f.value == "abc' AND '1'='2"
    assert (t.technique, f.technique) == ("boolean_true", "boolean_false")


def test_time_payload_carries_expected_delay() -> None:
    p = PayloadOracle().sqli_time(seed="1", delay=5)
    assert "pg_sleep(5)" in p.value
    assert p.meta["expected_delay_ms"] == 5000


def test_xss_reflection_embeds_marker() -> None:
    payloads = PayloadOracle().xss_reflection("MARK()")
    assert isinstance(payloads[0], Payload)
    assert payloads[0].value == "<script>MARK()</script>"
    assert all("MARK()" in p.value for p in payloads)


def test_retrieve_unknown_claim_is_empty() -> None:
    assert PayloadOracle().retrieve("nope", "none") == []


def test_retrieve_top_k_limits_results() -> None:
    got = PayloadOracle().retrieve("sqli", "boolean_true", top_k=2, seed="x")
    assert len(got) == 2


def test_retrieval_is_deterministic() -> None:
    o = PayloadOracle()
    assert o.sqli_boolean_pair("z")[0].value == o.sqli_boolean_pair("z")[0].value
