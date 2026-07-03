"""The one-call engine facade: start() wires everything; ingest -> run -> report end to end."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("py_trees")

from pentora.engine.app import start  # noqa: E402
from pentora.engine.capture import CapturedTxn  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt(secret: str, sub: str) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps({"sub": sub, "role": "user"}, separators=(",", ":")).encode())
    return f"{h}.{p}." + _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())


class _FakeClassifier:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def classify(self, system: str, user: str) -> dict[str, Any]:
        return self.result


def test_start_wires_engine_and_runs_clean() -> None:
    e = start(target="https://app.example.com", classifier=_FakeClassifier({"is_vulnerable": False}))
    summary = e.run()          # nothing seeded -> no crash, no findings
    assert summary["findings"] == 0


def test_facade_finds_idor_end_to_end(idor_server) -> None:  # noqa: ANN001
    secret = "s3cr3t"
    jwt_a, jwt_b = _jwt(secret, "user_a"), _jwt(secret, "user_b")
    with idor_server(secret, vulnerable=True) as base:
        e = start(target=base, scope_hosts=["127.0.0.1"],
                  classifier=_FakeClassifier({"is_vulnerable": False}))
        e.ingest([
            CapturedTxn(method="GET", url=f"{base}/api/orders/1",
                        req_headers={"Authorization": f"Bearer {jwt_a}"}, status=200, role_label="user_a"),
            CapturedTxn(method="GET", url=f"{base}/api/orders/2",
                        req_headers={"Authorization": f"Bearer {jwt_b}"}, status=200, role_label="user_b"),
        ])
        e.run()
    assert any(f.title == "IDOR" for f in e.bb.query("finding"))


def test_facade_finds_disclosure_end_to_end() -> None:
    fake = _FakeClassifier({"is_vulnerable": True, "vuln_type": "pii_leak", "severity_score": 8})
    e = start(target="https://app.example.com", classifier=fake)
    e.ingest([
        CapturedTxn(method="GET", url="https://app.example.com/api/me", status=200,
                    resp_body='{"card":"4111111111111111"}'),
    ])
    e.run()
    findings = e.bb.query("finding")
    assert any(f.title == "PII_LEAK" and f.severity == "high" for f in findings)


def test_ingest_har(tmp_path: Path) -> None:
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://app.acme.com/api/x",
                     "headers": [{"name": "Accept", "value": "application/json"}]},
         "response": {"status": 200, "content": {"text": "hello"}}},
    ]}}
    har_path = tmp_path / "traffic.har"
    har_path.write_text(json.dumps(har), encoding="utf-8")
    e = start(target="https://app.acme.com", classifier=_FakeClassifier({"is_vulnerable": False}))
    e.ingest_har(har_path)
    assert e.bb.query("http_txn")
    assert e.bb.query("endpoint")


def test_report_markdown_from_facade(tmp_path: Path) -> None:
    fake = _FakeClassifier({"is_vulnerable": True, "vuln_type": "pii_leak", "severity_score": 7})
    e = start(target="https://app.example.com", classifier=fake)
    e.ingest([CapturedTxn(method="GET", url="https://app.example.com/x", status=200,
                          resp_body='{"cc":"4111111111111111"}')])
    e.run()
    md = e.report_markdown(tmp_path / "r.md")
    assert "Pentora CART Report" in md
    assert "PII_LEAK" in md
