"""Traffic capture primitive — the ingestion funnel from live HTTP(S) into typed Facts.

Three layers, cleanly separated:

1. ``translate(txn)`` — pure function: a normalized ``CapturedTxn`` -> typed Facts
   (HttpTransaction, ObservedEndpoint, SecurityContext when a JWT/cookie is present, Parameter).
   Stdlib + pydantic only, fully testable, no proxy required.
2. ``CapturePrimitive`` — adheres to the Primitive ABC: ``run`` translates a batch of captured
   transactions and returns a PrimitiveResult of Facts (and drops them on ``ctx.blackboard``).
3. ``CaptureAddon`` — a mitmproxy addon that **duck-types** the flow (no mitmproxy import), so
   this module imports cleanly without mitmproxy. ``run_live_capture`` wires it into a live
   DumpMaster (mitmproxy imported lazily, only when you actually listen).

Secrets are redacted before landing in HttpTransaction; the raw JWT lives only on the
SecurityContext that the auth playbooks need.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel

from pentora.engine.blackboard import Blackboard
from pentora.engine.facts import (
    Fact,
    HttpTransaction,
    ObservedEndpoint,
    Parameter,
    SecurityContext,
)
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Primitive,
    PrimitiveResult,
    RunContext,
)

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]{12,}$")


class CapturedTxn(BaseModel):
    """A normalized request/response pair — the neutral shape both the batch primitive and the
    live mitmproxy addon translate from."""

    method: str
    url: str
    req_headers: dict[str, str] = {}
    req_body: str | None = None
    status: int = 0
    resp_headers: dict[str, str] = {}
    resp_body: str | None = None
    role_label: str | None = None


class CaptureInput(BaseModel):
    transactions: list[CapturedTxn] = []


# ---- pure translation ------------------------------------------------------

def _template_path(path: str) -> str:
    """/users/123/orders/8f2a... -> /users/{id}/orders/{id}."""
    out = []
    for seg in path.split("/"):
        if seg.isdigit() or _UUID_RE.match(seg) or _HEX_RE.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def _parse_cookies(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _find_jwt(headers_ci: dict[str, str], cookies: dict[str, str]) -> str | None:
    auth = headers_ci.get("authorization", "")
    if auth:
        m = _JWT_RE.search(auth)
        if m:
            return m.group(0)
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok.count(".") == 2:
                return tok
    for v in cookies.values():
        m = _JWT_RE.search(v)
        if m:
            return m.group(0)
    return None


def _jwt_role(jwt: str, fallback: str) -> str:
    try:
        payload_b64 = jwt.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
        role = payload.get("role") or payload.get("sub")
        return str(role) if role else fallback
    except Exception:  # noqa: BLE001
        return fallback


def _semantic(name: str) -> str | None:
    n = name.lower()
    if n == "id" or n.endswith(("id", "_id", "uuid", "guid")):
        return "resource_id"
    if "email" in n:
        return "email"
    if n in ("price", "amount", "total", "cost"):
        return "price"
    return None


def translate(txn: CapturedTxn) -> list[Fact]:
    """Turn one captured transaction into typed blackboard facts."""
    parts = urlsplit(txn.url)
    path = parts.path or "/"
    headers_ci = {k.lower(): v for k, v in txn.req_headers.items()}
    cookies = _parse_cookies(headers_ci.get("cookie", ""))

    redacted = {
        k: ("<redacted>" if k in ("authorization", "cookie") else v)
        for k, v in headers_ci.items()
    }
    body_sha = (
        hashlib.sha256(txn.resp_body.encode()).hexdigest()[:16] if txn.resp_body else None
    )
    facts: list[Fact] = [
        HttpTransaction(
            source="capture", method=txn.method, url=txn.url, req_headers=redacted,
            status=txn.status, resp_body_sha=body_sha, role_label=txn.role_label,
        )
    ]

    auth_present = "authorization" in headers_ci or bool(cookies)
    endpoint = ObservedEndpoint(
        source="capture", method=txn.method, template=_template_path(path),
        auth_required=auth_present or None,
    )
    facts.append(endpoint)

    jwt = _find_jwt(headers_ci, cookies)
    if jwt:
        facts.append(SecurityContext(
            source="capture", role_label=txn.role_label or _jwt_role(jwt, "captured"),
            has_jwt=True, jwt=jwt, cookies=cookies,
        ))
    elif cookies:
        facts.append(SecurityContext(
            source="capture", role_label=txn.role_label or "captured", cookies=cookies,
        ))

    for name, values in parse_qs(parts.query).items():
        facts.append(Parameter(
            source="capture", endpoint_id=endpoint.id, location="query", name=name,
            semantic=_semantic(name), example_values=values[:3],
        ))
    return facts


# ---- the Primitive (batch: HAR / flow dump / test fixtures) -----------------

class CapturePrimitive(Primitive):
    name = "capture"
    version = "0.1"
    input_schema = CaptureInput
    capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.PASSIVE
    )

    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        if not isinstance(inp, CaptureInput):
            return PrimitiveResult(summary="bad input", is_error=True)
        facts: list[Fact] = []
        for txn in inp.transactions:
            facts.extend(translate(txn))
        if ctx.blackboard is not None:
            for f in facts:
                ctx.blackboard.assert_fact(f)
        return PrimitiveResult(
            facts=facts,
            summary=f"captured {len(inp.transactions)} txn -> {len(facts)} facts",
        )


# ---- the live mitmproxy addon (duck-typed flow, no mitmproxy import) --------

def flow_to_txn(flow: Any) -> CapturedTxn:
    """Build a CapturedTxn from a mitmproxy HTTPFlow via duck typing (works with real flows)."""
    req = flow.request
    resp = getattr(flow, "response", None)
    return CapturedTxn(
        method=req.method,
        url=getattr(req, "pretty_url", None) or req.url,
        req_headers=dict(req.headers.items()),
        req_body=req.get_text(strict=False) if hasattr(req, "get_text") else None,
        status=resp.status_code if resp else 0,
        resp_headers=dict(resp.headers.items()) if resp else {},
        resp_body=(resp.get_text(strict=False) if resp and hasattr(resp, "get_text") else None),
    )


class CaptureAddon:
    """mitmproxy addon. Register on a running DumpMaster; drops typed facts on each response.

    Imports nothing from mitmproxy — it only reads attributes off the flow object mitmproxy
    hands it, so this module stays importable without mitmproxy installed.
    """

    def __init__(self, blackboard: Blackboard, scope_hosts: list[str] | None = None) -> None:
        self.bb = blackboard
        self.scope_hosts = scope_hosts or []

    def response(self, flow: Any) -> None:
        txn = flow_to_txn(flow)
        if self.scope_hosts and not any(h in txn.url for h in self.scope_hosts):
            return
        for f in translate(txn):
            self.bb.assert_fact(f)


async def run_live_capture(
    blackboard: Blackboard,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
    scope_hosts: list[str] | None = None,
) -> Any:
    """Start a live intercepting proxy that feeds the blackboard. Requires ``mitmproxy``."""
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    opts = Options(listen_host=listen_host, listen_port=listen_port)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(CaptureAddon(blackboard, scope_hosts))
    await master.run()
    return master
