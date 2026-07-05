"""Active HTTP replay primitive — fires a real request with a chosen token, returns the real
response as facts.

This is the first ACTIVE primitive: unlike passive capture, it touches the target. It is declared
``blast_radius=ACTIVE_SAFE`` (sends a request, changes no server state) and ``read_only=True``,
so the Governor gates it — blocked in a dry-run scan, blocked out of scope, and counted against
the request budget. It returns the real status + body so the deterministic Validator can decide
on ground truth (200 with sensitive data vs 401/403), not a simulation.
"""
from __future__ import annotations

import hashlib

import httpx
from pydantic import BaseModel

from pentora.engine.facts import HttpTransaction
from pentora.engine.primitive import (
    BlastRadius,
    Capability,
    Primitive,
    PrimitiveResult,
    RunContext,
    ScopeViolation,
)


class ReplayInput(BaseModel):
    url: str
    token: str | None = None
    method: str = "GET"
    role_label: str = "replay"


class HttpReplayPrimitive(Primitive):
    name = "http_replay"
    version = "0.1"
    input_schema = ReplayInput
    capability = Capability(
        read_only=True,                        # a GET reads; it does not mutate
        destructive=False,
        idempotent=True,
        blast_radius=BlastRadius.ACTIVE_SAFE,  # sends a real request -> the Governor gates it
        est_requests=1,
        rate_limit_rps=5.0,
    )

    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        if not isinstance(inp, ReplayInput):
            return PrimitiveResult(summary="bad input", is_error=True)
        try:
            ctx.scope.assert_in_scope(inp.url)
        except ScopeViolation as e:
            return PrimitiveResult(summary=f"out of scope: {e}", is_error=True)

        headers: dict[str, str] = {}
        if inp.token:
            headers["Authorization"] = f"Bearer {inp.token}"
        try:
            async with httpx.AsyncClient(
                timeout=10.0, verify=False, follow_redirects=False  # noqa: S501
            ) as client:
                resp = await client.request(inp.method, inp.url, headers=headers)
        except httpx.HTTPError as e:
            return PrimitiveResult(summary=f"request failed: {e}", is_error=True, requests_made=1)

        body = resp.text
        txn = HttpTransaction(
            source=self.name,
            method=inp.method,
            url=inp.url,
            req_headers={"authorization": "<redacted>"} if inp.token else {},
            status=resp.status_code,
            resp_body_sha=hashlib.sha256(body.encode()).hexdigest()[:16],
            role_label=inp.role_label,
        )
        return PrimitiveResult(
            facts=[txn],
            data={
                "status": resp.status_code,
                "body": body,
                "content_type": resp.headers.get("content-type", ""),
            },
            requests_made=1,
            summary=f"{inp.method} {inp.url} -> {resp.status_code}",
        )
