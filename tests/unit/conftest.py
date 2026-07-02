"""Shared fixtures for engine tests — a real local HTTP server that validates HS256 JWTs.

This replaces the retired DemoProtectedResource: tests now fire real requests at a live server
that checks the token signature and the ``role`` claim, so the replay primitive and validator
run against ground truth.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


def _validate(token: str, secret: str) -> tuple[int, str]:
    parts = token.split(".")
    if len(parts) != 3:
        return 401, "malformed"
    h, p, sig = parts
    expected = (
        base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    if not hmac.compare_digest(expected, sig):
        return 401, "unauthorized"
    try:
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return 400, "bad payload"
    if payload.get("role") == "admin":
        return 200, "ADMIN_PANEL: users, secrets, api-keys"
    return 403, "forbidden"


@contextmanager
def _serve(secret: str) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            code, body = _validate(token, secret)
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:  # silence server logs
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


@pytest.fixture
def jwt_server() -> Callable[[str], object]:
    """Return a context manager: ``with jwt_server(secret) as base_url: ...``."""
    return _serve
