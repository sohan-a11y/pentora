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


# ---- IDOR / BOLA server: /api/orders/{id}, ownership per token sub ----------

_ORDERS = {"1": ("user_a", "ALPHA-secret-order-one"), "2": ("user_b", "BETA-secret-order-two")}


def _token_sub(token: str, secret: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, sig = parts
    expected = (
        base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        return str(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("sub"))
    except Exception:
        return None


@contextmanager
def _serve_idor(secret: str, vulnerable: bool = True) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            oid = self.path.rstrip("/").rsplit("/", 1)[-1]
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            sub = _token_sub(token, secret)
            if sub is None:
                code, body = 401, "unauthorized"
            elif oid not in _ORDERS:
                code, body = 404, "not found"
            else:
                owner, data = _ORDERS[oid]
                if not vulnerable and owner != sub:
                    code, body = 403, "forbidden"      # secure: ownership enforced
                else:
                    code, body = 200, data             # vulnerable: any order by id
            payload = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


@pytest.fixture
def idor_server() -> Callable[..., object]:
    """Return a context manager: ``with idor_server(secret, vulnerable=True) as base_url: ...``."""
    return _serve_idor


# ---- SQLi server: /search?q=, boolean-based on a vulnerable build --------------

_ITEMS = {"alpha": "ALPHA_DATA", "beta": "BETA_DATA"}


def _sqli_query(q: str, vulnerable: bool) -> str:
    if not vulnerable:
        return _ITEMS.get(q, "")                       # parameterized: q is an exact literal
    if any(m in q for m in ("OR '1'='1", 'OR "1"="1', "OR ('1'='1")):
        return " ".join(_ITEMS.values())               # TRUE injection -> all rows
    if any(m in q for m in ("AND '1'='2", 'AND "1"="2', "AND ('1'='2")):
        return ""                                      # FALSE injection -> no rows
    name = q.split("'")[0].split('"')[0]               # benign: match up to the injection quote
    return _ITEMS.get(name, "")


@contextmanager
def _serve_sqli(vulnerable: bool = True) -> Iterator[str]:
    from urllib.parse import parse_qs, urlsplit

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            data = _sqli_query(q, vulnerable).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


@pytest.fixture
def sqli_server() -> Callable[..., object]:
    """Context manager: ``with sqli_server(vulnerable=True) as base_url: ...`` (/search?q=)."""
    return _serve_sqli


# ---- XSS server: /echo?name=, reflected unescaped on a vulnerable build --------


@contextmanager
def _serve_xss(vulnerable: bool = True) -> Iterator[str]:
    import html
    from urllib.parse import parse_qs, urlsplit

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            name = parse_qs(urlsplit(self.path).query).get("name", [""])[0]
            shown = name if vulnerable else html.escape(name)
            data = f"<html><body>Hello {shown}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


@pytest.fixture
def xss_server() -> Callable[..., object]:
    """Context manager: ``with xss_server(vulnerable=True) as base_url: ...`` (/echo?name=)."""
    return _serve_xss


# ---- BOLA server: POST /api/objects creates state; GET /api/objects/{id} reads --


@contextmanager
def _serve_bola(secret: str, vulnerable: bool = True) -> Iterator[str]:
    state: dict[str, tuple[str, str]] = {}
    seq = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def _auth(self) -> str | None:
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            return _token_sub(token, secret)

        def _write(self, code: int, body: str) -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:  # noqa: N802
            sub = self._auth()
            if sub is None:
                self._write(401, "unauthorized")
                return
            seq["n"] += 1
            oid = str(seq["n"])
            obj_secret = f"OBJ-{oid}-{sub.upper()}-SECRET"
            state[oid] = (sub, obj_secret)
            self._write(201, json.dumps({"id": oid, "secret": obj_secret}))

        def do_GET(self) -> None:  # noqa: N802
            sub = self._auth()
            oid = self.path.rstrip("/").rsplit("/", 1)[-1]
            if sub is None:
                self._write(401, "unauthorized")
            elif oid not in state:
                self._write(404, "not found")
            else:
                owner, obj_secret = state[oid]
                if not vulnerable and owner != sub:
                    self._write(403, "forbidden")       # secure: object ownership enforced
                else:
                    self._write(200, obj_secret)        # vulnerable: any object by id

        def log_message(self, *args: object) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


@pytest.fixture
def bola_server() -> Callable[..., object]:
    """Context manager: ``with bola_server(secret, vulnerable=True) as base_url: ...``
    (POST /api/objects to create, GET /api/objects/{id} to read)."""
    return _serve_bola
