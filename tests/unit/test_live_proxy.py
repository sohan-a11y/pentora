"""Live proxy ingestion: a request routed through e.start_proxy() lands facts on the blackboard."""
from __future__ import annotations

import socket
import time
from typing import Any

import pytest

pytest.importorskip("mitmproxy")
pytest.importorskip("py_trees")

import httpx  # noqa: E402

from pentora.engine.app import start  # noqa: E402


class _Fake:
    def classify(self, system: str, user: str) -> dict[str, Any]:
        return {"is_vulnerable": False}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def test_live_proxy_captures_traffic(jwt_server) -> None:  # noqa: ANN001
    e = start(target="http://127.0.0.1", scope_hosts=["127.0.0.1"], classifier=_Fake())
    proxy_port = _free_port()
    proxy_url = e.start_proxy(port=proxy_port)
    try:
        with jwt_server("secret") as base:                 # a plain-HTTP target
            httpx.get(f"{base}/api/orders", proxy=proxy_url, timeout=10.0,
                      headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.x"})
            # the proxy thread writes asynchronously — wait for the fact to appear
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline and not e.bb.query("http_txn"):
                time.sleep(0.1)
        txns = e.bb.query("http_txn")
        assert txns, "live proxy did not capture the request"
        assert any("/api/orders" in t.url for t in txns)
    finally:
        e.stop_proxy()


def test_live_proxy_start_fails_loudly_on_occupied_port() -> None:
    """Regression: readiness was signalled before the socket bound, so a port-in-use start could
    report false success. start() must actively confirm the listener and raise otherwise."""
    from pentora.engine.blackboard import Blackboard
    from pentora.engine.live import LiveProxy

    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy_port = int(blocker.getsockname()[1])
    proxy = LiveProxy(Blackboard(), host="127.0.0.1", port=busy_port)
    try:
        with pytest.raises(RuntimeError):
            proxy.start(timeout=5.0)
    finally:
        proxy.stop()
        blocker.close()
