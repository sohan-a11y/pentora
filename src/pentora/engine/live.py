"""Live mitmproxy ingestion in a background thread — feeds the blackboard while a browser (or any
client) drives the target through the proxy. mitmproxy is imported lazily so this module loads
without it. The Blackboard is thread-safe, so the proxy thread writes while the main thread reads.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any

from pentora.engine.blackboard import Blackboard
from pentora.engine.capture import CaptureAddon


class _ReadyAddon:
    """A mitmproxy addon whose ``running`` hook fires only after the servers actually bind — the
    authoritative 'the listener is up' signal (a bind failure exits before this ever runs)."""

    def __init__(self, event: threading.Event) -> None:
        self._event = event

    def running(self) -> None:
        self._event.set()


class LiveProxy:
    def __init__(
        self,
        blackboard: Blackboard,
        host: str = "127.0.0.1",
        port: int = 8080,
        scope_hosts: list[str] | None = None,
    ) -> None:
        self.bb = blackboard
        self.host = host
        self.port = port
        self.scope_hosts = scope_hosts or []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self, timeout: float = 10.0) -> str:
        ready = threading.Event()
        errors: list[BaseException] = []

        async def _serve() -> None:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            opts = Options(listen_host=self.host, listen_port=self.port)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(CaptureAddon(self.bb, self.scope_hosts))
            master.addons.add(_ReadyAddon(ready))         # fires only once the listener binds
            self._master = master
            await master.run()                            # blocks until shutdown()

        def _run() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                loop.run_until_complete(_serve())
            except BaseException as e:  # noqa: BLE001 - mitmproxy exits via SystemExit on bind failure
                errors.append(e)
                ready.set()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        # ready is set by _ReadyAddon.running() ONLY after a successful bind, or by the error path
        # on failure (which also populates ``errors``). So an unbindable port fails loudly here.
        if not ready.wait(timeout):
            raise RuntimeError("live proxy failed to start within timeout")
        if errors:
            raise RuntimeError(f"live proxy failed to start: {errors[0]}")
        return self.url

    def stop(self) -> None:
        if self._loop is not None:
            if self._master is not None:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            else:                                      # master never built — still unwind the loop
                self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
