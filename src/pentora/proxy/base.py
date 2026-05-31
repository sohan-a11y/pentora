"""ProxyClient protocol — common interface for Burp and ZAP."""
from __future__ import annotations

from typing import Protocol

from pentora.finding import Finding


class ProxyClient(Protocol):
    name: str
    base_url: str

    async def is_alive(self) -> bool: ...

    async def add_to_scope(self, urls: list[str]) -> None: ...

    async def start_active_scan(self, urls: list[str]) -> str: ...

    async def wait_for_scan(
        self, scan_id: str, poll_interval_s: int = 5, timeout_s: int = 3600
    ) -> None: ...

    async def get_findings(self) -> list[Finding]: ...

    async def export_xml(self, output_path: str) -> None: ...
