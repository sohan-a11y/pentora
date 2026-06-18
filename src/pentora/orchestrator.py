"""Scan orchestrator — runs phase modules, then reporters."""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

from pentora.context import ScanContext
from pentora.finding import Finding
from pentora.modules.base import PhaseModule
from pentora.proxy.base import ProxyClient
from pentora.reporters.base import Reporter
from pentora.wrappers.base import ToolNotInstalled

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        modules: list[PhaseModule],
        reporters: list[Reporter],
        on_phase_start: Callable[[str, ScanContext], Awaitable[None]] | None = None,
        on_phase_end: Callable[[str, ScanContext], Awaitable[None]] | None = None,
        proxy_client: ProxyClient | None = None,
    ) -> None:
        self._modules = modules
        self._reporters = reporters
        self._on_phase_start = on_phase_start
        self._on_phase_end = on_phase_end
        self._proxy_client = proxy_client

    async def run(self, ctx: ScanContext) -> None:
        await ctx.prepare()
        assert ctx.store is not None

        proxy_scan_id: str | None = None
        completed_phases: list[str] = []

        for module in self._modules:
            log.info("phase_start", extra={"phase": module.name})
            if self._on_phase_start is not None:
                await self._on_phase_start(module.name, ctx)
            try:
                await module.run(ctx)
            except ToolNotInstalled as e:
                # A missing external tool degrades gracefully — skip, don't abort the scan.
                log.warning("phase_skipped_missing_tool", extra={"phase": module.name, "error": str(e)})  # noqa: E501
            except Exception as e:  # noqa: BLE001 - per-module isolation, log and continue
                log.error("phase_failed", extra={"phase": module.name, "error": str(e)})
            if self._on_phase_end is not None:
                await self._on_phase_end(module.name, ctx)

            # Track completed phases and persist state for resume support
            completed_phases.append(module.name)
            state = {"completed_phases": completed_phases, "target": ctx.target}
            try:
                (ctx.output_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
            except OSError as e:
                log.warning("state_write_failed", extra={"error": str(e)})

            # After recon phase: add discovered hosts to proxy scope
            if self._proxy_client is not None and module.name.startswith("recon"):
                all_findings: list[Finding] = await ctx.store.all()
                recon_hosts = list(
                    {f.endpoint for f in all_findings if f.module.startswith("recon")}
                )
                if recon_hosts:
                    try:
                        await self._proxy_client.add_to_scope(recon_hosts)
                    except Exception as e:  # noqa: BLE001
                        log.warning("proxy_add_scope_failed", extra={"error": str(e)})

            # After discovery phase: start active scan
            if self._proxy_client is not None and module.name.startswith("discovery"):
                all_findings = await ctx.store.all()
                endpoints = list(
                    {f.endpoint for f in all_findings if f.module.startswith("discovery")}
                )
                if endpoints:
                    try:
                        proxy_scan_id = await self._proxy_client.start_active_scan(endpoints)
                    except Exception as e:  # noqa: BLE001
                        log.warning("proxy_start_scan_failed", extra={"error": str(e)})

        # After all phases: wait for proxy scan and collect findings
        if self._proxy_client is not None and proxy_scan_id:
            try:
                await self._proxy_client.wait_for_scan(proxy_scan_id)
                proxy_findings = await self._proxy_client.get_findings()
                for pf in proxy_findings:
                    await ctx.store.add(pf)
                xml_path = str(ctx.output_dir / "burp-export.xml")
                await self._proxy_client.export_xml(xml_path)
            except Exception as e:  # noqa: BLE001
                log.warning("proxy_post_scan_failed", extra={"error": str(e)})

        findings = await ctx.store.all()
        for reporter in self._reporters:
            try:
                out = await reporter.write(ctx.output_dir, findings, ctx.target)
                log.info("report_written", extra={"reporter": reporter.name, "path": str(out)})
            except Exception as e:  # noqa: BLE001 - per-reporter isolation, log and continue
                log.error("reporter_failed", extra={"reporter": reporter.name, "error": str(e)})
