"""Scan orchestrator — runs phase modules, then reporters."""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from pentora.context import ScanContext
from pentora.modules.base import PhaseModule
from pentora.reporters.base import Reporter

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        modules: list[PhaseModule],
        reporters: list[Reporter],
        on_phase_start: Callable[[str, ScanContext], Awaitable[None]] | None = None,
        on_phase_end: Callable[[str, ScanContext], Awaitable[None]] | None = None,
    ) -> None:
        self._modules = modules
        self._reporters = reporters
        self._on_phase_start = on_phase_start
        self._on_phase_end = on_phase_end

    async def run(self, ctx: ScanContext) -> None:
        await ctx.prepare()
        assert ctx.store is not None

        for module in self._modules:
            log.info("phase_start", extra={"module": module.name})
            if self._on_phase_start is not None:
                await self._on_phase_start(module.name, ctx)
            try:
                await module.run(ctx)
            except Exception as e:  # noqa: BLE001 - per-module isolation, log and continue
                log.error("phase_failed", extra={"module": module.name, "error": str(e)})
            if self._on_phase_end is not None:
                await self._on_phase_end(module.name, ctx)

        findings = await ctx.store.all()
        for reporter in self._reporters:
            try:
                out = await reporter.write(ctx.output_dir, findings, ctx.target)
                log.info("report_written", extra={"reporter": reporter.name, "path": str(out)})
            except Exception as e:  # noqa: BLE001 - per-reporter isolation, log and continue
                log.error("reporter_failed", extra={"reporter": reporter.name, "error": str(e)})
