from pathlib import Path

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.orchestrator import Orchestrator
from pentora.reporters.json_reporter import JsonReporter
from pentora.scope import Scope


class FakeModule(PhaseModule):
    name = "fake"

    async def run(self, ctx):
        f = Finding(module="fake", title="ok", endpoint="https://x.com",
                    method="-", evidence="-",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))
        if ctx.store:
            await ctx.store.add(f)
        return [f]


@pytest.mark.asyncio
async def test_orchestrator_runs_modules_and_reporters(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://x.com",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["x.com"]),
    )
    orc = Orchestrator(modules=[FakeModule()], reporters=[JsonReporter()])
    await orc.run(ctx)
    assert (tmp_path / "summary.json").exists()


@pytest.mark.asyncio
async def test_orchestrator_calls_phase_hooks(tmp_path: Path) -> None:
    started: list[str] = []
    ended: list[str] = []

    async def on_start(name: str, ctx: ScanContext) -> None:
        started.append(name)

    async def on_end(name: str, ctx: ScanContext) -> None:
        ended.append(name)

    ctx = ScanContext(
        target="https://x.com",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["x.com"]),
    )
    orc = Orchestrator(
        modules=[FakeModule()],
        reporters=[JsonReporter()],
        on_phase_start=on_start,
        on_phase_end=on_end,
    )
    await orc.run(ctx)
    assert started == ["fake"]
    assert ended == ["fake"]


@pytest.mark.asyncio
async def test_orchestrator_no_hooks(tmp_path: Path) -> None:
    """Orchestrator works fine when no hooks are provided (default=None)."""
    ctx = ScanContext(
        target="https://x.com",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["x.com"]),
    )
    orc = Orchestrator(modules=[FakeModule()], reporters=[JsonReporter()])
    await orc.run(ctx)  # must not raise
    assert (tmp_path / "summary.json").exists()
