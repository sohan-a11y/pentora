"""Tests for phase-resume support."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from pentora.cli import main
from pentora.context import ScanContext
from pentora.orchestrator import Orchestrator
from pentora.reporters.base import Reporter


class _FakeReporter(Reporter):
    name = "fake"
    output_filename = "fake.json"

    async def write(self, output_dir: Path, findings: list, target: str) -> Path:
        out = output_dir / self.output_filename
        out.write_text("[]")
        return out


@pytest.mark.asyncio
async def test_orchestrator_writes_state_json(tmp_path: Path) -> None:
    """Orchestrator should write state.json after each phase."""
    module_a = MagicMock()
    module_a.name = "recon"
    module_a.run = AsyncMock()

    module_b = MagicMock()
    module_b.name = "discovery"
    module_b.run = AsyncMock()

    from pentora.config import load_config
    from pentora.scope import Scope

    ctx = ScanContext(
        target="https://target.com",
        output_dir=tmp_path,
        config=load_config(),
        scope=Scope(include=["target.com"]),
    )
    ctx.store = MagicMock()
    ctx.store.all = AsyncMock(return_value=[])
    ctx.prepare = AsyncMock()

    orc = Orchestrator(modules=[module_a, module_b], reporters=[_FakeReporter()])
    await orc.run(ctx)

    state_file = tmp_path / "state.json"
    assert state_file.exists()
    state = json.loads(state_file.read_text())
    assert "completed_phases" in state
    assert "recon" in state["completed_phases"]
    assert "discovery" in state["completed_phases"]
    assert state["target"] == "https://target.com"


def test_scan_resume_skips_completed_phases(tmp_path: Path) -> None:
    """--resume should skip phases already in state.json."""
    out = tmp_path / "report"
    out.mkdir()
    # Write state indicating recon is done
    state = {"completed_phases": ["recon"], "target": "https://target.com"}
    (out / "state.json").write_text(json.dumps(state))

    recon_instantiated = []

    original_recon_init = None

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http, \
         patch("pentora.cli.PHASE_MAP") as phase_map_mock:
        # Track which modules were actually instantiated
        recon_module = MagicMock()
        recon_module.name = "recon"
        recon_module.run = AsyncMock(side_effect=lambda ctx: recon_instantiated.append(1))

        discovery_module = MagicMock()
        discovery_module.name = "discovery"
        discovery_module.run = AsyncMock(return_value=None)

        phase_map_mock.__getitem__ = MagicMock(side_effect={
            "recon": MagicMock(return_value=recon_module),
            "discovery": MagicMock(return_value=discovery_module),
        }.__getitem__)
        phase_map_mock.__contains__ = MagicMock(side_effect=lambda k: k in {"recon", "discovery"})
        phase_map_mock.keys = MagicMock(return_value=["recon", "discovery"])

        Sub.return_value.run = AsyncMock(return_value=[])
        Http.return_value.run = AsyncMock(return_value=[])

        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://target.com",
            "--output", str(out),
            "--phases", "recon,discovery",
            "--resume",
        ])

    assert result.exit_code == 0, result.output
    # recon was in completed_phases → should be skipped, so never run
    assert len(recon_instantiated) == 0
