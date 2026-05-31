"""Integration test: full 16-module scan with all wrappers mocked."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from click.testing import CliRunner

from pentora.cli import PHASE_MAP, main

# Convenience shortcut to reduce patch line length
_P = patch


def _am() -> AsyncMock:
    return AsyncMock(return_value=[])


def test_phase_map_has_16_modules() -> None:
    """Task 70: confirm all 16 modules in PHASE_MAP."""
    expected = {
        "recon", "discovery", "auth", "authz", "injection",
        "upload", "ssrf", "logic", "disclosure", "transport",
        "headers", "cors", "takeover", "ratelimit", "mobile", "cloud",
    }
    assert set(PHASE_MAP.keys()) == expected, (
        f"Missing: {expected - set(PHASE_MAP.keys())}  "
        f"Extra: {set(PHASE_MAP.keys()) - expected}"
    )


def test_list_modules_shows_all_16() -> None:
    """Task 71: list-modules shows all 16."""
    runner = CliRunner()
    result = runner.invoke(main, ["list-modules"])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.strip().splitlines() if line.strip()]
    assert len(lines) == 16


@respx.mock
def test_dry_run_scan_lists_all_phases(tmp_path: Path) -> None:
    """--dry-run with --phases all should list all 16 phases."""
    out = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "https://t.example", "--output", str(out), "--phases", "all", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    for phase in PHASE_MAP:
        assert phase in result.output


@pytest.mark.asyncio
@respx.mock
async def test_full_mocked_orchestrator_run(tmp_path: Path) -> None:
    """Task 72: Run Orchestrator with all 16 module.run() methods mocked."""
    from pentora.config import Config
    from pentora.context import ScanContext
    from pentora.orchestrator import Orchestrator
    from pentora.reporters.finding_folder import FindingFolderReporter
    from pentora.reporters.html import HtmlReporter
    from pentora.reporters.json_reporter import JsonReporter
    from pentora.reporters.markdown import MarkdownReporter
    from pentora.scope import Scope

    # Catch-all HTTP mocks
    hsts = {"strict-transport-security": "max-age=31536000"}
    respx.route(method="GET").mock(
        return_value=httpx.Response(200, headers=hsts, text="<html></html>")
    )
    respx.route(method="POST").mock(return_value=httpx.Response(429))

    out = tmp_path / "scan_out"
    ctx = ScanContext(
        target="https://t.example",
        output_dir=out,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )

    modules = [cls() for cls in PHASE_MAP.values()]
    reporters = [
        JsonReporter(),
        MarkdownReporter(),
        HtmlReporter(),
        FindingFolderReporter(),
    ]

    # Patch all subprocess-calling wrappers to return []
    _recon = "pentora.modules.recon"
    _disc = "pentora.modules.discovery"
    _inj = "pentora.modules.injection"
    _auth = "pentora.modules.auth"
    _trans = "pentora.modules.transport"
    _cloud = "pentora.modules.cloud"

    with (
        _P(f"{_recon}.SubfinderWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_recon}.HttpxWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_disc}.FfufWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_disc}.ArjunWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_disc}.KatanaWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.SqlmapWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.DalfoxWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.GhauriWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.CommixWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.SmugglerWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.XsstrikeWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_inj}.OralyzerWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_auth}.JwtToolWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_trans}.TlsScanWrapper.run", new_callable=AsyncMock, return_value=[]),
        _P(f"{_cloud}.S3ScannerWrapper.run", new_callable=AsyncMock, return_value=[]),
    ):
        orc = Orchestrator(modules=modules, reporters=reporters)
        await orc.run(ctx)

    # All reporters must have produced output
    assert (out / "summary.json").exists()
    assert (out / "summary.md").exists()
    assert (out / "summary.html").exists()
    assert (out / "findings").is_dir()
