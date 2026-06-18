from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.modules.recon import ReconModule
from pentora.scope import Scope
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.httpx_tool import HttpxResult


@pytest.mark.asyncio
async def test_recon_module_produces_findings(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=["api.pure.app", "cdn.pure.app"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.pure.app", status_code=200, title="API", tech=["nginx"]),
            HttpxResult(url="https://cdn.pure.app", status_code=403, title=""),
        ])

        module = ReconModule()
        findings = await module.run(ctx)

    assert len(findings) >= 2  # at least one finding per live host
    titles = [f.title for f in findings]
    assert any("api.pure.app" in t for t in titles)


@pytest.mark.asyncio
async def test_recon_module_writes_live_hosts_file(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=["api.pure.app"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.pure.app", status_code=200, title="API"),
            HttpxResult(url="https://cdn.pure.app", status_code=403, title=""),
        ])
        await ReconModule().run(ctx)

    live_hosts = (tmp_path / "recon" / "live-hosts.txt").read_text()
    assert "https://api.pure.app" in live_hosts
    assert "https://cdn.pure.app" in live_hosts


@pytest.mark.asyncio
async def test_recon_falls_back_to_native_probe_when_cli_empty(tmp_path: Path) -> None:
    """If the httpx CLI yields nothing (e.g. wrong `httpx` on PATH), native probe runs."""
    ctx = ScanContext(
        target="https://pure.app", output_dir=tmp_path, config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http, \
         patch("pentora.modules.recon._native_probe", new_callable=AsyncMock) as native:
        Sub.return_value.run = AsyncMock(return_value=[])
        Http.return_value.run = AsyncMock(return_value=[])  # wrong/empty CLI output
        native.return_value = [
            HttpxResult(url="https://pure.app", status_code=200, title="Home", tech=["nginx"]),
        ]
        findings = await ReconModule().run(ctx)

    native.assert_awaited_once()
    assert any("pure.app" in f.title for f in findings)


@pytest.mark.asyncio
async def test_recon_survives_missing_subfinder(tmp_path: Path) -> None:
    """A missing subfinder must not abort recon; it still probes the primary host."""
    ctx = ScanContext(
        target="https://pure.app", output_dir=tmp_path, config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    await ctx.prepare()

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(side_effect=ToolNotInstalled("subfinder"))
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://pure.app", status_code=200, title="Home"),
        ])
        findings = await ReconModule().run(ctx)

    assert any("pure.app" in f.title for f in findings)
