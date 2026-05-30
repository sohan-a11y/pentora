from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.modules.recon import ReconModule
from pentora.scope import Scope
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
