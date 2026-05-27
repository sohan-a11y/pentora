from pathlib import Path

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.scope import Scope


@pytest.mark.asyncio
async def test_scan_context_creates_output_dirs(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    await ctx.prepare()
    assert (tmp_path / "out").is_dir()
    assert (tmp_path / "out" / "findings").is_dir()
    assert (tmp_path / "out" / "logs").is_dir()
    assert (tmp_path / "out" / "recon").is_dir()


@pytest.mark.asyncio
async def test_scan_context_writes_scope_lock(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()
    lock = (tmp_path / "out" / "scope.lock").read_text()
    assert "pure.app" in lock
    assert "*.pure.app" in lock
