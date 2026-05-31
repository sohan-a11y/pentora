"""TDD tests for MobileModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.mobile import MobileModule
from pentora.scope import Scope


def _ctx(tmp_path: Path, apk_path: str | None = None) -> ScanContext:
    ctx = ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )
    # Store apk_path as an extra attribute for the module to read
    if apk_path is not None:
        object.__setattr__(ctx, "apk_path", apk_path)
    return ctx


@pytest.mark.asyncio
async def test_no_apk_path_returns_empty(tmp_path: Path) -> None:
    """No apk_path in ctx.extra => module returns [] immediately."""
    ctx = ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )
    await ctx.prepare()
    findings = await MobileModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_tool_not_installed_returns_empty(tmp_path: Path) -> None:
    """ToolNotInstalled => module logs warning and returns []."""
    from pentora.wrappers.base import ToolNotInstalled
    ctx = _ctx(tmp_path, apk_path="/tmp/app.apk")
    await ctx.prepare()
    with patch(
        "pentora.modules.mobile.ApktoolWrapper.run",
        side_effect=ToolNotInstalled("apktool not found"),
    ):
        findings = await MobileModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_secret_in_decompiled_source_flagged(tmp_path: Path) -> None:
    """Secret found in decompiled APK source => HIGH finding."""
    from pentora.wrappers.apktool import ApkDecompileResult

    fake_decompile = ApkDecompileResult(
        output_dir=tmp_path / "decompiled",
        manifest_found=True,
        source_dirs=["smali/com/example"],
    )
    # Create a fake source file with a secret
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir(parents=True, exist_ok=True)
    (decompiled / "config.smali").write_text(
        "const-string v0, \"AKIAIOSFODNN7EXAMPLE1234\"\n"
    )
    fake_decompile = ApkDecompileResult(
        output_dir=decompiled,
        manifest_found=True,
        source_dirs=["smali"],
    )
    ctx = _ctx(tmp_path, apk_path=str(tmp_path / "app.apk"))
    # Create dummy apk
    (tmp_path / "app.apk").write_bytes(b"apk-payload-placeholder")
    await ctx.prepare()
    with patch(
        "pentora.modules.mobile.ApktoolWrapper.run",
        new_callable=AsyncMock,
        return_value=[fake_decompile],
    ), patch(
        "pentora.modules.mobile.JadxWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        findings = await MobileModule().run(ctx)

    secret_findings = [
        f for f in findings
        if "secret" in f.title.lower()
        or "disclosure" in f.title.lower()
        or "aws" in f.title.lower()
    ]
    assert len(secret_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in secret_findings)
