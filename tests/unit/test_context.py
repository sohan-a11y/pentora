from pathlib import Path

import httpx
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


@pytest.mark.asyncio
async def test_scan_context_extra_dict(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
        extra={"apk_path": "/tmp/test.apk"},
    )
    assert ctx.extra["apk_path"] == "/tmp/test.apk"


@pytest.mark.asyncio
async def test_scan_context_extra_dict_default_empty(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    assert ctx.extra == {}


@pytest.mark.asyncio
async def test_scan_context_http_client_no_proxy(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    client = ctx.http_client()
    assert isinstance(client, httpx.AsyncClient)
    await client.aclose()


@pytest.mark.asyncio
async def test_scan_context_http_client_with_proxy(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
        proxy_url="http://127.0.0.1:8080",
    )
    client = ctx.http_client()
    assert isinstance(client, httpx.AsyncClient)
    await client.aclose()


@pytest.mark.asyncio
async def test_scan_context_proxy_url_default_none(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    assert ctx.proxy_url is None
