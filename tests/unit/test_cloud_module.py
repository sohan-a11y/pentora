"""TDD tests for CloudModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.cloud import CloudModule
from pentora.scope import Scope


def _ctx(tmp_path: Path, target: str = "https://pure.app") -> ScanContext:
    return ScanContext(
        target=target,
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )


@pytest.mark.asyncio
@respx.mock
async def test_open_firebase_flagged_critical(tmp_path: Path) -> None:
    """Firebase .json endpoint returning data => CRITICAL finding."""
    respx.get("https://pure.firebaseio.com/.json").mock(
        return_value=httpx.Response(200, json={"users": {"uid1": "data"}})
    )
    # Mock all other probes as 404
    respx.route(method="GET").mock(return_value=httpx.Response(404))
    with patch(
        "pentora.modules.cloud.S3ScannerWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        ctx = _ctx(tmp_path)
        await ctx.prepare()
        findings = await CloudModule().run(ctx)
    firebase = [f for f in findings if "firebase" in f.title.lower()]
    assert len(firebase) >= 1
    assert firebase[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_open_azure_blob_medium(tmp_path: Path) -> None:
    """Azure blob 200 => MEDIUM finding."""
    # Firebase and S3 should return 404/miss
    respx.get("https://pure.firebaseio.com/.json").mock(return_value=httpx.Response(401))
    respx.get("https://pureapp.firebaseio.com/.json").mock(return_value=httpx.Response(401))
    respx.get("https://pure-app.firebaseio.com/.json").mock(return_value=httpx.Response(401))
    respx.get("https://pure.blob.core.windows.net/$web/index.html").mock(
        return_value=httpx.Response(200, text="<html>hello</html>")
    )
    respx.get("https://pureapp.blob.core.windows.net/$web/index.html").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://pure-app.blob.core.windows.net/$web/index.html").mock(
        return_value=httpx.Response(404)
    )
    # GCS
    respx.get("https://storage.googleapis.com/pure/").mock(return_value=httpx.Response(404))
    respx.get("https://storage.googleapis.com/pureapp/").mock(return_value=httpx.Response(404))
    respx.get("https://storage.googleapis.com/pure-app/").mock(return_value=httpx.Response(404))
    with patch(
        "pentora.modules.cloud.S3ScannerWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        ctx = _ctx(tmp_path)
        await ctx.prepare()
        findings = await CloudModule().run(ctx)
    azure = [f for f in findings if "azure" in f.title.lower() or "blob" in f.title.lower()]
    assert len(azure) >= 1
    assert any(f.severity == Severity.MEDIUM for f in azure)


@pytest.mark.asyncio
@respx.mock
async def test_no_open_services_no_findings(tmp_path: Path) -> None:
    """All cloud probes return 403/404 => no findings."""
    respx.route(method="GET").mock(return_value=httpx.Response(403))
    with patch(
        "pentora.modules.cloud.S3ScannerWrapper.run",
        new_callable=AsyncMock,
        return_value=[],
    ):
        ctx = _ctx(tmp_path)
        await ctx.prepare()
        findings = await CloudModule().run(ctx)
    assert findings == []
