from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.discovery import DiscoveryModule
from pentora.modules.discovery_probes import DiscoveryHit
from pentora.scope import Scope


def test_hit_to_finding_returns_none_for_unknown_kind() -> None:
    hit = DiscoveryHit(url="https://x/y", kind="mystery", evidence="HTTP 200")
    assert DiscoveryModule._hit_to_finding(hit) is None


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://pure.app",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )


@pytest.mark.asyncio
@respx.mock
async def test_discovery_emits_env_and_vcs_and_swagger_findings(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    (tmp_path / "recon" / "live-hosts.txt").write_text("https://api.pure.app\n")

    # Built-in probes: env exposed (high), git config exposed (high), swagger (medium).
    respx.get("https://api.pure.app/.env").mock(return_value=httpx.Response(200))
    respx.get("https://api.pure.app/.git/config").mock(return_value=httpx.Response(200))
    respx.get("https://api.pure.app/swagger.json").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))

    with patch("pentora.modules.discovery.FfufWrapper") as Ffuf, \
         patch("pentora.modules.discovery.ArjunWrapper") as Arjun, \
         patch("pentora.modules.discovery.KatanaWrapper") as Katana:
        Ffuf.return_value.run = AsyncMock(return_value=[])
        Arjun.return_value.run = AsyncMock(return_value=[])
        Katana.return_value.run = AsyncMock(return_value=[])
        findings = await DiscoveryModule().run(ctx)

    kinds = {f.module for f in findings}
    assert "discovery.env" in kinds
    assert "discovery.vcs" in kinds
    assert "discovery.swagger" in kinds

    env = next(f for f in findings if f.module == "discovery.env")
    assert env.severity in (Severity.HIGH, Severity.CRITICAL)
    swagger = next(f for f in findings if f.module == "discovery.swagger")
    assert swagger.severity == Severity.MEDIUM


@pytest.mark.asyncio
@respx.mock
async def test_discovery_emits_graphql_introspection(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    (tmp_path / "recon" / "live-hosts.txt").write_text("https://api.pure.app\n")

    respx.get("https://api.pure.app/graphql").mock(return_value=httpx.Response(200))
    respx.post("https://api.pure.app/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"__schema": {"types": []}}})
    )
    respx.route().mock(return_value=httpx.Response(404))

    with patch("pentora.modules.discovery.FfufWrapper") as Ffuf, \
         patch("pentora.modules.discovery.ArjunWrapper") as Arjun, \
         patch("pentora.modules.discovery.KatanaWrapper") as Katana:
        Ffuf.return_value.run = AsyncMock(return_value=[])
        Arjun.return_value.run = AsyncMock(return_value=[])
        Katana.return_value.run = AsyncMock(return_value=[])
        findings = await DiscoveryModule().run(ctx)

    graphql = [f for f in findings if f.module == "discovery.graphql"]
    assert graphql
    assert any("introspection" in f.evidence.lower() for f in graphql)


@pytest.mark.asyncio
async def test_discovery_no_live_hosts_returns_empty(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    # No live-hosts.txt written.
    findings = await DiscoveryModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_discovery_persists_findings_to_store(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    (tmp_path / "recon" / "live-hosts.txt").write_text("https://api.pure.app\n")

    respx.get("https://api.pure.app/.env").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))

    with patch("pentora.modules.discovery.FfufWrapper") as Ffuf, \
         patch("pentora.modules.discovery.ArjunWrapper") as Arjun, \
         patch("pentora.modules.discovery.KatanaWrapper") as Katana:
        Ffuf.return_value.run = AsyncMock(return_value=[])
        Arjun.return_value.run = AsyncMock(return_value=[])
        Katana.return_value.run = AsyncMock(return_value=[])
        await DiscoveryModule().run(ctx)

    assert ctx.store is not None
    stored = await ctx.store.all()
    assert any(f.module == "discovery.env" for f in stored)
