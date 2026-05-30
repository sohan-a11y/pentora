from pathlib import Path

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.scope import Scope
from pentora.targets import Candidate, gather_candidates


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
    )


def _finding(module: str, endpoint: str, **extra: object) -> Finding:
    return Finding(
        module=module,
        title="t",
        endpoint=endpoint,
        method="GET",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra=dict(extra),
    )


@pytest.mark.asyncio
async def test_gather_candidates_reads_discovery_and_recon(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("recon.subdomain", "https://api.t.example"))
    await ctx.store.add(
        _finding("discovery.endpoint", "https://api.t.example/users?id=1", params=["id"])
    )

    candidates = await gather_candidates(ctx)

    urls = {c.url for c in candidates}
    assert "https://api.t.example" in urls
    assert "https://api.t.example/users?id=1" in urls
    by_url = {c.url: c for c in candidates}
    assert by_url["https://api.t.example/users?id=1"].params == ["id"]


@pytest.mark.asyncio
async def test_gather_candidates_dedups_by_url_and_method(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    # Two findings pointing at the same endpoint with the same method.
    await ctx.store.add(_finding("discovery.endpoint", "https://api.t.example/x"))
    await ctx.store.add(_finding("recon.subdomain", "https://api.t.example/x"))

    candidates = await gather_candidates(ctx)

    same = [c for c in candidates if c.url == "https://api.t.example/x"]
    assert len(same) == 1


@pytest.mark.asyncio
async def test_gather_candidates_empty_store_returns_empty(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert await gather_candidates(ctx) == []


@pytest.mark.asyncio
async def test_gather_candidates_no_store_returns_empty(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)  # not prepared; store is None
    assert await gather_candidates(ctx) == []


def test_candidate_defaults() -> None:
    c = Candidate(url="https://x")
    assert c.method == "GET"
    assert c.params == []
    assert c.kind == "url"
