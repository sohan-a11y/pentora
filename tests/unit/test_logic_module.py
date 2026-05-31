"""TDD tests for LogicModule -- race conditions, overflow, premium bypass, coupon reuse."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.logic import LogicModule
from pentora.scope import Scope


def _ctx(tmp_path: Path, profile: str = "generic") -> ScanContext:
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["t.example"]),
        profile_name=profile,
    )


def _finding(endpoint: str, method: str = "POST", **extra: object) -> Finding:
    return Finding(
        module="discovery.endpoint",
        title="endpoint",
        endpoint=endpoint,
        method=method,
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra=dict(extra),
    )


@pytest.mark.asyncio
@respx.mock
async def test_negative_quantity_accepted_is_high(tmp_path: Path) -> None:
    """Negative quantity accepted by cart endpoint is High."""
    respx.post("https://t.example/cart").mock(
        return_value=httpx.Response(200, json={"total": -100})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/cart"))

    findings = await LogicModule().run(ctx)
    neg_findings = [f for f in findings if "negative" in f.title.lower() or "quantity" in f.title.lower()]
    assert len(neg_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in neg_findings)


@pytest.mark.asyncio
@respx.mock
async def test_negative_quantity_rejected_no_finding(tmp_path: Path) -> None:
    """Negative quantity rejected (400) results in no finding."""
    respx.post("https://t.example/cart").mock(
        return_value=httpx.Response(400, json={"error": "invalid quantity"})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/cart"))

    findings = await LogicModule().run(ctx)
    neg_findings = [f for f in findings if "negative" in f.title.lower() or "quantity" in f.title.lower()]
    assert neg_findings == []


@pytest.mark.asyncio
@respx.mock
async def test_premium_bypass_reflected_is_high(tmp_path: Path) -> None:
    """PUT isPremium=true reflected in GET is High."""
    respx.put("https://t.example/profile").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/profile").mock(
        return_value=httpx.Response(200, json={"isPremium": True, "tier": "premium"})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/profile", method="PUT"))

    findings = await LogicModule().run(ctx)
    bypass_findings = [f for f in findings if "premium" in f.title.lower() or "bypass" in f.title.lower()]
    assert len(bypass_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in bypass_findings)


@pytest.mark.asyncio
@respx.mock
async def test_premium_bypass_not_reflected_no_finding(tmp_path: Path) -> None:
    """PUT isPremium=true NOT reflected in GET is no finding."""
    respx.put("https://t.example/profile").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/profile").mock(
        return_value=httpx.Response(200, json={"isPremium": False, "tier": "free"})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/profile", method="PUT"))

    findings = await LogicModule().run(ctx)
    bypass_findings = [f for f in findings if "premium" in f.title.lower() or "bypass" in f.title.lower()]
    assert bypass_findings == []


@pytest.mark.asyncio
@respx.mock
async def test_coupon_reuse_detected_is_medium(tmp_path: Path) -> None:
    """Same coupon code accepted 3x is Medium."""
    respx.post("https://t.example/checkout").mock(
        return_value=httpx.Response(200, json={"discount": 10})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/checkout"))

    findings = await LogicModule().run(ctx)
    coupon_findings = [f for f in findings if "coupon" in f.title.lower() or "reuse" in f.title.lower()]
    assert len(coupon_findings) >= 1
    assert any(f.severity in (Severity.MEDIUM, Severity.HIGH) for f in coupon_findings)


@pytest.mark.asyncio
@respx.mock
async def test_coupon_reuse_rejected_second_time_no_finding(tmp_path: Path) -> None:
    """Second coupon use rejected is no finding."""
    responses = iter([
        httpx.Response(200, json={"discount": 10}),
        httpx.Response(400, json={"error": "coupon already used"}),
        httpx.Response(400, json={"error": "coupon already used"}),
    ])
    respx.post("https://t.example/checkout").mock(side_effect=lambda req: next(responses))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/checkout"))

    findings = await LogicModule().run(ctx)
    coupon_findings = [f for f in findings if "coupon" in f.title.lower() or "reuse" in f.title.lower()]
    assert coupon_findings == []


@pytest.mark.asyncio
async def test_no_candidates_returns_empty(tmp_path: Path) -> None:
    """Empty store returns no findings."""
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await LogicModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_findings_persisted(tmp_path: Path) -> None:
    """Logic findings are saved to ctx.store."""
    respx.post("https://t.example/cart").mock(
        return_value=httpx.Response(200, json={"total": -99})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/cart"))

    await LogicModule().run(ctx)

    stored = await ctx.store.all()
    logic_stored = [f for f in stored if f.module.startswith("logic")]
    assert len(logic_stored) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_dating_profile_direct_message_is_high(tmp_path: Path) -> None:
    """Dating profile: DM to non-match returns 200 is High."""
    respx.post("https://t.example/messages").mock(
        return_value=httpx.Response(200, json={"sent": True})
    )

    ctx = _ctx(tmp_path, profile="dating")
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/messages"))

    findings = await LogicModule().run(ctx)
    dm_findings = [f for f in findings if "message" in f.title.lower() or "match" in f.title.lower()]
    assert len(dm_findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in dm_findings)


@pytest.mark.asyncio
@respx.mock
async def test_integer_overflow_accepted_is_medium(tmp_path: Path) -> None:
    """Extreme quantity values accepted is at least Medium."""
    respx.post("https://t.example/cart").mock(
        return_value=httpx.Response(200, json={"total": 9999999999})
    )

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/cart"))

    findings = await LogicModule().run(ctx)
    overflow_findings = [f for f in findings if "overflow" in f.title.lower() or "integer" in f.title.lower()]
    assert len(overflow_findings) >= 1
