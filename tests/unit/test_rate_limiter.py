"""RateLimiter token-bucket math + Governor enforcement on active primitives."""
from __future__ import annotations

import asyncio

from pydantic import BaseModel

from pentora.engine import (
    BlastRadius,
    Capability,
    Governor,
    Primitive,
    PrimitiveResult,
    RateLimiter,
    RunContext,
    RunScope,
)


class _In(BaseModel):
    pass


class _ActivePrim(Primitive):
    name = "active"
    capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.ACTIVE_SAFE
    )

    async def run(self, inp, ctx):  # noqa: ANN001, ANN201
        return PrimitiveResult(summary="ok", requests_made=1)


class _PassivePrim(Primitive):
    name = "passive"
    capability = Capability(
        read_only=True, destructive=False, idempotent=True, blast_radius=BlastRadius.PASSIVE
    )

    async def run(self, inp, ctx):  # noqa: ANN001, ANN201
        return PrimitiveResult(summary="ok")


def test_rate_limiter_bursts_then_throttles() -> None:
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    clock = [0.0]
    rl = RateLimiter(rps=10, burst=1, clock=lambda: clock[0], sleep=fake_sleep)

    async def main() -> None:
        await rl.acquire()   # burst token available -> no sleep
        await rl.acquire()   # empty, clock not advanced -> wait 1/10s
        await rl.acquire()   # still empty -> wait again

    asyncio.run(main())
    assert len(slept) == 2
    assert abs(slept[0] - 0.1) < 1e-9
    assert abs(slept[1] - 0.1) < 1e-9


def test_rate_limiter_refills_over_time() -> None:
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    clock = [0.0]
    rl = RateLimiter(rps=10, burst=1, clock=lambda: clock[0], sleep=fake_sleep)

    async def main() -> None:
        await rl.acquire()   # uses the burst token
        clock[0] = 1.0       # 1s later -> bucket refilled
        await rl.acquire()   # token available -> no sleep

    asyncio.run(main())
    assert slept == []


def test_rate_limiter_zero_rps_is_unlimited() -> None:
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)

    rl = RateLimiter(rps=0, sleep=fake_sleep)

    async def main() -> None:
        for _ in range(50):
            await rl.acquire()

    asyncio.run(main())
    assert slept == []


def test_governor_rate_limits_active_but_not_passive() -> None:
    calls = {"n": 0}

    class _RecordingLimiter(RateLimiter):
        def __init__(self) -> None:
            super().__init__(rps=1000)

        async def acquire(self) -> None:
            calls["n"] += 1

    gov = Governor(rate_limiter=_RecordingLimiter())
    ctx = RunContext(scope=RunScope())

    asyncio.run(gov.execute(_PassivePrim(), _In(), ctx))
    assert calls["n"] == 0                     # passive is never throttled

    asyncio.run(gov.execute(_ActivePrim(), _In(), ctx))
    assert calls["n"] == 1                     # active goes through the limiter


def test_governor_without_limiter_still_works() -> None:
    res = asyncio.run(Governor().execute(_ActivePrim(), _In(), RunContext(scope=RunScope())))
    assert not res.is_error
