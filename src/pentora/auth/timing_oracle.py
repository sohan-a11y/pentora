"""Timing oracle — detect username enumeration via response-time deltas."""
from __future__ import annotations

import statistics
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass
class TimingComparison:
    delta_ms: float
    median_a_ms: float
    median_b_ms: float
    enumerable: bool


def median_ms(durations_s: list[float]) -> float:
    """Median of second-valued durations, returned in milliseconds."""
    if not durations_s:
        return 0.0
    return statistics.median(durations_s) * 1000.0


def compare_timings(
    samples_a_s: list[float],
    samples_b_s: list[float],
    threshold_ms: float = 200.0,
) -> TimingComparison:
    """Compare two timing samples; enumerable if the median delta exceeds threshold."""
    median_a = median_ms(samples_a_s)
    median_b = median_ms(samples_b_s)
    delta = abs(median_a - median_b)
    return TimingComparison(
        delta_ms=delta,
        median_a_ms=median_a,
        median_b_ms=median_b,
        enumerable=delta > threshold_ms,
    )


async def measure(
    send: Callable[[], Awaitable[object]],
    n: int,
    clock: Callable[[], float] = time.monotonic,
) -> list[float]:
    """Invoke ``send`` ``n`` times, returning per-call durations in seconds."""
    durations: list[float] = []
    for _ in range(n):
        start = clock()
        await send()
        durations.append(clock() - start)
    return durations
