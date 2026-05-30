import pytest

from pentora.auth.timing_oracle import (
    TimingComparison,
    compare_timings,
    measure,
    median_ms,
)


def test_median_ms_odd_and_even() -> None:
    assert median_ms([0.010, 0.020, 0.030]) == pytest.approx(20.0)
    assert median_ms([0.010, 0.030]) == pytest.approx(20.0)


def test_median_ms_empty_is_zero() -> None:
    assert median_ms([]) == 0.0


def test_compare_timings_flags_significant_delta() -> None:
    fast = [0.010, 0.011, 0.009]
    slow = [0.260, 0.255, 0.265]
    result = compare_timings(fast, slow, threshold_ms=200.0)
    assert isinstance(result, TimingComparison)
    assert result.enumerable is True
    assert result.delta_ms > 200.0


def test_compare_timings_below_threshold_not_enumerable() -> None:
    a = [0.100, 0.102, 0.098]
    b = [0.120, 0.121, 0.119]
    result = compare_timings(a, b, threshold_ms=200.0)
    assert result.enumerable is False


@pytest.mark.asyncio
async def test_measure_times_async_callable_with_injected_clock() -> None:
    ticks = iter([1.0, 1.05, 2.0, 2.20, 3.0, 3.30])  # start/stop pairs

    def fake_clock() -> float:
        return next(ticks)

    async def send() -> None:
        return None

    durations = await measure(send, n=3, clock=fake_clock)
    assert len(durations) == 3
    assert durations[0] == pytest.approx(0.05)
    assert durations[1] == pytest.approx(0.20)
    assert durations[2] == pytest.approx(0.30)
