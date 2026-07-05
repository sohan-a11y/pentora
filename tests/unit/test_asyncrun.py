"""asyncrun.run_sync: a coroutine must complete correctly whether or not a loop is already
running — reproduces the exact Jupyter/Colab failure (``asyncio.run() cannot be called from a
running event loop``) that broke every playbook when the engine ran inside a notebook kernel."""
from __future__ import annotations

import asyncio

import pytest

from pentora.engine.asyncrun import run_sync


async def _add(a: int, b: int) -> int:
    return a + b


async def _boom() -> None:
    raise ValueError("boom")


def test_run_sync_without_a_running_loop() -> None:
    assert run_sync(_add(2, 3)) == 5


def test_run_sync_propagates_exceptions_without_a_running_loop() -> None:
    with pytest.raises(ValueError, match="boom"):
        run_sync(_boom())


def test_run_sync_from_within_a_running_loop() -> None:
    """Reproduces a Jupyter/Colab kernel: cell code runs as a coroutine on an ALREADY running
    event loop, which makes a bare ``asyncio.run()`` raise RuntimeError."""
    async def _drive() -> int:
        asyncio.get_running_loop()                        # sanity: a loop really is running here
        return run_sync(_add(10, 20))                      # must NOT raise, must return correctly

    assert asyncio.run(_drive()) == 30


def test_run_sync_propagates_exceptions_from_within_a_running_loop() -> None:
    async def _drive() -> None:
        run_sync(_boom())

    with pytest.raises(ValueError, match="boom"):
        asyncio.run(_drive())
