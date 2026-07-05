"""Run a coroutine to completion from sync code, whether or not a loop is already running.

Playbooks and the ``Engine`` facade call async ``Primitive``s from synchronous code (py_trees
``update()`` methods, dataclass methods). ``asyncio.run()`` is correct when nothing else owns the
event loop — the common case in scripts and tests — but it raises ``RuntimeError`` when called
from inside a host that already runs one. Notably: Jupyter/IPython/Colab kernels, which execute
cell code as a coroutine on the kernel's own loop, and any async web framework. Detect that case
and run the coroutine on a fresh loop in a dedicated thread instead, so the same sync call works
both in a plain script and inside a notebook.
"""
from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run ``coro`` to completion and return its result, regardless of an ambient running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)                          # no loop here — the common case

    result: list[T] = []
    error: list[BaseException] = []

    def _run() -> None:
        try:
            result.append(asyncio.run(coro))
        except BaseException as e:  # noqa: BLE001 - re-raised on the caller's thread below
            error.append(e)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]
