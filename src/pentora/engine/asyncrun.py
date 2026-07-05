"""Run a coroutine to completion from sync code, whether or not a loop is already running.

Playbooks and the ``Engine`` facade call async ``Primitive``s from synchronous code (py_trees
``update()`` methods, dataclass methods). ``asyncio.run()`` is correct when nothing else owns the
event loop — the common case in scripts and tests — but it raises ``RuntimeError`` when called
from inside a host that already runs one. Notably: Jupyter/IPython/Colab kernels, which execute
cell code as a coroutine on the kernel's own loop.

A dedicated-thread-with-a-fresh-loop is the "textbook" fix for this and works in plain CPython,
but Google Colab's kernel runtime does not isolate a new thread's asyncio state cleanly in
practice — a fresh ``asyncio.run()`` on a brand-new thread has been observed to still raise the
same "cannot be called from a running event loop" error there (likely a uvloop or kernel-specific
peculiarity). ``nest_asyncio`` sidesteps this entirely by patching the *existing*, already-running
loop to be re-entrant instead of creating a new one — it is the standard, purpose-built fix for
exactly this class of problem, and does not depend on thread/loop isolation working correctly in
the host. Lazily imported: scripts and tests that never hit a running loop never need it installed.
"""
from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run ``coro`` to completion and return its result, regardless of an ambient running loop.

    Call this DIRECTLY from sync code — never wrap the call site in your own ``asyncio.run()``.
    Inside a notebook kernel the ambient loop already exists (that's the whole reason this
    function exists); an extra ``asyncio.run()`` around it is itself an invalid nested call and
    raises before ``run_sync`` ever runs.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)                          # no loop here — the common case

    import nest_asyncio  # lazy: only needed inside a notebook

    nest_asyncio.apply()                                  # idempotent — safe to call every time
    return asyncio.run(coro)
