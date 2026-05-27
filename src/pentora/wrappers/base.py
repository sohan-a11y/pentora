"""Base class for external command-line tool wrappers."""
from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pentora.logging_setup import log_tool_invocation


class ToolNotInstalled(RuntimeError):
    """Raised when the wrapped tool is not on PATH."""


class ToolWrapper(ABC):
    tool_name: str = ""
    install_check_argv: list[str] = []

    def __init__(self, log_dir: Path | None = None, timeout_s: int = 300):
        self._log_dir = log_dir
        self._timeout_s = timeout_s

    def installed(self) -> bool:
        return shutil.which(self.tool_name) is not None

    @abstractmethod
    def build_argv(self, *args: Any, **kwargs: Any) -> list[str]: ...

    @abstractmethod
    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]: ...

    async def run(self, *args: Any, **kwargs: Any) -> list[Any]:
        if not self.installed():
            raise ToolNotInstalled(f"{self.tool_name} not found on PATH")

        argv = self.build_argv(*args, **kwargs)
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=self._timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            raise
        duration_ms = int((time.monotonic() - t0) * 1000)

        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")

        if self._log_dir is not None:
            log_tool_invocation(
                log_dir=self._log_dir,
                tool=self.tool_name,
                argv=argv,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode or 0,
                duration_ms=duration_ms,
            )

        return self.parse(stdout, stderr, proc.returncode or 0)
