"""Logging setup — structlog for app logs, JSON per-invocation log for tools."""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import structlog


def setup_logging(log_file: Path, level: int = logging.INFO, console: bool = False) -> None:
    """Configure logging. Detailed logs go to ``log_file``; the console stays clean.

    Set ``console=True`` to also stream logs to stderr (useful for debugging). When
    a file handler is attached, Python's last-resort stderr handler is suppressed,
    so raw event names no longer leak into normal CLI output.
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [logging.FileHandler(log_file, encoding="utf-8")]
    if console:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        handlers=handlers,
        force=True,
    )
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


def log_tool_invocation(
    log_dir: Path,
    tool: str,
    argv: list[str],
    stdout: str,
    stderr: str,
    returncode: int,
    duration_ms: int,
) -> None:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "tool": tool,
        "argv": argv,
        "stdout": stdout[:50000],
        "stderr": stderr[:10000],
        "returncode": returncode,
        "duration_ms": duration_ms,
    }
    fp = log_dir / f"{ts}-{tool}.json"
    fp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
