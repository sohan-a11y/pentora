"""Logging setup — structlog for app logs, JSON per-invocation log for tools."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import structlog


def setup_logging(log_file: Path, level: int = logging.INFO) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
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
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "argv": argv,
        "stdout": stdout[:50000],
        "stderr": stderr[:10000],
        "returncode": returncode,
        "duration_ms": duration_ms,
    }
    fp = log_dir / f"{ts}-{tool}.json"
    fp.write_text(json.dumps(payload, indent=2))
