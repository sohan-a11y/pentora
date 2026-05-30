"""Base class for reporters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pentora.finding import Finding


class Reporter(ABC):
    name: str = ""
    output_filename: str = ""

    @abstractmethod
    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path: ...
