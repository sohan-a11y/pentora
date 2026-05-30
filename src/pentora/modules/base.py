"""Base class for phase modules."""
from __future__ import annotations

from abc import ABC, abstractmethod

from pentora.context import ScanContext
from pentora.finding import Finding


class PhaseModule(ABC):
    name: str = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]: ...
