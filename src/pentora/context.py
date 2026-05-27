"""ScanContext — passed to every module so they share state cleanly."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pentora.config import Config
from pentora.scope import Scope
from pentora.store import FindingsStore


@dataclass
class ScanContext:
    target: str
    output_dir: Path
    config: Config
    scope: Scope
    profile_name: str = "generic"
    token_a: str | None = None
    token_b: str | None = None
    store: FindingsStore | None = None

    async def prepare(self) -> None:
        for sub in ("findings", "logs", "logs/tool-invocations", "recon", "recon/screenshots"):
            (self.output_dir / sub).mkdir(parents=True, exist_ok=True)
        self._write_scope_lock()
        self.store = FindingsStore(self.output_dir / "findings.db")
        await self.store.init()

    def _write_scope_lock(self) -> None:
        lines = ["# scope.lock — exact scope used for this run"]
        for inc in self.scope.include:
            lines.append(inc)
        for exc in self.scope.exclude:
            lines.append(f"-{exc}")
        for p in self.scope.exclude_paths:
            lines.append(f"!{p}")
        (self.output_dir / "scope.lock").write_text("\n".join(lines) + "\n")
