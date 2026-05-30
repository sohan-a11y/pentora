"""Scope resolver — controls which URLs Pentora may touch."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a URL is forbidden (military / government / explicit deny list)."""


@dataclass
class Scope:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    forbidden_file: Path | None = None
    _forbidden: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.forbidden_file and self.forbidden_file.exists():
            self._forbidden = [
                line.strip()
                for line in self.forbidden_file.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]

    @classmethod
    def from_file(cls, path: Path) -> Scope:
        include: list[str] = []
        exclude: list[str] = []
        exclude_paths: list[str] = []
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                exclude_paths.append(line[1:])
            elif line.startswith("-"):
                exclude.append(line[1:])
            else:
                include.append(line)
        return cls(include=include, exclude=exclude, exclude_paths=exclude_paths)

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        # Forbidden TLD check is absolute
        for forbidden in self._forbidden:
            if host.endswith(forbidden):
                return False

        # Exclude path check
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(path, pattern):
                return False

        # Exclude host check
        for pattern in self.exclude:
            if fnmatch.fnmatch(host, pattern):
                return False

        # Include host check
        return any(fnmatch.fnmatch(host, pattern) for pattern in self.include)

    def assert_in_scope(self, url: str) -> None:
        """Raise ScopeViolation for forbidden URLs; return None when in-scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for forbidden in self._forbidden:
            if host.endswith(forbidden):
                raise ScopeViolation(f"{url} matches forbidden TLD {forbidden}")
        if not self.is_in_scope(url):
            raise ScopeViolation(f"{url} is out of scope")
