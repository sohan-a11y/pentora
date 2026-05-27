# Pentora Phase 1 — Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold the Pentora project, build the core framework (config, scope, finding model, SQLite store, orchestrator, logging), implement the first 4 reporters (HTML, JSON, Markdown, per-finding folder), and prove the vertical slice end-to-end by running a minimal recon scan and emitting reports.

**Architecture:** Click CLI → Config → ScanContext → Orchestrator → PhaseModule(s) → Finding(s) → Store → Reporter(s). All async. TDD enforced.

**Tech Stack:** Python 3.11+, Click 8.x, asyncio, aiosqlite, httpx, Jinja2, pytest, ruff, mypy.

**Exit criteria:** `pentora https://httpbin.org --phases recon --output ./out/` runs subfinder (mocked in tests, real on Kali), writes findings to SQLite, and produces an HTML report + JSON + Markdown + per-finding folder.

**Phase tag at completion:** `git tag pentora-phase-1-complete`

---

## Task 1: Initialize Python project (pyproject.toml + ruff + mypy + pytest)

**Files:**
- Create: `pyproject.toml`
- Create: `src/pentora/__init__.py`
- Create: `src/pentora/version.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`
- Create: `LICENSE` (AGPLv3 text from https://www.gnu.org/licenses/agpl-3.0.txt)

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "pentora"
dynamic = ["version"]
description = "Autonomous web application pentest orchestrator"
readme = "README.md"
requires-python = ">=3.11"
license = {text = "AGPL-3.0-or-later"}
authors = [{name = "Pentora contributors"}]
keywords = ["pentest", "security", "owasp", "burp", "automation"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "click>=8.1",
    "httpx>=0.27",
    "aiohttp>=3.10",
    "aiosqlite>=0.20",
    "jinja2>=3.1",
    "pyyaml>=6.0",
    "structlog>=24.1",
    "rich>=13.7",
    "pydantic>=2.8",
    "tenacity>=9.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "pytest-cov>=5.0",
    "pytest-mock>=3.14",
    "respx>=0.21",
    "ruff>=0.6",
    "mypy>=1.11",
    "types-PyYAML",
]
browser = ["playwright>=1.47"]
ai = []  # LLM providers use httpx only — no extra deps needed

[project.scripts]
pentora = "pentora.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.dynamic]
version = {attr = "pentora.version.__version__"}

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S", "A", "C4", "T20", "RET", "SIM"]
ignore = ["S101"]  # allow asserts in tests

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S", "ANN"]

[tool.mypy]
strict = true
python_version = "3.11"
plugins = ["pydantic.mypy"]

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false

[tool.pytest.ini_options]
asyncio_mode = "auto"
addopts = "--strict-markers --cov=pentora --cov-report=term-missing --cov-fail-under=80"
testpaths = ["tests"]

[tool.coverage.run]
branch = true
source = ["src/pentora"]
omit = ["*/version.py"]
```

- [ ] **Step 2: Write `src/pentora/version.py`**

```python
"""Single-source version string."""
__version__ = "0.1.0"
```

- [ ] **Step 3: Write `src/pentora/__init__.py`**

```python
"""Pentora — autonomous web app pentest orchestrator."""
from pentora.version import __version__

__all__ = ["__version__"]
```

- [ ] **Step 4: Write `tests/__init__.py`**

```python
```

(empty file, marks tests as a package)

- [ ] **Step 5: Write `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
build/
dist/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
.coverage.*
htmlcov/
*.cover

# Virtualenv
.venv/
venv/
env/

# IDE
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Pentora local
.pentora/
reports/
out/

# Secrets
.env
.env.local
*.key
*.pem
```

- [ ] **Step 6: Add AGPLv3 LICENSE**

Download from https://www.gnu.org/licenses/agpl-3.0.txt and save as `LICENSE`.

- [ ] **Step 7: Set up local dev environment**

```bash
python -m venv .venv
source .venv/bin/activate          # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

Expected: install succeeds, `pentora --help` fails (no CLI yet — that's the next task).

- [ ] **Step 8: Smoke test toolchain**

```bash
ruff check src/
mypy --strict src/pentora/
pytest -q
```

Expected: ruff PASS (empty src, nothing to lint), mypy PASS, pytest PASS (no tests collected).

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml src/pentora/__init__.py src/pentora/version.py tests/__init__.py .gitignore LICENSE
git commit -m "chore: scaffold python project with ruff+mypy+pytest"
```

---

## Task 2: Click CLI shell with --version

**Files:**
- Create: `src/pentora/cli.py`
- Create: `tests/unit/test_cli.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_cli.py`:
```python
from click.testing import CliRunner
from pentora.cli import main
from pentora.version import __version__


def test_cli_version_flag_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for sub in ("scan", "setup", "doctor", "update", "report", "import-results", "list-profiles", "list-modules"):
        assert sub in result.output
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_cli.py -v
```

Expected: ImportError — `pentora.cli` doesn't exist yet.

- [ ] **Step 3: Write `src/pentora/cli.py`**

```python
"""Click-based CLI entry point for Pentora."""
from __future__ import annotations

import click

from pentora.version import __version__


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, prog_name="pentora")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Pentora — autonomous web application pentest orchestrator."""


@main.command()
@click.argument("url")
def scan(url: str) -> None:
    """Run a full pentest scan against URL."""
    click.echo(f"[stub] scan {url}")


@main.command()
def setup() -> None:
    """Install all required tools on Kali."""
    click.echo("[stub] setup")


@main.command()
def doctor() -> None:
    """Diagnose missing tools and misconfigurations."""
    click.echo("[stub] doctor")


@main.command()
def update() -> None:
    """Update nuclei templates, wordlists, fingerprints."""
    click.echo("[stub] update")


@main.command()
@click.argument("findings_db", type=click.Path(exists=True))
def report(findings_db: str) -> None:
    """Regenerate reports from an existing findings DB."""
    click.echo(f"[stub] report {findings_db}")


@main.command("import-results")
@click.argument("source", type=click.Choice(["burp", "zap"]))
@click.argument("path", type=click.Path(exists=True))
def import_results(source: str, path: str) -> None:
    """Import an external scanner's results into Pentora's store."""
    click.echo(f"[stub] import {source} {path}")


@main.command("list-profiles")
def list_profiles() -> None:
    """List available profiles (dating, saas, fintech, ...)."""
    click.echo("[stub] list-profiles")


@main.command("list-modules")
def list_modules() -> None:
    """List available phase modules."""
    click.echo("[stub] list-modules")
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_cli.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Manual smoke test**

```bash
pentora --version
pentora --help
pentora scan https://example.com
```

Expected outputs:
- `pentora, version 0.1.0`
- Help text lists all 8 subcommands
- `[stub] scan https://example.com`

- [ ] **Step 6: Commit**

```bash
git add src/pentora/cli.py tests/unit/test_cli.py
git commit -m "feat(cli): add Click entry point with --version and 8 subcommand stubs"
```

---

## Task 3: Finding model + CVSS scoring

**Files:**
- Create: `src/pentora/finding.py`
- Create: `tests/unit/test_finding.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_finding.py`:
```python
from datetime import datetime, timezone

from pentora.finding import CVSS, Finding, Severity


def test_severity_from_cvss_score() -> None:
    assert Severity.from_score(9.5) is Severity.CRITICAL
    assert Severity.from_score(7.0) is Severity.HIGH
    assert Severity.from_score(4.0) is Severity.MEDIUM
    assert Severity.from_score(0.5) is Severity.LOW
    assert Severity.from_score(0.0) is Severity.INFO


def test_cvss_vector_round_trip() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss = CVSS.from_vector(vector)
    assert cvss.vector == vector
    assert cvss.score == 9.8  # known canonical score
    assert cvss.severity is Severity.CRITICAL


def test_finding_id_is_deterministic_for_same_inputs() -> None:
    a = Finding(
        module="authz.idor",
        title="IDOR on /api/users/{id}",
        endpoint="https://x.com/api/users/12345",
        method="GET",
        evidence="Returned User B's email",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    )
    b = Finding(
        module="authz.idor",
        title="IDOR on /api/users/{id}",
        endpoint="https://x.com/api/users/12345",
        method="GET",
        evidence="Returned User B's email",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    )
    assert a.id == b.id  # deterministic SHA256 of canonical fields


def test_finding_has_timestamp() -> None:
    f = Finding(
        module="recon",
        title="Subdomain found",
        endpoint="https://api.x.com",
        method="-",
        evidence="From subfinder",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    assert f.discovered_at <= datetime.now(timezone.utc)
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_finding.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/finding.py`**

```python
"""Finding data model + CVSS scoring."""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

# CVSS v3.1 metric values (Base score only — Temporal/Environmental not used here).
# Reference: https://www.first.org/cvss/v3.1/specification-document
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score == 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


@dataclass(frozen=True)
class CVSS:
    vector: str
    score: float

    @classmethod
    def from_vector(cls, vector: str) -> "CVSS":
        score = _calc_base_score(vector)
        return cls(vector=vector, score=round(score, 1))

    @property
    def severity(self) -> Severity:
        return Severity.from_score(self.score)


def _calc_base_score(vector: str) -> float:
    # Parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    av = _AV[parts["AV"]]
    ac = _AC[parts["AC"]]
    ui = _UI[parts["UI"]]
    scope_changed = parts["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
    iss = 1 - ((1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]]))
    impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) if not scope_changed else 1.08 * (impact + exploitability)
    return min(raw, 10.0)


@dataclass
class Finding:
    module: str
    title: str
    endpoint: str
    method: str
    evidence: str
    cvss: CVSS
    description: str = ""
    remediation: str = ""
    request_raw: str = ""
    response_raw: str = ""
    screenshot_path: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "pentora"  # pentora | burp | zap | nuclei
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Deterministic ID based on canonical fields."""
        key = f"{self.module}|{self.endpoint}|{self.method}|{self.title}|{self.evidence}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def severity(self) -> Severity:
        return self.cvss.severity
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_finding.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Verify CVSS canonical score**

The test asserts `9.8` for `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — this is the canonical NVD-published score for that vector. If it fails, the calculator is wrong; trace `_calc_base_score`.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/finding.py tests/unit/test_finding.py
git commit -m "feat(finding): add Finding dataclass with deterministic ID and CVSS v3.1 scorer"
```

---

## Task 4: Scope resolver

**Files:**
- Create: `src/pentora/scope.py`
- Create: `tests/unit/test_scope.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_scope.py`:
```python
from pathlib import Path

import pytest

from pentora.scope import Scope, ScopeViolation


def test_scope_allows_exact_host() -> None:
    scope = Scope(include=["pure.app"])
    assert scope.is_in_scope("https://pure.app/login")


def test_scope_allows_wildcard_subdomain() -> None:
    scope = Scope(include=["*.pure.app"])
    assert scope.is_in_scope("https://api.pure.app/v1/users")
    assert scope.is_in_scope("https://cdn.pure.app/img.jpg")
    assert not scope.is_in_scope("https://pure.app/login")  # bare domain not covered by *


def test_scope_excludes_take_precedence() -> None:
    scope = Scope(include=["*.pure.app"], exclude=["admin.pure.app"])
    assert scope.is_in_scope("https://api.pure.app")
    assert not scope.is_in_scope("https://admin.pure.app/dashboard")


def test_scope_path_exclude() -> None:
    scope = Scope(include=["pure.app"], exclude_paths=["/billing/*", "/legal/*"])
    assert scope.is_in_scope("https://pure.app/profile")
    assert not scope.is_in_scope("https://pure.app/billing/invoice/123")


def test_scope_forbidden_domains_always_blocked(tmp_path: Path) -> None:
    forbidden = tmp_path / "forbidden.txt"
    forbidden.write_text(".mil\n.gov\n")
    scope = Scope(include=["*.dod.mil"], forbidden_file=forbidden)
    with pytest.raises(ScopeViolation, match="forbidden TLD"):
        scope.assert_in_scope("https://target.dod.mil/")


def test_scope_load_from_file(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment\n*.pure.app\n-admin.pure.app\n!/billing/*\n")
    scope = Scope.from_file(scope_file)
    assert scope.is_in_scope("https://api.pure.app")
    assert not scope.is_in_scope("https://admin.pure.app")
    assert not scope.is_in_scope("https://api.pure.app/billing/123")
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_scope.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/scope.py`**

```python
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
    def from_file(cls, path: Path) -> "Scope":
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
        for pattern in self.include:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    def assert_in_scope(self, url: str) -> None:
        """Raise ScopeViolation for forbidden URLs, return None for in-scope, raise for out-of-scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for forbidden in self._forbidden:
            if host.endswith(forbidden):
                raise ScopeViolation(f"{url} matches forbidden TLD {forbidden}")
        if not self.is_in_scope(url):
            raise ScopeViolation(f"{url} is out of scope")
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_scope.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/scope.py tests/unit/test_scope.py
git commit -m "feat(scope): add scope resolver with wildcard, exclude, and forbidden-TLD support"
```

---

## Task 5: SQLite findings store

**Files:**
- Create: `src/pentora/store.py`
- Create: `tests/unit/test_store.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_store.py`:
```python
import pytest
from pathlib import Path

from pentora.finding import CVSS, Finding
from pentora.store import FindingsStore


@pytest.mark.asyncio
async def test_store_persists_and_retrieves_finding(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    f = Finding(
        module="recon",
        title="Subdomain found",
        endpoint="https://api.x.com",
        method="-",
        evidence="From subfinder",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    await store.add(f)
    rows = await store.all()
    assert len(rows) == 1
    assert rows[0].id == f.id


@pytest.mark.asyncio
async def test_store_deduplicates_on_id(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    f = Finding(
        module="recon",
        title="dup",
        endpoint="https://x.com",
        method="-",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    await store.add(f)
    await store.add(f)  # same ID — no duplicate
    assert len(await store.all()) == 1


@pytest.mark.asyncio
async def test_store_filter_by_severity(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    high = Finding(
        module="injection",
        title="SQLi",
        endpoint="https://x.com/search",
        method="GET",
        evidence="time-based",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    low = Finding(
        module="headers",
        title="Missing HSTS",
        endpoint="https://x.com/",
        method="GET",
        evidence="No Strict-Transport-Security header",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    )
    await store.add(high)
    await store.add(low)

    criticals_and_highs = await store.by_min_severity("HIGH")
    assert len(criticals_and_highs) == 1
    assert criticals_and_highs[0].title == "SQLi"
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_store.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/store.py`**

```python
"""SQLite-backed async findings store."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from pentora.finding import CVSS, Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    evidence TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    severity TEXT NOT NULL,
    request_raw TEXT NOT NULL DEFAULT '',
    response_raw TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT,
    discovered_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'pentora',
    extra TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_module ON findings(module);
"""

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingsStore:
    def __init__(self, db_path: Path):
        self._path = db_path

    async def init(self) -> None:
        async with aiosqlite.connect(self._path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()

    async def add(self, f: Finding) -> None:
        async with aiosqlite.connect(self._path) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO findings
                (id, module, title, endpoint, method, evidence, description, remediation,
                 cvss_vector, cvss_score, severity, request_raw, response_raw,
                 screenshot_path, discovered_at, source, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.id, f.module, f.title, f.endpoint, f.method, f.evidence,
                    f.description, f.remediation,
                    f.cvss.vector, f.cvss.score, f.severity.value,
                    f.request_raw, f.response_raw, f.screenshot_path,
                    f.discovered_at.isoformat(), f.source, json.dumps(f.extra),
                ),
            )
            await db.commit()

    async def all(self) -> list[Finding]:
        async with aiosqlite.connect(self._path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM findings ORDER BY cvss_score DESC")
            rows = await cur.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def by_min_severity(self, min_severity: str) -> list[Finding]:
        threshold = _SEVERITY_ORDER[Severity[min_severity.upper()]]
        results = []
        for f in await self.all():
            if _SEVERITY_ORDER[f.severity] >= threshold:
                results.append(f)
        return results

    @staticmethod
    def _row_to_finding(row: aiosqlite.Row) -> Finding:
        return Finding(
            module=row["module"],
            title=row["title"],
            endpoint=row["endpoint"],
            method=row["method"],
            evidence=row["evidence"],
            description=row["description"],
            remediation=row["remediation"],
            cvss=CVSS(vector=row["cvss_vector"], score=row["cvss_score"]),
            request_raw=row["request_raw"],
            response_raw=row["response_raw"],
            screenshot_path=row["screenshot_path"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            source=row["source"],
            extra=json.loads(row["extra"]),
        )
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_store.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/store.py tests/unit/test_store.py
git commit -m "feat(store): add async SQLite-backed FindingsStore with dedup and severity filter"
```

---

## Task 6: Config loader (3-layer)

**Files:**
- Create: `src/pentora/config.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_config.py`:
```python
from pathlib import Path

from pentora.config import Config, load_config


def test_load_config_defaults_only() -> None:
    cfg = load_config()
    assert cfg.rate_limit == 10
    assert cfg.threads == 50
    assert cfg.proxy == "auto"


def test_user_config_overrides_defaults(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("defaults:\n  rate_limit: 25\n  proxy: zap\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    cfg = load_config()
    assert cfg.rate_limit == 25
    assert cfg.proxy == "zap"
    assert cfg.threads == 50  # unchanged default


def test_cli_overrides_win(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("defaults:\n  rate_limit: 25\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    cfg = load_config(cli_overrides={"rate_limit": 100})
    assert cfg.rate_limit == 100


def test_env_var_api_key_interpolation(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("api_keys:\n  shodan: $MY_SHODAN_KEY\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    monkeypatch.setenv("MY_SHODAN_KEY", "secret-token-123")
    cfg = load_config()
    assert cfg.api_keys["shodan"] == "secret-token-123"
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_config.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/config.py`**

```python
"""3-layer config loader: built-in defaults < user config < CLI overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULTS: dict[str, Any] = {
    "defaults": {
        "rate_limit": 10,
        "threads": 50,
        "proxy": "auto",
        "llm_provider": None,  # no default — must be set by user
        "llm_model": None,
    },
    "api_keys": {},
    "profiles": {},
}


@dataclass
class Config:
    rate_limit: int = 10
    threads: int = 50
    proxy: str = "auto"
    llm_provider: str | None = None
    llm_model: str | None = None
    api_keys: dict[str, str] = field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)


def _interpolate_env(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        return os.environ.get(value[1:], value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(cli_overrides: dict[str, Any] | None = None) -> Config:
    merged = dict(_DEFAULTS)

    user_path = os.environ.get("PENTORA_CONFIG") or str(Path.home() / ".pentora" / "config.yaml")
    p = Path(user_path)
    if p.exists():
        user_cfg = yaml.safe_load(p.read_text()) or {}
        merged = _deep_merge(merged, user_cfg)

    merged = _interpolate_env(merged)

    defaults = merged["defaults"]
    if cli_overrides:
        for k, v in cli_overrides.items():
            defaults[k] = v

    return Config(
        rate_limit=defaults["rate_limit"],
        threads=defaults["threads"],
        proxy=defaults["proxy"],
        llm_provider=defaults["llm_provider"],
        llm_model=defaults["llm_model"],
        api_keys=merged.get("api_keys", {}),
        profiles=merged.get("profiles", {}),
    )
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_config.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/config.py tests/unit/test_config.py
git commit -m "feat(config): add 3-layer YAML config loader with env-var interpolation"
```

---

## Task 7: ScanContext

**Files:**
- Create: `src/pentora/context.py`
- Create: `tests/unit/test_context.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_context.py`:
```python
from pathlib import Path

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.scope import Scope


@pytest.mark.asyncio
async def test_scan_context_creates_output_dirs(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app"]),
    )
    await ctx.prepare()
    assert (tmp_path / "out").is_dir()
    assert (tmp_path / "out" / "findings").is_dir()
    assert (tmp_path / "out" / "logs").is_dir()
    assert (tmp_path / "out" / "recon").is_dir()


@pytest.mark.asyncio
async def test_scan_context_writes_scope_lock(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path / "out",
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()
    lock = (tmp_path / "out" / "scope.lock").read_text()
    assert "pure.app" in lock
    assert "*.pure.app" in lock
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_context.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/context.py`**

```python
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
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_context.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/context.py tests/unit/test_context.py
git commit -m "feat(context): add ScanContext with output dir prep and scope.lock writer"
```

---

## Task 8: Logging setup (structlog + per-tool invocation log)

**Files:**
- Create: `src/pentora/logging_setup.py`
- Create: `tests/unit/test_logging_setup.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_logging_setup.py`:
```python
from pathlib import Path

from pentora.logging_setup import log_tool_invocation, setup_logging


def test_setup_logging_creates_log_file(tmp_path: Path) -> None:
    setup_logging(tmp_path / "logs" / "pentora.log")
    assert (tmp_path / "logs").is_dir()


def test_log_tool_invocation_writes_record(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs" / "tool-invocations"
    log_dir.mkdir(parents=True)
    log_tool_invocation(
        log_dir=log_dir,
        tool="subfinder",
        argv=["subfinder", "-d", "pure.app"],
        stdout="api.pure.app\ncdn.pure.app\n",
        stderr="",
        returncode=0,
        duration_ms=2340,
    )
    files = list(log_dir.glob("*-subfinder.json"))
    assert len(files) == 1
    text = files[0].read_text()
    assert "api.pure.app" in text
    assert "\"returncode\": 0" in text
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_logging_setup.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/logging_setup.py`**

```python
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
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_logging_setup.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/logging_setup.py tests/unit/test_logging_setup.py
git commit -m "feat(logging): add structlog setup and per-tool invocation JSON log"
```

---

## Task 9: Tool wrapper base class

**Files:**
- Create: `src/pentora/wrappers/__init__.py`
- Create: `src/pentora/wrappers/base.py`
- Create: `tests/unit/test_wrapper_base.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_wrapper_base.py`:
```python
from pathlib import Path

import pytest

from pentora.wrappers.base import ToolNotInstalled, ToolWrapper


class FakeTool(ToolWrapper):
    tool_name = "echo"
    install_check_argv = ["echo", "--version"]  # always succeeds

    def build_argv(self, *args, **kwargs):
        return ["echo", *args]

    def parse(self, stdout, stderr, returncode):
        return [stdout.strip()]


@pytest.mark.asyncio
async def test_wrapper_runs_command_and_parses(tmp_path: Path) -> None:
    tool = FakeTool(log_dir=tmp_path)
    result = await tool.run("hello", "world")
    assert result == ["hello world"]


@pytest.mark.asyncio
async def test_wrapper_raises_when_tool_missing(tmp_path: Path) -> None:
    class Missing(ToolWrapper):
        tool_name = "this-tool-does-not-exist-xyz123"
        install_check_argv = ["this-tool-does-not-exist-xyz123", "--version"]

        def build_argv(self, *args, **kwargs):
            return [self.tool_name]

        def parse(self, stdout, stderr, returncode):
            return []

    with pytest.raises(ToolNotInstalled):
        await Missing(log_dir=tmp_path).run()
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_wrapper_base.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/wrappers/__init__.py`**

```python
"""External tool wrappers."""
```

- [ ] **Step 4: Write `src/pentora/wrappers/base.py`**

```python
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
```

- [ ] **Step 5: Run test, see pass**

```bash
pytest tests/unit/test_wrapper_base.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/wrappers/__init__.py src/pentora/wrappers/base.py tests/unit/test_wrapper_base.py
git commit -m "feat(wrappers): add ToolWrapper ABC with install check, timeout, and invocation log"
```

---

## Task 10: subfinder wrapper

**Files:**
- Create: `src/pentora/wrappers/subfinder.py`
- Create: `tests/fixtures/subfinder/two_subs.txt`
- Create: `tests/unit/test_subfinder_wrapper.py`

- [ ] **Step 1: Create fixture**

`tests/fixtures/subfinder/two_subs.txt`:
```
api.pure.app
cdn.pure.app
```

- [ ] **Step 2: Write failing test**

`tests/unit/test_subfinder_wrapper.py`:
```python
from pathlib import Path

from pentora.wrappers.subfinder import SubfinderWrapper


def test_subfinder_parses_newline_separated_subs(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/subfinder/two_subs.txt").read_text()
    wrapper = SubfinderWrapper(log_dir=tmp_path)
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert result == ["api.pure.app", "cdn.pure.app"]


def test_subfinder_build_argv_uses_domain() -> None:
    wrapper = SubfinderWrapper()
    argv = wrapper.build_argv("pure.app")
    assert argv == ["subfinder", "-d", "pure.app", "-silent", "-all"]
```

- [ ] **Step 3: Run test, see fail**

```bash
pytest tests/unit/test_subfinder_wrapper.py -v
```

Expected: ImportError.

- [ ] **Step 4: Write `src/pentora/wrappers/subfinder.py`**

```python
"""subfinder — passive subdomain enumeration (ProjectDiscovery)."""
from __future__ import annotations

from pentora.wrappers.base import ToolWrapper


class SubfinderWrapper(ToolWrapper):
    tool_name = "subfinder"
    install_check_argv = ["subfinder", "-version"]

    def build_argv(self, domain: str) -> list[str]:  # type: ignore[override]
        return [self.tool_name, "-d", domain, "-silent", "-all"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[str]:  # type: ignore[override]
        return [line.strip() for line in stdout.splitlines() if line.strip()]
```

- [ ] **Step 5: Run test, see pass**

```bash
pytest tests/unit/test_subfinder_wrapper.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/wrappers/subfinder.py tests/fixtures/subfinder/two_subs.txt tests/unit/test_subfinder_wrapper.py
git commit -m "feat(wrappers): add subfinder wrapper with parser test"
```

---

## Task 11: httpx wrapper

**Files:**
- Create: `src/pentora/wrappers/httpx_tool.py`
- Create: `tests/fixtures/httpx/three_hosts.jsonl`
- Create: `tests/unit/test_httpx_wrapper.py`

- [ ] **Step 1: Create fixture**

`tests/fixtures/httpx/three_hosts.jsonl`:
```jsonl
{"url":"https://api.pure.app","status_code":200,"title":"Pure API","tech":["nginx","cloudflare"]}
{"url":"https://cdn.pure.app","status_code":403,"title":""}
{"url":"https://dead.pure.app","status_code":0,"failed":true}
```

- [ ] **Step 2: Write failing test**

`tests/unit/test_httpx_wrapper.py`:
```python
from pathlib import Path

from pentora.wrappers.httpx_tool import HttpxResult, HttpxWrapper


def test_httpx_parses_jsonl_and_skips_dead(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/httpx/three_hosts.jsonl").read_text()
    wrapper = HttpxWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2  # dead one filtered
    assert results[0].url == "https://api.pure.app"
    assert results[0].status_code == 200
    assert "nginx" in results[0].tech
    assert results[1].url == "https://cdn.pure.app"


def test_httpx_build_argv_for_subdomain_list() -> None:
    wrapper = HttpxWrapper()
    argv = wrapper.build_argv(["api.pure.app", "cdn.pure.app"])
    assert "-json" in argv
    assert "-silent" in argv
    assert "-tech-detect" in argv
    assert "-title" in argv
```

- [ ] **Step 3: Run test, see fail**

```bash
pytest tests/unit/test_httpx_wrapper.py -v
```

Expected: ImportError.

- [ ] **Step 4: Write `src/pentora/wrappers/httpx_tool.py`**

```python
"""httpx — HTTP probing (ProjectDiscovery). Aliased to avoid clash with stdlib name."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from pentora.wrappers.base import ToolWrapper


@dataclass
class HttpxResult:
    url: str
    status_code: int
    title: str
    tech: list[str] = field(default_factory=list)


class HttpxWrapper(ToolWrapper):
    tool_name = "httpx"
    install_check_argv = ["httpx", "-version"]

    def build_argv(self, hosts: list[str]) -> list[str]:  # type: ignore[override]
        # httpx reads stdin when no -l/-u flag; we'll feed via stdin in the orchestrator,
        # but for direct invocation just use -u with comma-joined hosts.
        return [
            self.tool_name,
            "-u", ",".join(hosts),
            "-json", "-silent", "-tech-detect", "-title",
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[HttpxResult]:  # type: ignore[override]
        out: list[HttpxResult] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("failed") or not doc.get("url"):
                continue
            out.append(
                HttpxResult(
                    url=doc["url"],
                    status_code=int(doc.get("status_code", 0)),
                    title=doc.get("title", ""),
                    tech=list(doc.get("tech", [])),
                )
            )
        return out
```

- [ ] **Step 5: Run test, see pass**

```bash
pytest tests/unit/test_httpx_wrapper.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/wrappers/httpx_tool.py tests/fixtures/httpx/three_hosts.jsonl tests/unit/test_httpx_wrapper.py
git commit -m "feat(wrappers): add httpx wrapper with JSONL parser"
```

---

## Task 12: PhaseModule base + minimal Recon module

**Files:**
- Create: `src/pentora/modules/__init__.py`
- Create: `src/pentora/modules/base.py`
- Create: `src/pentora/modules/recon.py`
- Create: `tests/unit/test_recon_module.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_recon_module.py`:
```python
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.modules.recon import ReconModule
from pentora.scope import Scope
from pentora.wrappers.httpx_tool import HttpxResult


@pytest.mark.asyncio
async def test_recon_module_produces_findings(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://pure.app",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["pure.app", "*.pure.app"]),
    )
    await ctx.prepare()

    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=["api.pure.app", "cdn.pure.app"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.pure.app", status_code=200, title="API", tech=["nginx"]),
            HttpxResult(url="https://cdn.pure.app", status_code=403, title=""),
        ])

        module = ReconModule()
        findings = await module.run(ctx)

    assert len(findings) >= 2  # at least one finding per live host
    titles = [f.title for f in findings]
    assert any("api.pure.app" in t for t in titles)
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_recon_module.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/modules/__init__.py`**

```python
"""Phase modules — each represents one section of the spec's §5."""
```

- [ ] **Step 4: Write `src/pentora/modules/base.py`**

```python
"""Base class for phase modules."""
from __future__ import annotations

from abc import ABC, abstractmethod

from pentora.context import ScanContext
from pentora.finding import Finding


class PhaseModule(ABC):
    name: str = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]: ...
```

- [ ] **Step 5: Write `src/pentora/modules/recon.py`**

```python
"""Recon phase — subdomain enumeration + HTTP probing."""
from __future__ import annotations

from urllib.parse import urlparse

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.httpx_tool import HttpxWrapper
from pentora.wrappers.subfinder import SubfinderWrapper


class ReconModule(PhaseModule):
    name = "recon"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        log_dir = ctx.output_dir / "logs" / "tool-invocations"

        # 1. Extract root domain from target
        host = urlparse(ctx.target).hostname or ctx.target
        root = ".".join(host.split(".")[-2:])

        # 2. Subdomain enumeration
        subs = await SubfinderWrapper(log_dir=log_dir).run(root)

        # 3. HTTP probe
        live = await HttpxWrapper(log_dir=log_dir).run(subs)

        # 4. Emit one finding per live subdomain (informational)
        for r in live:
            f = Finding(
                module="recon.subdomain",
                title=f"Live subdomain discovered: {urlparse(r.url).hostname}",
                endpoint=r.url,
                method="GET",
                evidence=f"HTTP {r.status_code} — {r.title or '(no title)'} — tech: {', '.join(r.tech) or 'unknown'}",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                description="Subdomain reachable over HTTP/HTTPS.",
                remediation="Inventory all live subdomains; decommission unused services.",
            )
            findings.append(f)
            if ctx.store:
                await ctx.store.add(f)

        return findings
```

- [ ] **Step 6: Run test, see pass**

```bash
pytest tests/unit/test_recon_module.py -v
```

Expected: 1 passed.

- [ ] **Step 7: Commit**

```bash
git add src/pentora/modules/__init__.py src/pentora/modules/base.py src/pentora/modules/recon.py tests/unit/test_recon_module.py
git commit -m "feat(modules): add PhaseModule ABC and minimal Recon module (subfinder + httpx)"
```

---

## Task 13: Reporter base class

**Files:**
- Create: `src/pentora/reporters/__init__.py`
- Create: `src/pentora/reporters/base.py`

- [ ] **Step 1: Write `src/pentora/reporters/__init__.py`**

```python
"""Output-format reporters."""
```

- [ ] **Step 2: Write `src/pentora/reporters/base.py`**

```python
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
```

- [ ] **Step 3: Commit**

```bash
git add src/pentora/reporters/__init__.py src/pentora/reporters/base.py
git commit -m "feat(reporters): add Reporter ABC"
```

---

## Task 14: JSON reporter

**Files:**
- Create: `src/pentora/reporters/json_reporter.py`
- Create: `tests/unit/test_json_reporter.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_json_reporter.py`:
```python
import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.json_reporter import JsonReporter


@pytest.mark.asyncio
async def test_json_reporter_writes_summary(tmp_path: Path) -> None:
    findings = [
        Finding(
            module="recon",
            title="api.pure.app live",
            endpoint="https://api.pure.app",
            method="GET",
            evidence="HTTP 200",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        ),
    ]
    reporter = JsonReporter()
    out = await reporter.write(tmp_path, findings, target="https://pure.app")
    assert out == tmp_path / "summary.json"
    doc = json.loads(out.read_text())
    assert doc["target"] == "https://pure.app"
    assert doc["findings_count"] == 1
    assert doc["findings"][0]["title"] == "api.pure.app live"
    assert doc["findings"][0]["cvss"]["vector"].startswith("CVSS:3.1/")
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_json_reporter.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/reporters/json_reporter.py`**

```python
"""JSON summary reporter."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pentora.finding import Finding
from pentora.reporters.base import Reporter


class JsonReporter(Reporter):
    name = "json"
    output_filename = "summary.json"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        doc = {
            "tool": "pentora",
            "version": "0.1.0",
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "findings": [self._serialize(f) for f in findings],
        }
        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2))
        return out

    @staticmethod
    def _serialize(f: Finding) -> dict:
        return {
            "id": f.id,
            "module": f.module,
            "title": f.title,
            "endpoint": f.endpoint,
            "method": f.method,
            "evidence": f.evidence,
            "description": f.description,
            "remediation": f.remediation,
            "cvss": {"vector": f.cvss.vector, "score": f.cvss.score},
            "severity": f.severity.value,
            "source": f.source,
            "discovered_at": f.discovered_at.isoformat(),
            "extra": f.extra,
        }
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_json_reporter.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/reporters/json_reporter.py tests/unit/test_json_reporter.py
git commit -m "feat(reporters): add JSON summary reporter"
```

---

## Task 15: Markdown reporter

**Files:**
- Create: `src/pentora/reporters/markdown.py`
- Create: `tests/unit/test_markdown_reporter.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_markdown_reporter.py`:
```python
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.markdown import MarkdownReporter


@pytest.mark.asyncio
async def test_markdown_reporter_outputs_grouped_by_severity(tmp_path: Path) -> None:
    findings = [
        Finding(module="recon", title="sub1", endpoint="https://x.com", method="-",
                evidence="HTTP 200", cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")),
        Finding(module="injection.sqli", title="SQLi", endpoint="https://x.com/q?id=1", method="GET",
                evidence="time-based", cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    ]
    out = await MarkdownReporter().write(tmp_path, findings, target="https://x.com")
    text = out.read_text()
    assert "# Pentora Report — https://x.com" in text
    assert "## Critical (1)" in text
    assert "## Info (1)" in text
    assert "SQLi" in text
    assert "sub1" in text
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_markdown_reporter.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/reporters/markdown.py`**

```python
"""Markdown summary reporter."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter


class MarkdownReporter(Reporter):
    name = "markdown"
    output_filename = "summary.md"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        grouped: dict[Severity, list[Finding]] = defaultdict(list)
        for f in findings:
            grouped[f.severity].append(f)

        lines = [
            f"# Pentora Report — {target}",
            "",
            f"_Generated {datetime.now(timezone.utc).isoformat()}_",
            "",
            f"**Total findings:** {len(findings)}",
            "",
        ]
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            items = grouped.get(sev, [])
            if not items:
                continue
            lines.append(f"## {sev.value.title()} ({len(items)})")
            lines.append("")
            for f in items:
                lines.append(f"### {f.title}")
                lines.append("")
                lines.append(f"- **Module:** `{f.module}`")
                lines.append(f"- **Endpoint:** `{f.method} {f.endpoint}`")
                lines.append(f"- **CVSS:** {f.cvss.score} (`{f.cvss.vector}`)")
                lines.append(f"- **Evidence:** {f.evidence}")
                if f.remediation:
                    lines.append(f"- **Remediation:** {f.remediation}")
                lines.append("")

        out = output_dir / self.output_filename
        out.write_text("\n".join(lines))
        return out
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_markdown_reporter.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/reporters/markdown.py tests/unit/test_markdown_reporter.py
git commit -m "feat(reporters): add Markdown reporter grouped by severity"
```

---

## Task 16: HTML reporter (Jinja2)

**Files:**
- Create: `src/pentora/templates/report.html`
- Create: `src/pentora/reporters/html.py`
- Create: `tests/unit/test_html_reporter.py`

- [ ] **Step 1: Write the Jinja2 template — `src/pentora/templates/report.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pentora Report — {{ target }}</title>
<style>
:root {
  --bg: #0e1116; --fg: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
  --crit: #ff5757; --high: #ff8c42; --med: #ffd454; --low: #6ee7b7; --info: #8b949e;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
body { background: var(--bg); color: var(--fg); margin: 0; padding: 2rem; max-width: 1200px; margin: auto; }
h1 { border-bottom: 2px solid var(--accent); padding-bottom: .5rem; }
.meta { color: var(--muted); margin: 1rem 0 2rem; }
.summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 2rem 0; }
.summary div { padding: 1rem; border-radius: .5rem; text-align: center; font-weight: 600; }
.summary .crit { background: var(--crit); color: #000; }
.summary .high { background: var(--high); color: #000; }
.summary .med  { background: var(--med);  color: #000; }
.summary .low  { background: var(--low);  color: #000; }
.summary .info { background: var(--info); color: #000; }
.finding { border-left: 4px solid var(--muted); padding: 1rem 1.5rem; margin: 1.5rem 0; background: #161b22; border-radius: 0 .5rem .5rem 0; }
.finding.crit { border-color: var(--crit); }
.finding.high { border-color: var(--high); }
.finding.med  { border-color: var(--med); }
.finding.low  { border-color: var(--low); }
.badge { display: inline-block; padding: .2rem .6rem; border-radius: .3rem; font-size: .8rem; font-weight: 700; color: #000; }
.badge.crit { background: var(--crit); }
.badge.high { background: var(--high); }
.badge.med  { background: var(--med); }
.badge.low  { background: var(--low); }
.badge.info { background: var(--info); }
code { background: #21262d; padding: .1rem .4rem; border-radius: .2rem; }
.kv { color: var(--muted); margin-right: .5rem; }
</style>
</head>
<body>
<h1>Pentora Report — {{ target }}</h1>
<div class="meta">Generated {{ generated_at }} • Pentora {{ version }}</div>
<div class="summary">
  <div class="crit">{{ counts.critical }}<br>Critical</div>
  <div class="high">{{ counts.high }}<br>High</div>
  <div class="med">{{ counts.medium }}<br>Medium</div>
  <div class="low">{{ counts.low }}<br>Low</div>
  <div class="info">{{ counts.info }}<br>Info</div>
</div>
{% for f in findings %}
<div class="finding {{ f.severity.value[:4] }}">
  <span class="badge {{ f.severity.value[:4] }}">{{ f.severity.value | upper }}</span>
  <h2>{{ f.title }}</h2>
  <p><span class="kv">Module</span> <code>{{ f.module }}</code></p>
  <p><span class="kv">Endpoint</span> <code>{{ f.method }} {{ f.endpoint }}</code></p>
  <p><span class="kv">CVSS</span> {{ f.cvss.score }} (<code>{{ f.cvss.vector }}</code>)</p>
  <p><span class="kv">Evidence</span> {{ f.evidence }}</p>
  {% if f.remediation %}<p><span class="kv">Remediation</span> {{ f.remediation }}</p>{% endif %}
</div>
{% endfor %}
</body>
</html>
```

- [ ] **Step 2: Write failing test**

`tests/unit/test_html_reporter.py`:
```python
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.html import HtmlReporter


@pytest.mark.asyncio
async def test_html_reporter_renders_summary_and_finding(tmp_path: Path) -> None:
    findings = [
        Finding(module="injection.sqli", title="SQLi on /search",
                endpoint="https://x.com/search?q=1", method="GET",
                evidence="time-based, 5s sleep",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    ]
    out = await HtmlReporter().write(tmp_path, findings, target="https://x.com")
    text = out.read_text()
    assert "<!DOCTYPE html>" in text
    assert "SQLi on /search" in text
    assert "CRITICAL" in text
    assert "9.8" in text
```

- [ ] **Step 3: Run test, see fail**

```bash
pytest tests/unit/test_html_reporter.py -v
```

Expected: ImportError.

- [ ] **Step 4: Write `src/pentora/reporters/html.py`**

```python
"""Jinja2 HTML reporter."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter
from pentora.version import __version__


class HtmlReporter(Reporter):
    name = "html"
    output_filename = "summary.html"

    def __init__(self) -> None:
        tpl_dir = Path(__file__).parent.parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(["html"]),
        )

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        counts = Counter(f.severity for f in findings)
        ctx = {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "findings": findings,
            "counts": {
                "critical": counts[Severity.CRITICAL],
                "high": counts[Severity.HIGH],
                "medium": counts[Severity.MEDIUM],
                "low": counts[Severity.LOW],
                "info": counts[Severity.INFO],
            },
        }
        out = output_dir / self.output_filename
        out.write_text(self._env.get_template("report.html").render(ctx))
        return out
```

- [ ] **Step 5: Add package-data hook to `pyproject.toml`**

In `[tool.setuptools]` section add:
```toml
[tool.setuptools.package-data]
pentora = ["templates/*.html", "templates/*.css", "templates/*.j2"]
```

- [ ] **Step 6: Reinstall in editable mode to pick up package-data**

```bash
pip install -e ".[dev]"
```

- [ ] **Step 7: Run test, see pass**

```bash
pytest tests/unit/test_html_reporter.py -v
```

Expected: 1 passed.

- [ ] **Step 8: Commit**

```bash
git add src/pentora/templates/report.html src/pentora/reporters/html.py tests/unit/test_html_reporter.py pyproject.toml
git commit -m "feat(reporters): add Jinja2 HTML reporter with dark theme"
```

---

## Task 17: Per-finding folder reporter

**Files:**
- Create: `src/pentora/templates/finding.md.j2`
- Create: `src/pentora/templates/poc.sh.j2`
- Create: `src/pentora/reporters/finding_folder.py`
- Create: `tests/unit/test_finding_folder_reporter.py`

- [ ] **Step 1: Write Jinja templates**

`src/pentora/templates/finding.md.j2`:
```jinja2
# {{ f.title }}

**Severity:** {{ f.severity.value | upper }} (CVSS {{ f.cvss.score }})
**Module:** `{{ f.module }}`
**Endpoint:** `{{ f.method }} {{ f.endpoint }}`
**Discovered:** {{ f.discovered_at.isoformat() }}
**Source:** {{ f.source }}

## Description

{{ f.description or "No description provided." }}

## Evidence

{{ f.evidence }}

## Remediation

{{ f.remediation or "TBD" }}

## Reproduction

See `request.http`, `response.http`, `poc.sh`, `poc.py` in this folder.

## CVSS

`{{ f.cvss.vector }}` — score **{{ f.cvss.score }}**
```

`src/pentora/templates/poc.sh.j2`:
```jinja2
#!/usr/bin/env bash
# Pentora PoC — {{ f.title }}
# Severity: {{ f.severity.value }} ({{ f.cvss.score }})
# Generated: {{ f.discovered_at.isoformat() }}

set -euo pipefail

ENDPOINT="{{ f.endpoint }}"
METHOD="{{ f.method }}"

echo "=== Reproducing: {{ f.title }} ==="
echo "Expected evidence: {{ f.evidence | replace('"', "'") }}"
echo ""

curl -sS -X "$METHOD" "$ENDPOINT" -i || true
```

- [ ] **Step 2: Write failing test**

`tests/unit/test_finding_folder_reporter.py`:
```python
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.finding_folder import FindingFolderReporter


@pytest.mark.asyncio
async def test_finding_folder_creates_bundle(tmp_path: Path) -> None:
    findings = [
        Finding(
            module="authz.idor",
            title="IDOR on /api/users/{id}",
            endpoint="https://x.com/api/users/99",
            method="GET",
            evidence="Returned User B's email",
            description="A's token accessed B's profile.",
            remediation="Server-side ownership check.",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            request_raw="GET /api/users/99 HTTP/1.1\nAuthorization: Bearer abc\n",
            response_raw="HTTP/1.1 200 OK\n\n{\"email\":\"victim@x.com\"}",
        ),
    ]
    (tmp_path / "findings").mkdir()
    await FindingFolderReporter().write(tmp_path, findings, target="https://x.com")
    folders = list((tmp_path / "findings").iterdir())
    assert len(folders) == 1
    folder = folders[0]
    assert (folder / "finding.md").exists()
    assert (folder / "poc.sh").exists()
    assert (folder / "request.http").exists()
    assert (folder / "response.http").exists()
    assert "IDOR" in (folder / "finding.md").read_text()
    assert "victim@x.com" in (folder / "response.http").read_text()
```

- [ ] **Step 3: Run test, see fail**

```bash
pytest tests/unit/test_finding_folder_reporter.py -v
```

Expected: ImportError.

- [ ] **Step 4: Write `src/pentora/reporters/finding_folder.py`**

```python
"""Per-finding folder bundle reporter — one folder per finding with request/response/PoC/screenshot."""
from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pentora.finding import Finding
from pentora.reporters.base import Reporter


_SAFE = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    return _SAFE.sub("_", s.lower()).strip("_")[:50]


class FindingFolderReporter(Reporter):
    name = "finding_folder"
    output_filename = "findings/"

    def __init__(self) -> None:
        tpl_dir = Path(__file__).parent.parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(disabled_extensions=("sh", "py", "j2")),
        )

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        root = output_dir / "findings"
        root.mkdir(exist_ok=True)
        for f in findings:
            folder = root / f"{f.discovered_at.strftime('%Y%m%d_%H%M%S')}_{_slug(f.module)}_{_slug(f.title)}"
            folder.mkdir(exist_ok=True)
            (folder / "finding.md").write_text(self._env.get_template("finding.md.j2").render(f=f))
            (folder / "poc.sh").write_text(self._env.get_template("poc.sh.j2").render(f=f))
            (folder / "poc.sh").chmod(0o755)
            (folder / "request.http").write_text(f.request_raw or "")
            (folder / "response.http").write_text(f.response_raw or "")
        return root
```

- [ ] **Step 5: Run test, see pass**

```bash
pytest tests/unit/test_finding_folder_reporter.py -v
```

Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/templates/finding.md.j2 src/pentora/templates/poc.sh.j2 src/pentora/reporters/finding_folder.py tests/unit/test_finding_folder_reporter.py
git commit -m "feat(reporters): add per-finding folder bundle reporter"
```

---

## Task 18: Orchestrator

**Files:**
- Create: `src/pentora/orchestrator.py`
- Create: `tests/unit/test_orchestrator.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_orchestrator.py`:
```python
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.orchestrator import Orchestrator
from pentora.reporters.json_reporter import JsonReporter
from pentora.scope import Scope


class FakeModule(PhaseModule):
    name = "fake"

    async def run(self, ctx):
        f = Finding(module="fake", title="ok", endpoint="https://x.com",
                    method="-", evidence="-",
                    cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))
        if ctx.store:
            await ctx.store.add(f)
        return [f]


@pytest.mark.asyncio
async def test_orchestrator_runs_modules_and_reporters(tmp_path: Path) -> None:
    ctx = ScanContext(
        target="https://x.com",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["x.com"]),
    )
    orc = Orchestrator(modules=[FakeModule()], reporters=[JsonReporter()])
    await orc.run(ctx)
    assert (tmp_path / "summary.json").exists()
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_orchestrator.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `src/pentora/orchestrator.py`**

```python
"""Scan orchestrator — runs phase modules, then reporters."""
from __future__ import annotations

import asyncio
import logging

from pentora.context import ScanContext
from pentora.modules.base import PhaseModule
from pentora.reporters.base import Reporter

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, modules: list[PhaseModule], reporters: list[Reporter]):
        self._modules = modules
        self._reporters = reporters

    async def run(self, ctx: ScanContext) -> None:
        await ctx.prepare()
        assert ctx.store is not None

        for module in self._modules:
            log.info("phase_start", extra={"module": module.name})
            try:
                await module.run(ctx)
            except Exception as e:
                log.error("phase_failed", extra={"module": module.name, "error": str(e)})

        findings = await ctx.store.all()
        for reporter in self._reporters:
            try:
                out = await reporter.write(ctx.output_dir, findings, ctx.target)
                log.info("report_written", extra={"reporter": reporter.name, "path": str(out)})
            except Exception as e:
                log.error("reporter_failed", extra={"reporter": reporter.name, "error": str(e)})
```

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_orchestrator.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/pentora/orchestrator.py tests/unit/test_orchestrator.py
git commit -m "feat(orchestrator): add Orchestrator that runs modules then reporters"
```

---

## Task 19: Wire up `pentora scan` to use Orchestrator + Recon module

**Files:**
- Modify: `src/pentora/cli.py`
- Create: `tests/unit/test_cli_scan_integration.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_cli_scan_integration.py`:
```python
from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from pentora.cli import main
from pentora.wrappers.httpx_tool import HttpxResult


def test_scan_command_produces_report(tmp_path: Path) -> None:
    out = tmp_path / "report"
    with patch("pentora.modules.recon.SubfinderWrapper") as Sub, \
         patch("pentora.modules.recon.HttpxWrapper") as Http:
        Sub.return_value.run = AsyncMock(return_value=["api.x.com"])
        Http.return_value.run = AsyncMock(return_value=[
            HttpxResult(url="https://api.x.com", status_code=200, title="API", tech=["nginx"]),
        ])
        runner = CliRunner()
        result = runner.invoke(main, [
            "scan", "https://x.com",
            "--output", str(out),
            "--phases", "recon",
            "--scope-include", "x.com,*.x.com",
        ])
    assert result.exit_code == 0, result.output
    assert (out / "summary.json").exists()
    assert (out / "summary.html").exists()
    assert (out / "summary.md").exists()
    assert (out / "findings").is_dir()
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_cli_scan_integration.py -v
```

Expected: ERROR — `scan` doesn't accept `--output`, `--phases`, `--scope-include` yet.

- [ ] **Step 3: Update `src/pentora/cli.py` `scan` command**

Replace the existing `scan` stub with:

```python
@main.command()
@click.argument("url")
@click.option("--output", "-o", type=click.Path(), default="./pentora-out", help="Output directory")
@click.option("--phases", default="recon", help="Comma-separated phase names (or 'all')")
@click.option("--scope-include", default="", help="Comma-separated in-scope hosts/wildcards")
@click.option("--scope-exclude", default="", help="Comma-separated excluded hosts")
@click.option("--token-a", default=None)
@click.option("--token-b", default=None)
@click.option("--profile", default="generic")
def scan(
    url: str,
    output: str,
    phases: str,
    scope_include: str,
    scope_exclude: str,
    token_a: str | None,
    token_b: str | None,
    profile: str,
) -> None:
    """Run a full pentest scan against URL."""
    import asyncio
    from urllib.parse import urlparse

    from pentora.config import load_config
    from pentora.context import ScanContext
    from pentora.modules.recon import ReconModule
    from pentora.orchestrator import Orchestrator
    from pentora.reporters.finding_folder import FindingFolderReporter
    from pentora.reporters.html import HtmlReporter
    from pentora.reporters.json_reporter import JsonReporter
    from pentora.reporters.markdown import MarkdownReporter
    from pentora.scope import Scope

    # Default scope: derive from URL if --scope-include is empty
    if not scope_include:
        host = urlparse(url).hostname or url
        root = ".".join(host.split(".")[-2:])
        include = [root, f"*.{root}"]
    else:
        include = [s.strip() for s in scope_include.split(",") if s.strip()]
    exclude = [s.strip() for s in scope_exclude.split(",") if s.strip()]

    cfg = load_config()
    ctx = ScanContext(
        target=url,
        output_dir=Path(output),
        config=cfg,
        scope=Scope(include=include, exclude=exclude),
        profile_name=profile,
        token_a=token_a,
        token_b=token_b,
    )

    phase_map = {"recon": ReconModule}
    requested = [p.strip() for p in phases.split(",") if p.strip()]
    if "all" in requested:
        requested = list(phase_map.keys())
    modules = [phase_map[p]() for p in requested if p in phase_map]

    reporters = [JsonReporter(), MarkdownReporter(), HtmlReporter(), FindingFolderReporter()]
    orc = Orchestrator(modules=modules, reporters=reporters)
    asyncio.run(orc.run(ctx))
    click.echo(f"✓ Scan complete. Reports written to {output}/")
```

Also add `from pathlib import Path` at the top of the file.

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_cli_scan_integration.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Manual smoke test (mocked, no real network)**

```bash
pentora scan https://example.com --output ./tmp-scan --phases recon
ls ./tmp-scan/
```

Expected (assuming subfinder/httpx are NOT installed, you'll see a graceful error logged but the run completes — orchestrator catches exceptions per module).

- [ ] **Step 6: Commit**

```bash
git add src/pentora/cli.py tests/unit/test_cli_scan_integration.py
git commit -m "feat(cli): wire scan command to orchestrator + recon module + 4 reporters"
```

---

## Task 20: dry-run mode

**Files:**
- Modify: `src/pentora/cli.py` (add `--dry-run`)
- Create: `tests/unit/test_dry_run.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_dry_run.py`:
```python
from click.testing import CliRunner

from pentora.cli import main


def test_dry_run_prints_plan_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "https://example.com", "--dry-run"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.output
    assert "recon" in result.output  # mentions phases that would run
```

- [ ] **Step 2: Run test, see fail**

```bash
pytest tests/unit/test_dry_run.py -v
```

Expected: FAIL (no --dry-run flag).

- [ ] **Step 3: Modify `src/pentora/cli.py` `scan` to accept `--dry-run`**

Add option:
```python
@click.option("--dry-run", is_flag=True, help="Print the plan and exit without scanning")
```

At the top of `scan` body (after parsing options, before instantiating modules), add:

```python
if dry_run:
    click.echo("=== DRY RUN ===")
    click.echo(f"Target: {url}")
    click.echo(f"Output: {output}")
    click.echo(f"Scope include: {include}")
    click.echo(f"Scope exclude: {exclude}")
    click.echo(f"Phases: {requested}")
    click.echo(f"Profile: {profile}")
    click.echo("Reporters: json, markdown, html, finding_folder")
    return
```

Add `dry_run: bool = False` to the function signature.

- [ ] **Step 4: Run test, see pass**

```bash
pytest tests/unit/test_dry_run.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Run all tests + coverage**

```bash
pytest --cov=pentora --cov-report=term-missing
```

Expected: ALL pass, coverage ≥ 80%.

- [ ] **Step 6: Commit**

```bash
git add src/pentora/cli.py tests/unit/test_dry_run.py
git commit -m "feat(cli): add --dry-run flag to print plan without scanning"
```

---

## Task 21: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write CI workflow**

`.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main, master, develop]
  pull_request:

jobs:
  lint-type-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Lint
        run: ruff check src/ tests/
      - name: Type check
        run: mypy --strict src/pentora/
      - name: Test
        run: pytest -q --cov=pentora --cov-report=xml --cov-fail-under=80
      - name: Coverage upload
        if: matrix.python-version == '3.12'
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: false
```

- [ ] **Step 2: Verify YAML syntax**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
```

Expected: no output (means valid).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow (lint + mypy + pytest on 3.11+3.12)"
```

---

## Task 22: README skeleton

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

```markdown
# Pentora

> Autonomous web application pentest orchestrator. One command. All phases. Production-ready reports.

[![CI](https://github.com/USER/pentora/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/pentora/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## What it is

Pentora runs a full web-application penetration test from a single command:

```bash
pentora https://target.example.com
```

It chains 60+ open-source security tools (subfinder, nuclei, sqlmap, dalfox, jwt_tool, testssl.sh, MobSF, …), integrates with Burp Suite Pro REST API and OWASP ZAP, optionally invokes a local or cloud LLM for novel payloads and report polish, and produces 11 importable report formats including per-finding folders with request/response/PoC/screenshot bundles.

## Status

**Pre-alpha** — Phase 1 (foundation) complete. Phase 2–4 in progress. Not yet ready for paid client work.

## Install (Kali Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/USER/pentora/main/install.sh | bash
```

## Usage

```bash
pentora scan https://target.com                                    # recon only (phase 1)
pentora scan https://target.com --phases all                        # everything
pentora scan https://target.com --profile dating                    # dating-app-tuned tests
pentora scan https://target.com --proxy burp                        # route via Burp Pro
pentora scan https://target.com --ai-mode --llm-provider ollama \
  --llm-model qwen2.5-coder:7b                                      # AI-assisted
pentora scan https://target.com --dry-run                           # print plan, don't execute
```

## License

AGPLv3. See [LICENSE](LICENSE).

## Legal

**Only use Pentora against systems you own or have written authorization to test.** Pentora refuses by default to scan `.mil` / `.gov` and a curated list of forbidden TLDs.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README skeleton with install + usage"
```

---

## Task 23: Phase 1 exit gate

- [ ] **Step 1: Run full test suite with coverage**

```bash
pytest -q --cov=pentora --cov-report=term-missing
```

Expected: all pass, coverage ≥ 80%.

- [ ] **Step 2: Run ruff and mypy**

```bash
ruff check src/ tests/
mypy --strict src/pentora/
```

Expected: both pass clean.

- [ ] **Step 3: Update CHANGELOG.md**

Create `CHANGELOG.md`:
```markdown
# Changelog

## [0.1.0] — 2026-05-27

### Phase 1: Foundation

- Project scaffold (pyproject.toml, ruff, mypy, pytest, CI)
- Core models: Finding, CVSS v3.1 scorer, Severity
- Scope resolver with wildcard + exclude + forbidden-TLD support
- 3-layer YAML config loader with env-var interpolation
- Async SQLite FindingsStore
- ScanContext + output dir prep + scope.lock writer
- Logging setup (structlog + per-tool JSON invocation log)
- ToolWrapper ABC + subfinder + httpx wrappers
- PhaseModule ABC + ReconModule (vertical slice)
- Reporters: JSON, Markdown, HTML (Jinja2), per-finding folder
- Orchestrator
- CLI: scan / setup / doctor / update / report / import-results / list-profiles / list-modules
- `--dry-run` flag
- GitHub Actions CI (lint + type + test on Python 3.11 + 3.12)
- README skeleton
```

- [ ] **Step 4: Commit + tag**

```bash
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG for phase 1"
git tag pentora-phase-1-complete
git log --oneline | head -25
```

Expected: ~23 commits on master, tag `pentora-phase-1-complete` points at the latest.

---

## Phase 1 Self-Review

1. **Spec coverage:** Foundation pieces from spec §4 (architecture diagram) all present: orchestrator ✅, phase modules ✅, tool wrappers ✅, findings store ✅, reporters ✅, CLI ✅, scope ✅, config ✅, logging ✅. Recon (§5.1) has minimal viable slice. Other modules deferred to Phase 2.
2. **Placeholder scan:** No "TBD" left in plan. ✅
3. **Type consistency:** `Finding`, `CVSS`, `Severity` defined in Task 3 used identically in Tasks 5, 14, 15, 16, 17. `ScanContext` from Task 7 used in Tasks 12, 18, 19. `PhaseModule` from Task 12 implemented by `ReconModule` and `FakeModule` in tests. `Reporter` from Task 13 implemented by all 4 reporters. ✅
4. **All steps have actual code, not "implement later".** ✅
