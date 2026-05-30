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
