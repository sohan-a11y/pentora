# Contributing to Pentora

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/sohan-a11y/pentora
cd pentora
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/unit/          # Unit tests only (fast, no external deps)
pytest tests/ --cov=pentora # Full suite with coverage
```

## Code Style

- Python 3.11+, type annotations required on all function signatures
- Ruff for linting: `ruff check src/ tests/`
- Mypy strict: `mypy --strict src/pentora/`
- 80% minimum test coverage enforced by pytest

## Adding a New Security Module

1. Create `src/pentora/modules/your_module.py` extending `PhaseModule`
2. Register it in `PHASE_MAP` in `src/pentora/cli.py`
3. Write tests in `tests/unit/test_your_module.py`
4. Add a test wrapper if using an external tool

## Adding a New Reporter

1. Create `src/pentora/reporters/your_reporter.py` extending `Reporter`
2. Register it in `src/pentora/reporters/__init__.py` (both `ALL_REPORTERS` and `REPORTER_MAP`)
3. Write tests mirroring `tests/unit/test_json_reporter.py`

## Commit Messages

Follow Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write tests first (TDD), then implement
4. Ensure `ruff check` and `mypy --strict` are clean
5. Ensure `pytest --cov-fail-under=80` passes
6. Open a PR against `main`

## License

By contributing, you agree that your contributions will be licensed under the AGPLv3.
