"""Production CART CLI (pentora-cart): argparse wiring + run_once / serve_loop orchestration."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pentora.engine.cli import build_parser, main, run_once, serve_loop


class _Delta:
    def __init__(self, new: list[Any], resolved: list[Any] | None = None) -> None:
        self.new = new
        self.resolved = resolved or []
        self.persisting: list[Any] = []

    @property
    def has_regressions(self) -> bool:
        return bool(self.new)


class _Finding:
    def __init__(self, title: str) -> None:
        self.title = title


class _FakeEngine:
    """Records the calls the CLI makes so orchestration can be asserted without a real engine."""

    def __init__(self, delta: _Delta | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._delta = delta or _Delta([])

    def ingest_har(self, path: str | Path) -> int:
        self.calls.append(("ingest_har", str(path)))
        return 1

    def run(self) -> dict[str, int]:
        self.calls.append(("run", ""))
        return {"findings": 1}

    def report_markdown(self, path: str | Path = "r.md") -> str:
        self.calls.append(("report", str(path)))
        return "# report"

    def save_baseline(self, path: str | Path = "b.json") -> Path:
        self.calls.append(("save_baseline", str(path)))
        Path(path).write_text("{}", encoding="utf-8")    # the real engine writes the file
        return Path(path)

    def diff_baseline(self, path: str | Path = "b.json") -> _Delta:
        self.calls.append(("diff_baseline", str(path)))
        return self._delta


# ---- parser ----


def test_parser_run_command() -> None:
    args = build_parser().parse_args(
        ["run", "--target", "http://x", "--har", "t.har", "--report", "o.md"]
    )
    assert args.command == "run"
    assert args.target == "http://x"
    assert args.har == "t.har"
    assert callable(args.func)


def test_parser_serve_defaults_and_once_flag() -> None:
    args = build_parser().parse_args(["serve", "--target", "http://x", "--once"])
    assert args.command == "serve"
    assert args.once is True
    assert args.interval == 3600.0


def test_parser_proxy_and_scope_list() -> None:
    args = build_parser().parse_args(
        ["proxy", "--target", "http://x", "--port", "9090", "--scope", "a.com", "b.com"]
    )
    assert args.port == 9090
    assert args.scope == ["a.com", "b.com"]


# ---- run_once ----


def test_run_once_ingests_runs_and_reports() -> None:
    eng = _FakeEngine()
    res = run_once(eng, har="t.har", report="o.md")
    assert [c[0] for c in eng.calls] == ["ingest_har", "run", "report"]
    assert res["report"] == "o.md"
    assert "delta" not in res


def test_run_once_diffs_when_baseline_exists(tmp_path: Path) -> None:
    baseline = tmp_path / "b.json"
    baseline.write_text("{}", encoding="utf-8")
    eng = _FakeEngine(delta=_Delta([_Finding("SQLI")]))
    res = run_once(eng, report="o.md", baseline=str(baseline))
    assert "delta" in res
    assert ("diff_baseline", str(baseline)) in eng.calls


def test_run_once_skips_diff_when_baseline_missing(tmp_path: Path) -> None:
    eng = _FakeEngine()
    res = run_once(eng, report="o.md", baseline=str(tmp_path / "nope.json"))
    assert "delta" not in res
    assert all(c[0] != "diff_baseline" for c in eng.calls)


# ---- serve_loop ----


def test_serve_loop_establishes_baseline_then_alerts_on_new(tmp_path: Path) -> None:
    baseline = tmp_path / "b.json"                       # missing -> establish first
    alerts: list[Any] = []
    engines: list[_FakeEngine] = []

    def factory() -> _FakeEngine:
        eng = _FakeEngine(delta=_Delta([_Finding("XSS")]))
        engines.append(eng)
        return eng

    cycles = serve_loop(
        factory, interval=0.0, iterations=1, baseline=str(baseline),
        sleeper=lambda _s: None, alert=alerts.append,
    )
    assert cycles == 1
    assert len(alerts) == 1                              # the new finding fired an alert
    assert alerts[0].has_regressions
    assert ("save_baseline", str(baseline)) in engines[0].calls


def test_serve_loop_silent_when_no_new_findings(tmp_path: Path) -> None:
    baseline = tmp_path / "b.json"
    baseline.write_text("{}", encoding="utf-8")          # exists -> no establish pass
    alerts: list[Any] = []

    cycles = serve_loop(
        lambda: _FakeEngine(delta=_Delta([])),
        interval=0.0, iterations=2, baseline=str(baseline),
        sleeper=lambda _s: None, alert=alerts.append,
    )
    assert cycles == 2
    assert alerts == []                                  # unchanged target stays silent


# ---- main dispatch ----


def test_main_without_command_returns_2() -> None:
    assert main([]) == 2


def test_serve_without_traffic_source_returns_2() -> None:
    # Regression: serve with no --proxy and no --har would silently monitor an empty blackboard
    # forever. It must refuse instead of pretending to scan.
    assert main(["serve", "--target", "http://x"]) == 2
