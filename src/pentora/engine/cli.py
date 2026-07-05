"""Production CLI for the Pentora CART engine — ``pentora-cart``.

Four modes:

  run       one-shot scan of captured traffic (HAR) -> findings report
  baseline  run once and save the findings as the accepted baseline
  proxy     start a live intercepting proxy, capture a browser session, then scan
  serve     continuous daemon: rescan on an interval and alert only on NEW findings

``serve`` is a foreground loop by design — run it under a process supervisor
(systemd, Docker, ``nohup``) to daemonize it on a Linux box, e.g.::

    [Service]
    ExecStart=pentora-cart serve --target https://app.example.com --interval 3600

stdlib argparse only (no new dependency). The orchestration is split from argument parsing so
``run_once`` / ``serve_loop`` are unit-testable against any engine-shaped object.
"""
from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger("pentora.cart")


class EngineLike(Protocol):
    """The slice of the Engine facade the CLI drives (duck-typed for testability)."""

    def ingest_har(self, path: str | Path) -> int: ...
    def run(self) -> dict[str, int]: ...
    def report_markdown(self, path: str | Path = ...) -> str: ...
    def save_baseline(self, path: str | Path = ...) -> Path: ...
    def diff_baseline(self, path: str | Path = ...) -> Any: ...
    def start_proxy(self, port: int = ..., host: str = ...) -> str: ...
    def stop_proxy(self) -> None: ...


# ---- orchestration (engine-shaped input, no argparse) --------------------------


def run_once(
    engine: EngineLike,
    har: str | None = None,
    report: str | Path = "pentora-cart-report.md",
    baseline: str | None = None,
) -> dict[str, Any]:
    """Ingest optional HAR, drive the autonomous loop, write the report; diff a baseline if given
    and present on disk. Returns a summary dict."""
    if har:
        engine.ingest_har(har)
    summary = engine.run()
    engine.report_markdown(report)
    result: dict[str, Any] = {"summary": summary, "report": str(report)}
    if baseline and Path(baseline).exists():
        result["delta"] = engine.diff_baseline(baseline)
    return result


def _default_alert(delta: Any) -> None:
    titles = ", ".join(getattr(r, "title", "?") for r in delta.new) or "none"
    log.warning("REGRESSION: %d new finding(s): %s", len(delta.new), titles)


def serve_loop(
    engine_factory: Callable[[], EngineLike],
    interval: float,
    iterations: int | None = None,
    har: str | None = None,
    baseline: str = "pentora-baseline.json",
    report: str | Path = "pentora-cart-report.md",
    sleeper: Callable[[float], None] = time.sleep,
    alert: Callable[[Any], None] = _default_alert,
) -> int:
    """Continuous CART loop. Each cycle builds a FRESH engine (fresh blackboard), rescans, and
    diffs against the persisted baseline — so only genuinely new exposure fires an alert. Bounds
    to ``iterations`` cycles when given (``None`` runs until interrupted). Returns cycles run."""
    if not Path(baseline).exists():
        first = engine_factory()
        run_once(first, har=har, report=report)
        first.save_baseline(baseline)
        log.info("baseline established at %s", baseline)

    n = 0
    while iterations is None or n < iterations:
        n += 1
        sleeper(interval)
        res = run_once(engine_factory(), har=har, report=report, baseline=baseline)
        delta = res.get("delta")
        if delta is not None and getattr(delta, "has_regressions", False):
            alert(delta)
        else:
            log.info("scan %d: no new findings vs baseline", n)
    return n


# ---- argparse wiring -----------------------------------------------------------


def _make_engine(args: argparse.Namespace) -> EngineLike:
    from pentora.engine.app import start

    return start(
        target=args.target, rps=args.rps, model=args.model,
        ollama_host=args.ollama_host, scope_hosts=args.scope or None,
    )


def _cmd_run(args: argparse.Namespace) -> int:
    res = run_once(_make_engine(args), har=args.har, report=args.report, baseline=args.baseline)
    log.info("scan complete: %s -> %s", res["summary"], res["report"])
    delta = res.get("delta")
    if delta is not None:
        log.info(
            "vs baseline: %d new, %d resolved, %d persisting",
            len(delta.new), len(delta.resolved), len(delta.persisting),
        )
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    engine = _make_engine(args)
    if args.har:
        engine.ingest_har(args.har)
    engine.run()
    path = engine.save_baseline(args.out)
    log.info("baseline saved: %s", path)
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    engine = _make_engine(args)
    url = engine.start_proxy(port=args.port, host=args.host)
    log.info("proxy listening at %s — route your browser through it (Ctrl-C to stop)", url)
    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover - interactive stop
        log.info("stopping proxy")
    finally:
        engine.stop_proxy()
    run_once(engine, report=args.report)
    log.info("scan complete -> %s", args.report)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve_loop(
        lambda: _make_engine(args),
        interval=args.interval,
        iterations=1 if args.once else None,
        har=args.har,
        baseline=args.baseline,
        report=args.report,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentora-cart",
        description="Pentora CART — autonomous continuous red teaming on a local LLM.",
    )
    sub = parser.add_subparsers(dest="command")

    eng = argparse.ArgumentParser(add_help=False)
    eng.add_argument("--target", required=True, help="target root URL")
    eng.add_argument("--model", default="qwen3:8b", help="local Ollama model tag")
    eng.add_argument(
        "--ollama-host", dest="ollama_host", default="http://127.0.0.1:11434",
        help="Ollama server URL",
    )
    eng.add_argument("--rps", type=float, default=5.0, help="global request rate cap")
    eng.add_argument("--scope", nargs="*", default=[], help="in-scope host substrings")

    run = sub.add_parser("run", parents=[eng], help="one-shot scan of captured traffic")
    run.add_argument("--har", help="HAR export to ingest before scanning")
    run.add_argument("--report", default="pentora-cart-report.md")
    run.add_argument("--baseline", help="diff findings against this baseline file")
    run.set_defaults(func=_cmd_run)

    base = sub.add_parser("baseline", parents=[eng], help="run once and save a findings baseline")
    base.add_argument("--har", help="HAR export to ingest before scanning")
    base.add_argument("--out", default="pentora-baseline.json")
    base.set_defaults(func=_cmd_baseline)

    prox = sub.add_parser("proxy", parents=[eng], help="live intercepting proxy, then scan")
    prox.add_argument("--host", default="127.0.0.1")
    prox.add_argument("--port", type=int, default=8080)
    prox.add_argument("--duration", type=float, help="seconds to capture (default: until Ctrl-C)")
    prox.add_argument("--report", default="pentora-cart-report.md")
    prox.set_defaults(func=_cmd_proxy)

    serve = sub.add_parser(
        "serve", parents=[eng], help="continuous daemon: rescan on an interval, alert on deltas"
    )
    serve.add_argument("--interval", type=float, default=3600.0, help="seconds between scans")
    serve.add_argument("--har", help="HAR export to re-ingest each cycle")
    serve.add_argument("--baseline", default="pentora-baseline.json")
    serve.add_argument("--report", default="pentora-cart-report.md")
    serve.add_argument("--once", action="store_true", help="run a single cycle and exit")
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] | None = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
