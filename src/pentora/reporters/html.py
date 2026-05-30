"""Jinja2 HTML reporter."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
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
            "generated_at": datetime.now(UTC).isoformat(),
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
