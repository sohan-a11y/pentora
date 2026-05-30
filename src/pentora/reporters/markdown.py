"""Markdown summary reporter."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


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
            f"_Generated {datetime.now(UTC).isoformat()}_",
            "",
            f"**Total findings:** {len(findings)}",
            "",
        ]
        for sev in _SEVERITY_ORDER:
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
