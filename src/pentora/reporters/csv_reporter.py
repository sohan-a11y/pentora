"""CSV reporter — UTF-8 with BOM for Excel compatibility."""
from __future__ import annotations

import csv
from pathlib import Path

from pentora.finding import Finding
from pentora.reporters.base import Reporter

_FIELDS = [
    "severity", "score", "module", "title", "endpoint",
    "method", "evidence", "remediation", "source", "discovered_at",
]


class CsvReporter(Reporter):
    name = "csv"
    output_filename = "findings.csv"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        out = output_dir / self.output_filename
        with open(out, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FIELDS)
            writer.writeheader()
            for f in findings:
                writer.writerow({
                    "severity": f.severity.value,
                    "score": f.cvss.score,
                    "module": f.module,
                    "title": f.title,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "source": f.source,
                    "discovered_at": f.discovered_at.isoformat(),
                })
        return out
