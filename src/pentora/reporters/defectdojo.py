"""DefectDojo generic findings JSON reporter."""
from __future__ import annotations

import json
from pathlib import Path

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter

_SEVERITY_MAP = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


class DefectDojoReporter(Reporter):
    name = "defectdojo"
    output_filename = "findings.defectdojo.json"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        items = []
        for f in findings:
            items.append({
                "title": f.title,
                "severity": _SEVERITY_MAP[f.severity],
                "description": f.description,
                "mitigation": f.remediation,
                "cvssv3": f.cvss.vector,
                "date": f.discovered_at.date().isoformat(),
                "active": True,
                "verified": False,
            })

        doc = {"findings": items}
        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2))
        return out
