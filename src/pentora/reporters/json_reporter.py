"""JSON summary reporter."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentora.finding import Finding
from pentora.reporters.base import Reporter
from pentora.version import __version__


class JsonReporter(Reporter):
    name = "json"
    output_filename = "summary.json"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        doc = {
            "tool": "pentora",
            "version": __version__,
            "target": target,
            "generated_at": datetime.now(UTC).isoformat(),
            "findings_count": len(findings),
            "findings": [self._serialize(f) for f in findings],
        }
        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return out

    @staticmethod
    def _serialize(f: Finding) -> dict[str, Any]:
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
