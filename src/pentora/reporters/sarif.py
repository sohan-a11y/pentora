"""SARIF 2.1.0 reporter."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter
from pentora.version import __version__


def _sarif_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


class SarifReporter(Reporter):
    name = "sarif"
    output_filename = "findings.sarif"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        results = []
        for f in findings:
            results.append({
                "ruleId": f.module,
                "level": _sarif_level(f.severity),
                "message": {
                    "text": f"{f.title}\n{f.evidence}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.endpoint,
                            }
                        }
                    }
                ],
            })

        doc = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Pentora",
                            "version": __version__,
                            "informationUri": "https://github.com/pentora/pentora",
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(UTC).isoformat(),
                        }
                    ],
                }
            ],
        }

        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return out
