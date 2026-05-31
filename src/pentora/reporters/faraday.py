"""Faraday JSON import reporter."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from pentora.finding import Finding
from pentora.reporters.base import Reporter


class FaradayReporter(Reporter):
    name = "faraday"
    output_filename = "findings.faraday.json"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        # Group findings by hostname
        by_host: dict[str, list[Finding]] = {}
        for f in findings:
            parsed = urlparse(f.endpoint)
            host = parsed.hostname or parsed.netloc
            by_host.setdefault(host, []).append(f)

        hosts = []
        for host, host_findings in by_host.items():
            vulns: list[dict[str, object]] = []
            for f in host_findings:
                vulns.append({
                    "name": f.title,
                    "desc": f.description,
                    "severity": f.severity.value,
                    "refs": [],
                    "resolution": f.remediation,
                })
            hosts.append({
                "ip": host,
                "hostnames": [],
                "vulnerabilities": vulns,
            })

        doc = {"hosts": hosts}
        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2))
        return out
