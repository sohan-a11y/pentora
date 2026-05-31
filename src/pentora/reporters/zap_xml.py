"""ZAP XML export reporter."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter

_RISK_CODE = {
    Severity.CRITICAL: "3",
    Severity.HIGH: "3",
    Severity.MEDIUM: "2",
    Severity.LOW: "1",
    Severity.INFO: "0",
}


class ZapXmlReporter(Reporter):
    name = "zap_xml"
    output_filename = "zap-export.xml"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        out = output_dir / self.output_filename
        if out.exists():
            return out

        generated = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S")
        report = ET.Element(
            "OWASPZAPReport",
            version="2.14.0",
            generated=generated,
        )

        # Group by host
        by_host: dict[str, list[Finding]] = {}
        for f in findings:
            parsed = urlparse(f.endpoint)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            by_host.setdefault(host_key, []).append(f)

        # If no findings, create a single site element
        hosts_to_render = by_host if by_host else {target: []}

        for host_url, host_findings in hosts_to_render.items():
            parsed = urlparse(host_url)
            site = ET.SubElement(
                report, "site",
                name=host_url,
                host=parsed.netloc,
                port=str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                ssl=("true" if parsed.scheme == "https" else "false"),
            )
            alerts = ET.SubElement(site, "alerts")
            for f in host_findings:
                alert = ET.SubElement(alerts, "alertitem")
                ET.SubElement(alert, "pluginid").text = "0"
                ET.SubElement(alert, "alertRef").text = f.module
                ET.SubElement(alert, "alert").text = f.title
                ET.SubElement(alert, "name").text = f.title
                ET.SubElement(alert, "riskcode").text = _RISK_CODE[f.severity]
                ET.SubElement(alert, "confidence").text = "2"
                ET.SubElement(alert, "riskdesc").text = f.severity.value.capitalize()
                ET.SubElement(alert, "desc").text = f.description
                ET.SubElement(alert, "solution").text = f.remediation
                ET.SubElement(alert, "evidence").text = f.evidence
                instance = ET.SubElement(alert, "instances")
                inst = ET.SubElement(instance, "instance")
                ET.SubElement(inst, "uri").text = f.endpoint
                ET.SubElement(inst, "method").text = f.method

        tree = ET.ElementTree(report)
        ET.indent(tree, space="  ")
        xml_body = ET.tostring(report, encoding="unicode")
        content = '<?xml version="1.0"?>\n' + xml_body
        out.write_text(content)
        return out
