"""Burp Suite XML export reporter."""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from pentora.finding import Finding, Severity
from pentora.reporters.base import Reporter

_SEVERITY_MAP = {
    Severity.CRITICAL: "High",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Information",
}


def _resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return "0.0.0.0"  # noqa: S104


class BurpXmlReporter(Reporter):
    name = "burp_xml"
    output_filename = "burp-export.xml"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        out = output_dir / self.output_filename
        if out.exists():
            return out

        export_time = datetime.now(UTC).strftime("%a %b %d %H:%M:%S UTC %Y")
        root = ET.Element("issues", burpVersion="2024.1", exportTime=export_time)

        for idx, f in enumerate(findings, start=1):
            parsed = urlparse(f.endpoint)
            issue = ET.SubElement(root, "issue")

            ET.SubElement(issue, "serialNumber").text = str(idx)
            ET.SubElement(issue, "type").text = "0"
            ET.SubElement(issue, "name").text = f.title
            ET.SubElement(issue, "severity").text = _SEVERITY_MAP[f.severity]
            ET.SubElement(issue, "confidence").text = "Certain"
            host_el = ET.SubElement(issue, "host")
            host_el.set("ip", _resolve_ip(parsed.hostname or ""))
            host_el.text = f"{parsed.scheme}://{parsed.netloc}"
            ET.SubElement(issue, "path").text = parsed.path or "/"
            ET.SubElement(issue, "issueDetail").text = f.evidence
            ET.SubElement(issue, "issueBackground").text = f.description
            ET.SubElement(issue, "remediationDetail").text = f.remediation

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")

        xml_body = ET.tostring(root, encoding="unicode")
        content = "\n".join([
            '<?xml version="1.0"?>',
            '<!DOCTYPE issues [<!ELEMENT issues (issue*)>]>',
            xml_body,
        ])
        out.write_text(content, encoding="utf-8")
        return out
