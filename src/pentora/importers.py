"""Importers — parse external scanner exports (Burp / ZAP XML) into Findings.

Lets ``pentora import-results burp <file>`` (or ``zap``) pull third-party scan
output into Pentora's store so it shows up in the unified reports. Uses
``defusedxml`` to parse untrusted scanner output safely.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defusedxml.ElementTree import parse as _xml_parse

from pentora.finding import CVSS, Finding

# Normalized severity name → representative CVSS score (drives Finding.severity).
_SEV_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
    "information": 0.0,
    "informational": 0.0,
}

# ZAP riskcode → severity name.
_ZAP_RISK: dict[str, str] = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _cvss_for(severity: str) -> CVSS:
    score = _SEV_SCORE.get(severity.lower().strip(), 0.0)
    return CVSS(vector=f"imported:{severity}", score=score)


def _text(node: Any, tag: str, default: str = "") -> str:
    child = node.find(tag)
    if child is not None and child.text:
        return str(child.text).strip()
    return default


def import_burp_xml(path: Path) -> list[Finding]:
    """Parse a Burp Suite XML issue export into Findings."""
    root = _xml_parse(str(path)).getroot()
    if root is None:
        return []
    findings: list[Finding] = []
    for issue in root.findall(".//issue"):
        name = _text(issue, "name", "Unknown issue")
        severity = _text(issue, "severity", "Information")
        host_node = issue.find("host")
        host = ""
        if host_node is not None and host_node.text:
            host = host_node.text.strip()
        path_str = _text(issue, "path")
        endpoint = f"{host}{path_str}" if host else path_str
        findings.append(
            Finding(
                module="import.burp",
                title=name,
                endpoint=endpoint,
                method="GET",
                evidence=_text(issue, "issueDetail"),
                cvss=_cvss_for(severity),
                description=_text(issue, "issueBackground"),
                remediation=(
                    _text(issue, "remediationDetail")
                    or _text(issue, "remediationBackground")
                ),
                source="burp",
            )
        )
    return findings


def import_zap_xml(path: Path) -> list[Finding]:
    """Parse an OWASP ZAP XML report into Findings (one per instance)."""
    root = _xml_parse(str(path)).getroot()
    if root is None:
        return []
    findings: list[Finding] = []
    for item in root.findall(".//alertitem"):
        name = _text(item, "alert") or _text(item, "name", "Unknown alert")
        severity = _ZAP_RISK.get(_text(item, "riskcode", "0"), "info")
        desc = _text(item, "desc")
        solution = _text(item, "solution")
        evidence = _text(item, "evidence")
        instances = item.findall(".//instance")
        if not instances:
            findings.append(
                Finding(
                    module="import.zap",
                    title=name,
                    endpoint="",
                    method="GET",
                    evidence=evidence,
                    cvss=_cvss_for(severity),
                    description=desc,
                    remediation=solution,
                    source="zap",
                )
            )
            continue
        for inst in instances:
            findings.append(
                Finding(
                    module="import.zap",
                    title=name,
                    endpoint=_text(inst, "uri"),
                    method=_text(inst, "method", "GET") or "GET",
                    evidence=_text(inst, "evidence") or evidence,
                    cvss=_cvss_for(severity),
                    description=desc,
                    remediation=solution,
                    source="zap",
                )
            )
    return findings


def import_results(source: str, path: Path) -> list[Finding]:
    """Dispatch to the right importer for ``source`` ('burp' | 'zap')."""
    if source == "burp":
        return import_burp_xml(path)
    if source == "zap":
        return import_zap_xml(path)
    msg = f"Unknown import source: {source!r} (expected 'burp' or 'zap')"
    raise ValueError(msg)
