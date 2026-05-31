"""BurpClient — REST API integration for Burp Suite Professional."""
from __future__ import annotations

import asyncio

import httpx

from pentora.finding import CVSS, Finding, Severity


def _burp_severity_to_cvss(severity: str) -> CVSS:
    """Map Burp severity string to a representative CVSS vector."""
    vectors: dict[str, str] = {
        "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "Low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Information": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }
    vector = vectors.get(severity, vectors["Information"])
    return CVSS.from_vector(vector)


def _map_severity(burp_sev: str) -> Severity:
    mapping: dict[str, Severity] = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Information": Severity.INFO,
    }
    return mapping.get(burp_sev, Severity.INFO)


class BurpClient:
    """Burp Suite REST API client (burp-rest-api extension required)."""

    name = "burp"

    def __init__(self, base_url: str = "http://127.0.0.1:1337") -> None:
        self.base_url = base_url.rstrip("/")

    async def is_alive(self) -> bool:
        """Return True if the Burp REST API is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/burp/versions")
                return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    async def add_to_scope(self, urls: list[str]) -> None:
        """Add each URL to Burp's target scope."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for url in urls:
                await client.put(
                    f"{self.base_url}/burp/target/scope",
                    params={"url": url},
                )

    async def start_active_scan(self, urls: list[str]) -> str:
        """Start an active scan and return the scan ID."""
        if not urls:
            return ""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.base_url}/burp/scanner/scans/active",
                params={"baseUrl": urls[0]},
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("id", ""))

    async def wait_for_scan(
        self, scan_id: str, poll_interval_s: int = 5, timeout_s: int = 3600
    ) -> None:
        """Block until the scan reaches 100% completion or timeout."""
        elapsed = 0
        async with httpx.AsyncClient(timeout=10.0) as client:
            while elapsed < timeout_s:
                resp = await client.get(f"{self.base_url}/burp/scanner/status")
                resp.raise_for_status()
                data = resp.json()
                if data.get("scanPercentage") == 100:
                    return
                await asyncio.sleep(poll_interval_s)
                elapsed += poll_interval_s
        msg = f"Burp scan did not complete within {timeout_s}s"
        raise TimeoutError(msg)

    async def get_findings(self) -> list[Finding]:
        """Retrieve issues from Burp and convert to Finding objects."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{self.base_url}/burp/scanner/issues")
            resp.raise_for_status()
            issues: list[dict[str, object]] = resp.json()

        findings: list[Finding] = []
        for issue in issues:
            sev_str = str(issue.get("severity", "Information"))
            cvss = _burp_severity_to_cvss(sev_str)
            findings.append(
                Finding(
                    module="burp",
                    title=str(issue.get("issueName", "Unknown")),
                    endpoint=str(issue.get("url", "")),
                    method="GET",
                    evidence=str(issue.get("issueDetail", "")),
                    cvss=cvss,
                    description=str(issue.get("issueBackground", "")),
                    remediation=str(issue.get("remediationBackground", "")),
                    source="burp",
                )
            )
        return findings

    async def export_xml(self, output_path: str) -> None:
        """Download the Burp XML report and write to output_path."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                f"{self.base_url}/burp/report",
                params={"reportType": "XML"},
            )
            resp.raise_for_status()
        import pathlib
        pathlib.Path(output_path).write_bytes(resp.content)
