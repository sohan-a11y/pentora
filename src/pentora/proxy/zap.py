"""ZapClient — OWASP ZAP REST API integration."""
from __future__ import annotations

import asyncio
import os

import httpx

from pentora.finding import CVSS, Finding, Severity


def _zap_severity_to_cvss(risk: str) -> CVSS:
    """Map ZAP risk string to a representative CVSS vector."""
    vectors: dict[str, str] = {
        "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "Low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Informational": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }
    vector = vectors.get(risk, vectors["Informational"])
    return CVSS.from_vector(vector)


def _map_zap_severity(risk: str) -> Severity:
    mapping: dict[str, Severity] = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFO,
    }
    return mapping.get(risk, Severity.INFO)


class ZapClient:
    """OWASP ZAP REST API client."""

    name = "zap"

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8090",
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key or os.environ.get("ZAP_API_KEY", "")

    async def is_alive(self) -> bool:
        """Return True if ZAP is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/JSON/core/view/version/",
                    params={"apikey": self._api_key},
                )
                return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    async def add_to_scope(self, urls: list[str]) -> None:
        """Include each URL in the default ZAP context scope."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for url in urls:
                await client.get(
                    f"{self.base_url}/JSON/context/action/includeInContext/",
                    params={
                        "contextName": "Default Context",
                        "regex": url,
                        "apikey": self._api_key,
                    },
                )

    async def start_active_scan(self, urls: list[str]) -> str:
        """Start an active scan and return the ZAP scanId."""
        if not urls:
            return ""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={"url": urls[0], "apikey": self._api_key},
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("scan", ""))

    async def wait_for_scan(
        self, scan_id: str, poll_interval_s: int = 5, timeout_s: int = 3600
    ) -> None:
        """Block until ZAP scan reaches 100 or timeout."""
        elapsed = 0
        async with httpx.AsyncClient(timeout=10.0) as client:
            while elapsed < timeout_s:
                resp = await client.get(
                    f"{self.base_url}/JSON/ascan/view/status/",
                    params={"scanId": scan_id, "apikey": self._api_key},
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("status") == "100":
                    return
                await asyncio.sleep(poll_interval_s)
                elapsed += poll_interval_s
        msg = f"ZAP scan did not complete within {timeout_s}s"
        raise TimeoutError(msg)

    async def get_findings(self) -> list[Finding]:
        """Retrieve ZAP alerts and convert to Finding objects."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}/JSON/core/view/alerts/",
                params={"baseurl": self.base_url, "apikey": self._api_key},
            )
            resp.raise_for_status()
            data = resp.json()
            alerts: list[dict[str, object]] = data.get("alerts", [])

        findings: list[Finding] = []
        for alert in alerts:
            risk = str(alert.get("risk", "Informational"))
            cvss = _zap_severity_to_cvss(risk)
            findings.append(
                Finding(
                    module="zap",
                    title=str(alert.get("alert", "Unknown")),
                    endpoint=str(alert.get("url", "")),
                    method=str(alert.get("method", "GET")),
                    evidence=str(alert.get("evidence", "")),
                    cvss=cvss,
                    description=str(alert.get("description", "")),
                    remediation=str(alert.get("solution", "")),
                    source="zap",
                )
            )
        return findings

    async def export_xml(self, output_path: str) -> None:
        """Download ZAP XML report and write to output_path."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                f"{self.base_url}/OTHER/core/other/xmlreport/",
                params={"apikey": self._api_key},
            )
            resp.raise_for_status()
        import pathlib
        pathlib.Path(output_path).write_bytes(resp.content)
