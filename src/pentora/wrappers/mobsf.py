"""MobSF -- Mobile Security Framework REST API wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

_DEFAULT_URL = "http://localhost:8000"
_DEFAULT_KEY = "mobsf-api-key"


@dataclass
class MobsfIssue:
    title: str
    description: str
    severity: str


class MobsfWrapper:
    """REST client for MobSF (not a ToolWrapper — uses HTTP not subprocess)."""

    def __init__(self, base_url: str = _DEFAULT_URL, api_key: str = _DEFAULT_KEY):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._headers = {"Authorization": api_key}

    async def scan_apk(self, apk_path: str) -> list[MobsfIssue]:
        """Upload APK, wait for scan, return issues."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            # Upload
            with open(apk_path, "rb") as fh:  # noqa: ASYNC230
                upload_resp = await client.post(
                    f"{self._base_url}/api/v1/upload",
                    headers=self._headers,
                    files={"file": fh},
                )
            upload_resp.raise_for_status()
            scan_hash: str = upload_resp.json()["hash"]

            # Trigger scan
            await client.post(
                f"{self._base_url}/api/v1/scan",
                headers=self._headers,
                data={"hash": scan_hash},
            )

            # Get JSON report
            report_resp = await client.post(
                f"{self._base_url}/api/v1/report_json",
                headers=self._headers,
                data={"hash": scan_hash},
            )
            report_resp.raise_for_status()
            return self._parse_report(report_resp.json())

    def _parse_report(self, report: dict[str, Any]) -> list[MobsfIssue]:
        issues: list[MobsfIssue] = []
        for level in ("high", "medium", "low"):
            for item in report.get(level, []):
                issues.append(
                    MobsfIssue(
                        title=str(item.get("title", "")),
                        description=str(item.get("description", "")),
                        severity=level.upper(),
                    )
                )
        return issues

    def parse_report_json(self, data: dict[str, Any]) -> list[MobsfIssue]:
        """Parse a MobSF JSON report dict directly (useful for testing)."""
        return self._parse_report(data)
