from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.html import HtmlReporter


@pytest.mark.asyncio
async def test_html_reporter_renders_summary_and_finding(tmp_path: Path) -> None:
    findings = [
        Finding(module="injection.sqli", title="SQLi on /search",
                endpoint="https://x.com/search?q=1", method="GET",
                evidence="time-based, 5s sleep",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    ]
    out = await HtmlReporter().write(tmp_path, findings, target="https://x.com")
    text = out.read_text()
    assert "<!DOCTYPE html>" in text
    assert "SQLi on /search" in text
    assert "CRITICAL" in text
    assert "9.8" in text
