from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.markdown import MarkdownReporter


@pytest.mark.asyncio
async def test_markdown_reporter_outputs_grouped_by_severity(tmp_path: Path) -> None:
    findings = [
        Finding(module="recon", title="sub1", endpoint="https://x.com", method="-",
                evidence="HTTP 200",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")),
        Finding(module="injection.sqli", title="SQLi", endpoint="https://x.com/q?id=1",
                method="GET", evidence="time-based",
                cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    ]
    out = await MarkdownReporter().write(tmp_path, findings, target="https://x.com")
    text = out.read_text()
    assert "# Pentora Report — https://x.com" in text
    assert "## Critical (1)" in text
    assert "## Info (1)" in text
    assert "SQLi" in text
    assert "sub1" in text
