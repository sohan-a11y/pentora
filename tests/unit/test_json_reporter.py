import json
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.json_reporter import JsonReporter


@pytest.mark.asyncio
async def test_json_reporter_writes_summary(tmp_path: Path) -> None:
    findings = [
        Finding(
            module="recon",
            title="api.pure.app live",
            endpoint="https://api.pure.app",
            method="GET",
            evidence="HTTP 200",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        ),
    ]
    reporter = JsonReporter()
    out = await reporter.write(tmp_path, findings, target="https://pure.app")
    assert out == tmp_path / "summary.json"
    doc = json.loads(out.read_text())
    assert doc["target"] == "https://pure.app"
    assert doc["findings_count"] == 1
    assert doc["findings"][0]["title"] == "api.pure.app live"
    assert doc["findings"][0]["cvss"]["vector"].startswith("CVSS:3.1/")
