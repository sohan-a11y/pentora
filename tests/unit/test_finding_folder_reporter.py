from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.finding_folder import FindingFolderReporter


@pytest.mark.asyncio
async def test_finding_folder_creates_bundle(tmp_path: Path) -> None:
    findings = [
        Finding(
            module="authz.idor",
            title="IDOR on /api/users/{id}",
            endpoint="https://x.com/api/users/99",
            method="GET",
            evidence="Returned User B's email",
            description="A's token accessed B's profile.",
            remediation="Server-side ownership check.",
            cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            request_raw="GET /api/users/99 HTTP/1.1\nAuthorization: Bearer abc\n",
            response_raw="HTTP/1.1 200 OK\n\n{\"email\":\"victim@x.com\"}",
        ),
    ]
    (tmp_path / "findings").mkdir()
    await FindingFolderReporter().write(tmp_path, findings, target="https://x.com")
    folders = list((tmp_path / "findings").iterdir())
    assert len(folders) == 1
    folder = folders[0]
    assert (folder / "finding.md").exists()
    assert (folder / "poc.sh").exists()
    assert (folder / "request.http").exists()
    assert (folder / "response.http").exists()
    assert "IDOR" in (folder / "finding.md").read_text()
    assert "victim@x.com" in (folder / "response.http").read_text()
