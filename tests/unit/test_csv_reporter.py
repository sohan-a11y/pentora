"""Tests for CSV reporter."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pentora.finding import CVSS, Finding
from pentora.reporters.csv_reporter import CsvReporter


def _make_finding() -> Finding:
    return Finding(
        module="sqli",
        title="SQL Injection",
        endpoint="https://target.com/api/users",
        method="POST",
        evidence="Database error",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        description="SQL injection vulnerability",
        remediation="Use parameterized queries",
    )


@pytest.mark.asyncio
async def test_csv_reporter_creates_file(tmp_path: Path) -> None:
    reporter = CsvReporter()
    out = await reporter.write(tmp_path, [_make_finding()], target="https://target.com")
    assert out == tmp_path / "findings.csv"
    assert out.exists()


@pytest.mark.asyncio
async def test_csv_reporter_headers(tmp_path: Path) -> None:
    reporter = CsvReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    with open(out, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "severity", "score", "module", "title", "endpoint",
            "method", "evidence", "remediation", "source", "discovered_at",
        ]


@pytest.mark.asyncio
async def test_csv_reporter_finding_row(tmp_path: Path) -> None:
    finding = _make_finding()
    reporter = CsvReporter()
    out = await reporter.write(tmp_path, [finding], target="https://target.com")
    with open(out, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["module"] == "sqli"
    assert row["title"] == "SQL Injection"
    assert row["endpoint"] == "https://target.com/api/users"
    assert row["method"] == "POST"
    assert float(row["score"]) > 0


@pytest.mark.asyncio
async def test_csv_reporter_utf8_bom(tmp_path: Path) -> None:
    """File must start with UTF-8 BOM for Excel compatibility."""
    reporter = CsvReporter()
    out = await reporter.write(tmp_path, [], target="https://target.com")
    raw = out.read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf", "File must start with UTF-8 BOM"


@pytest.mark.asyncio
async def test_csv_reporter_multiple_findings(tmp_path: Path) -> None:
    findings = [_make_finding() for _ in range(3)]
    reporter = CsvReporter()
    out = await reporter.write(tmp_path, findings, target="https://target.com")
    with open(out, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 3
