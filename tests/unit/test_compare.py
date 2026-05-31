"""Tests for pentora compare command."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from click.testing import CliRunner

from pentora.cli import main
from pentora.finding import CVSS, Finding
from pentora.store import FindingsStore


def _make_finding(title: str, endpoint: str = "https://target.com/api") -> Finding:
    return Finding(
        module="sqli",
        title=title,
        endpoint=endpoint,
        method="GET",
        evidence="test evidence",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )


async def _seed(db_path: Path, findings: list[Finding]) -> None:
    store = FindingsStore(db_path)
    await store.init()
    for f in findings:
        await store.add(f)


def test_compare_identifies_new(tmp_path: Path) -> None:
    dir_a = tmp_path / "scan_a"
    dir_b = tmp_path / "scan_b"
    dir_a.mkdir()
    dir_b.mkdir()

    asyncio.run(_seed(dir_a / "findings.db", [_make_finding("Old Finding")]))
    asyncio.run(_seed(dir_b / "findings.db", [
        _make_finding("Old Finding"),
        _make_finding("New Finding", "https://target.com/new"),
    ]))

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(dir_a), str(dir_b)])
    assert result.exit_code == 0, result.output
    assert "NEW" in result.output
    assert "New Finding" in result.output


def test_compare_identifies_resolved(tmp_path: Path) -> None:
    dir_a = tmp_path / "scan_a"
    dir_b = tmp_path / "scan_b"
    dir_a.mkdir()
    dir_b.mkdir()

    asyncio.run(_seed(dir_a / "findings.db", [
        _make_finding("Old Finding"),
        _make_finding("Resolved Finding", "https://target.com/resolved"),
    ]))
    asyncio.run(_seed(dir_b / "findings.db", [_make_finding("Old Finding")]))

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(dir_a), str(dir_b)])
    assert result.exit_code == 0, result.output
    assert "RESOLVED" in result.output
    assert "Resolved Finding" in result.output


def test_compare_identifies_persists(tmp_path: Path) -> None:
    dir_a = tmp_path / "scan_a"
    dir_b = tmp_path / "scan_b"
    dir_a.mkdir()
    dir_b.mkdir()

    asyncio.run(_seed(dir_a / "findings.db", [_make_finding("Persistent Finding")]))
    asyncio.run(_seed(dir_b / "findings.db", [_make_finding("Persistent Finding")]))

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(dir_a), str(dir_b)])
    assert result.exit_code == 0, result.output
    assert "PERSISTS" in result.output
    assert "Persistent Finding" in result.output


def test_compare_writes_json(tmp_path: Path) -> None:
    dir_a = tmp_path / "scan_a"
    dir_b = tmp_path / "scan_b"
    dir_a.mkdir()
    dir_b.mkdir()

    asyncio.run(_seed(dir_a / "findings.db", []))
    asyncio.run(_seed(dir_b / "findings.db", [_make_finding("New Finding")]))

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["compare", str(dir_a), str(dir_b)])
        assert result.exit_code == 0, result.output
        assert Path("comparison.json").exists()
        doc = json.loads(Path("comparison.json").read_text())
        assert "new" in doc
        assert "resolved" in doc
        assert "persists" in doc
