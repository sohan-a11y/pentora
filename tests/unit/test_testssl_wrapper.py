"""Tests for testssl wrapper parser."""
from __future__ import annotations

from pathlib import Path

from pentora.wrappers.testssl import TlsIssue, TlsScanWrapper


def test_testssl_parses_vulnerable_json() -> None:
    fixture = Path("tests/fixtures/testssl/vulnerable.json").read_text()
    wrapper = TlsScanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) >= 2
    assert all(isinstance(r, TlsIssue) for r in results)
    ids = [r.id for r in results]
    assert "SSLv3" in ids


def test_testssl_clean_yields_no_issues() -> None:
    fixture = Path("tests/fixtures/testssl/clean.json").read_text()
    wrapper = TlsScanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert results == []


def test_testssl_empty_output() -> None:
    wrapper = TlsScanWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_testssl_high_severity_cve_present() -> None:
    fixture = Path("tests/fixtures/testssl/vulnerable.json").read_text()
    wrapper = TlsScanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    high = [r for r in results if r.severity == "HIGH"]
    assert len(high) >= 1
    assert high[0].cve == "CVE-2014-3566"


def test_testssl_build_argv() -> None:
    wrapper = TlsScanWrapper()
    argv = wrapper.build_argv("t.example:443", "/tmp/out.json")
    assert "--jsonfile" in argv
    assert "t.example:443" in argv
