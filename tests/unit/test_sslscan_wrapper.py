"""Tests for sslscan wrapper parser."""
from __future__ import annotations

from pathlib import Path

from pentora.wrappers.sslscan import SslIssue, SslscanWrapper


def test_sslscan_parses_vulnerable_xml() -> None:
    fixture = Path("tests/fixtures/sslscan/vulnerable.xml").read_text()
    wrapper = SslscanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) >= 2
    assert all(isinstance(r, SslIssue) for r in results)
    protocols = [r.protocol for r in results]
    assert "ssl" in protocols


def test_sslscan_clean_yields_no_issues() -> None:
    fixture = Path("tests/fixtures/sslscan/clean.xml").read_text()
    wrapper = SslscanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert results == []


def test_sslscan_empty_output() -> None:
    wrapper = SslscanWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_sslscan_high_severity_for_sslv2() -> None:
    fixture = Path("tests/fixtures/sslscan/vulnerable.xml").read_text()
    wrapper = SslscanWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    ssl_issues = [r for r in results if r.protocol == "ssl"]
    assert any(r.severity == "HIGH" for r in ssl_issues)


def test_sslscan_build_argv() -> None:
    wrapper = SslscanWrapper()
    argv = wrapper.build_argv("t.example")
    assert "sslscan" in argv
    assert "t.example" in argv
