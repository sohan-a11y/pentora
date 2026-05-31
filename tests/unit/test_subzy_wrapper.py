"""Tests for subzy wrapper parser."""
from __future__ import annotations

from pathlib import Path

from pentora.wrappers.subzy import SubzyFinding, SubzyWrapper


def test_subzy_parses_vulnerable_json() -> None:
    fixture = Path("tests/fixtures/subzy/vulnerable.json").read_text()
    wrapper = SubzyWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2
    assert all(isinstance(r, SubzyFinding) for r in results)
    subdomains = [r.subdomain for r in results]
    assert "assets.t.example" in subdomains


def test_subzy_clean_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/subzy/clean.json").read_text()
    wrapper = SubzyWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert results == []


def test_subzy_empty_output() -> None:
    wrapper = SubzyWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_subzy_service_present() -> None:
    fixture = Path("tests/fixtures/subzy/vulnerable.json").read_text()
    wrapper = SubzyWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    github_findings = [r for r in results if r.service == "GitHub Pages"]
    assert len(github_findings) >= 1


def test_subzy_build_argv() -> None:
    wrapper = SubzyWrapper()
    argv = wrapper.build_argv("/tmp/targets.txt")
    assert "run" in argv
    assert "--targets" in argv
