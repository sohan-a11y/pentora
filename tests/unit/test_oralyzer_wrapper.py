from pathlib import Path

import pytest

from pentora.wrappers.oralyzer import OralyzerHit, OralyzerWrapper


def test_oralyzer_parses_vulnerable_line() -> None:
    fixture = Path("tests/fixtures/oralyzer/redirect_found.txt").read_text()
    wrapper = OralyzerWrapper()
    hits = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(hits) == 1
    hit = hits[0]
    assert isinstance(hit, OralyzerHit)
    assert "example.com/login" in hit.url
    assert "evil.com" in hit.redirect_to


def test_oralyzer_clean_output_yields_no_hits() -> None:
    fixture = Path("tests/fixtures/oralyzer/clean.txt").read_text()
    wrapper = OralyzerWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_oralyzer_empty_output() -> None:
    wrapper = OralyzerWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_oralyzer_build_argv_uses_url() -> None:
    wrapper = OralyzerWrapper()
    argv = wrapper.build_argv("https://t.example/login?next=x")
    assert "-u" in argv
    assert "https://t.example/login?next=x" in argv


def test_oralyzer_multiple_vulnerable_lines() -> None:
    stdout = (
        "[VULNERABLE] https://a.com/?next=https://evil.com [redirect to: https://evil.com]\n"
        "[VULNERABLE] https://b.com/?url=https://bad.org [redirect to: https://bad.org]\n"
    )
    wrapper = OralyzerWrapper()
    hits = wrapper.parse(stdout=stdout, stderr="", returncode=0)
    assert len(hits) == 2
    urls = {h.url for h in hits}
    assert "https://a.com/?next=https://evil.com" in urls
    assert "https://b.com/?url=https://bad.org" in urls
