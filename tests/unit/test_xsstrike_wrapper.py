from pathlib import Path

from pentora.wrappers.xsstrike import XsstrikeHit, XsstrikeWrapper


def test_xsstrike_parses_vulnerable_vector() -> None:
    fixture = Path("tests/fixtures/xsstrike/vulnerable.txt").read_text()
    wrapper = XsstrikeWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    hit = result[0]
    assert isinstance(hit, XsstrikeHit)
    assert hit.param == "q"
    assert "confirm(1)" in hit.payload


def test_xsstrike_clean_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/xsstrike/clean.txt").read_text()
    wrapper = XsstrikeWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_xsstrike_empty_output() -> None:
    wrapper = XsstrikeWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_xsstrike_build_argv_uses_url() -> None:
    wrapper = XsstrikeWrapper()
    argv = wrapper.build_argv("https://t.example/search?q=1")
    assert "-u" in argv
    assert "https://t.example/search?q=1" in argv
