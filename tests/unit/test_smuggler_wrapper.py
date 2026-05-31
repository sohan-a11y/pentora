from pathlib import Path

from pentora.wrappers.smuggler import SmugglerFinding, SmugglerWrapper


def test_smuggler_parses_issue() -> None:
    fixture = Path("tests/fixtures/smuggler/vulnerable.txt").read_text()
    wrapper = SmugglerWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, SmugglerFinding)
    assert "CL.TE" in finding.technique
    assert finding.evidence


def test_smuggler_clean_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/smuggler/clean.txt").read_text()
    wrapper = SmugglerWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_smuggler_empty_output() -> None:
    wrapper = SmugglerWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_smuggler_build_argv_uses_url() -> None:
    wrapper = SmugglerWrapper()
    argv = wrapper.build_argv("https://t.example/")
    assert "-u" in argv
    assert "https://t.example/" in argv
