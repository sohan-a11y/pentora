from pathlib import Path

from pentora.wrappers.commix import CommixFinding, CommixWrapper


def test_commix_parses_injected_parameter() -> None:
    fixture = Path("tests/fixtures/commix/injected.txt").read_text()
    wrapper = CommixWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, CommixFinding)
    assert finding.parameter == "addr"
    assert "command injection" in finding.technique
    assert finding.evidence


def test_commix_clean_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/commix/clean.txt").read_text()
    wrapper = CommixWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_commix_empty_output() -> None:
    wrapper = CommixWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_commix_build_argv_uses_url() -> None:
    wrapper = CommixWrapper()
    argv = wrapper.build_argv("https://t.example/ping?addr=1")
    assert argv[0] == "commix"
    assert "--url" in argv
    assert "https://t.example/ping?addr=1" in argv
    assert "--batch" in argv
