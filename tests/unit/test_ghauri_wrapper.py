from pathlib import Path

from pentora.wrappers.ghauri import GhauriFinding, GhauriWrapper


def test_ghauri_parses_injected_parameter() -> None:
    fixture = Path("tests/fixtures/ghauri/injected.txt").read_text()
    wrapper = GhauriWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, GhauriFinding)
    assert finding.parameter == "id"
    assert "PostgreSQL" in finding.dbms
    assert "blind" in finding.technique
    assert finding.evidence


def test_ghauri_clean_target_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/ghauri/clean.txt").read_text()
    wrapper = GhauriWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_ghauri_empty_output() -> None:
    wrapper = GhauriWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=1) == []


def test_ghauri_build_argv_uses_request_file() -> None:
    wrapper = GhauriWrapper()
    argv = wrapper.build_argv("request.txt")
    assert argv[0] == "ghauri"
    assert "-r" in argv
    assert "request.txt" in argv
    assert "--batch" in argv
