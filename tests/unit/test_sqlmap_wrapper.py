from pathlib import Path

from pentora.wrappers.sqlmap import SqlmapFinding, SqlmapWrapper


def test_sqlmap_parses_injected_parameter() -> None:
    fixture = Path("tests/fixtures/sqlmap/injected.txt").read_text()
    wrapper = SqlmapWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, SqlmapFinding)
    assert finding.parameter == "id"
    assert "MySQL" in finding.dbms
    assert "time-based" in finding.technique or "boolean-based" in finding.technique
    assert finding.evidence


def test_sqlmap_clean_target_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/sqlmap/clean.txt").read_text()
    wrapper = SqlmapWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert result == []


def test_sqlmap_empty_output() -> None:
    wrapper = SqlmapWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=1) == []


def test_sqlmap_build_argv_uses_request_file() -> None:
    wrapper = SqlmapWrapper()
    argv = wrapper.build_argv("request.txt")
    assert argv[0] == "sqlmap"
    assert "-r" in argv
    assert "request.txt" in argv
    assert "--batch" in argv
