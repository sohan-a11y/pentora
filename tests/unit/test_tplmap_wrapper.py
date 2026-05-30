from pathlib import Path

from pentora.wrappers.tplmap import TplmapFinding, TplmapWrapper


def test_tplmap_parses_injection_point() -> None:
    fixture = Path("tests/fixtures/tplmap/injected.txt").read_text()
    wrapper = TplmapWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, TplmapFinding)
    assert finding.parameter == "name"
    assert finding.engine == "Jinja2"
    assert finding.evidence


def test_tplmap_clean_yields_no_findings() -> None:
    fixture = Path("tests/fixtures/tplmap/clean.txt").read_text()
    wrapper = TplmapWrapper()
    assert wrapper.parse(stdout=fixture, stderr="", returncode=0) == []


def test_tplmap_empty_output() -> None:
    wrapper = TplmapWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_tplmap_build_argv_uses_url() -> None:
    wrapper = TplmapWrapper()
    argv = wrapper.build_argv("https://t.example/?name=John")
    assert "-u" in argv
    assert "https://t.example/?name=John" in argv
