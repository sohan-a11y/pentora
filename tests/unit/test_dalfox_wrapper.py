from pathlib import Path

from pentora.wrappers.dalfox import DalfoxHit, DalfoxWrapper


def test_dalfox_parses_json_array() -> None:
    fixture = Path("tests/fixtures/dalfox/hits.json").read_text()
    wrapper = DalfoxWrapper()
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(result) == 2
    first = result[0]
    assert isinstance(first, DalfoxHit)
    assert first.param == "q"
    assert first.payload == "<script>alert(1)</script>"
    assert first.type == "V"
    assert first.severity == "High"


def test_dalfox_parses_jsonl_lines() -> None:
    line1 = '{"type": "V", "param": "x", "payload": "p1", "severity": "High"}'
    line2 = '{"type": "G", "param": "y", "payload": "p2", "severity": "Low"}'
    wrapper = DalfoxWrapper()
    result = wrapper.parse(stdout=f"{line1}\n{line2}\n", stderr="", returncode=0)
    assert {h.param for h in result} == {"x", "y"}


def test_dalfox_empty_output() -> None:
    wrapper = DalfoxWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_dalfox_garbage_output() -> None:
    wrapper = DalfoxWrapper()
    assert wrapper.parse(stdout="not json at all", stderr="", returncode=0) == []


def test_dalfox_build_argv_uses_url_and_json_format() -> None:
    wrapper = DalfoxWrapper()
    argv = wrapper.build_argv("https://t.example/search?q=1")
    assert argv[0] == "dalfox"
    assert "url" in argv
    assert "https://t.example/search?q=1" in argv
    assert "json" in argv
