from pathlib import Path

from pentora.wrappers.katana import KatanaWrapper


def test_katana_parses_jsonl_endpoints(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/katana/crawl.jsonl").read_text()
    wrapper = KatanaWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert results == [
        "https://api.pure.app/",
        "https://api.pure.app/login",
        "https://api.pure.app/api/search",
    ]


def test_katana_parse_skips_malformed(tmp_path: Path) -> None:
    wrapper = KatanaWrapper(log_dir=tmp_path)
    assert wrapper.parse(stdout='{"bad json\n', stderr="", returncode=0) == []


def test_katana_build_argv_uses_url_and_jsonl() -> None:
    wrapper = KatanaWrapper()
    argv = wrapper.build_argv("https://api.pure.app")
    assert argv[0] == "katana"
    assert "-u" in argv
    assert "https://api.pure.app" in argv
    assert "-jsonl" in argv
    assert "-silent" in argv
