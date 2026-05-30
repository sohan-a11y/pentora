from pathlib import Path

from pentora.wrappers.ffuf import FfufHit, FfufWrapper


def test_ffuf_parses_json_results(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/ffuf/hits.json").read_text()
    wrapper = FfufWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2
    assert results[0] == FfufHit(url="https://api.pure.app/admin", status=200, length=4521)
    assert results[1].url == "https://api.pure.app/login"
    assert results[1].status == 302


def test_ffuf_parse_handles_empty_output(tmp_path: Path) -> None:
    wrapper = FfufWrapper(log_dir=tmp_path)
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_ffuf_build_argv_targets_fuzz_url_and_json() -> None:
    wrapper = FfufWrapper()
    argv = wrapper.build_argv("https://api.pure.app/FUZZ", "wordlists/common-dirs.txt")
    assert argv[0] == "ffuf"
    assert "-u" in argv
    assert "https://api.pure.app/FUZZ" in argv
    assert "-w" in argv
    assert "wordlists/common-dirs.txt" in argv
    assert "-of" in argv
    assert "json" in argv
