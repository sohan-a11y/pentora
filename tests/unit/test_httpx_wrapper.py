from pathlib import Path

from pentora.wrappers.httpx_tool import HttpxWrapper


def test_httpx_parses_jsonl_and_skips_dead(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/httpx/three_hosts.jsonl").read_text()
    wrapper = HttpxWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2  # dead one filtered
    assert results[0].url == "https://api.pure.app"
    assert results[0].status_code == 200
    assert "nginx" in results[0].tech
    assert results[1].url == "https://cdn.pure.app"


def test_httpx_build_argv_for_subdomain_list() -> None:
    wrapper = HttpxWrapper()
    argv = wrapper.build_argv(["api.pure.app", "cdn.pure.app"])
    assert "-json" in argv
    assert "-silent" in argv
    assert "-tech-detect" in argv
    assert "-title" in argv
