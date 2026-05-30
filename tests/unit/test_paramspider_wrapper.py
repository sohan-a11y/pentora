from pathlib import Path

from pentora.wrappers.paramspider import ParamSpiderWrapper


def test_paramspider_parses_urls_skipping_blanks(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/paramspider/urls.txt").read_text()
    wrapper = ParamSpiderWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 4
    assert results[0] == "https://api.pure.app/search?q=FUZZ"
    assert "https://api.pure.app/filter?category=FUZZ" in results


def test_paramspider_build_argv_uses_domain() -> None:
    wrapper = ParamSpiderWrapper()
    argv = wrapper.build_argv("pure.app")
    assert argv[0] == "paramspider"
    assert "-d" in argv
    assert "pure.app" in argv
