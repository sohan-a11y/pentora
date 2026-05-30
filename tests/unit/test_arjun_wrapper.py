from pathlib import Path

from pentora.wrappers.arjun import ArjunParam, ArjunWrapper


def test_arjun_parses_json_params(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/arjun/params.json").read_text()
    wrapper = ArjunWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 3
    assert ArjunParam(endpoint="https://api.pure.app/search", name="q", method="GET") in results
    assert ArjunParam(endpoint="https://api.pure.app/search", name="page", method="GET") in results
    assert (
        ArjunParam(endpoint="https://api.pure.app/profile", name="user_id", method="POST")
        in results
    )


def test_arjun_parse_handles_empty(tmp_path: Path) -> None:
    wrapper = ArjunWrapper(log_dir=tmp_path)
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_arjun_build_argv_uses_url_and_json_out() -> None:
    wrapper = ArjunWrapper()
    argv = wrapper.build_argv("https://api.pure.app/search")
    assert argv[0] == "arjun"
    assert "-u" in argv
    assert "https://api.pure.app/search" in argv
    assert "-oJ" in argv
