from pathlib import Path

from pentora.wrappers.graphw00f import Graphw00fResult, Graphw00fWrapper


def test_graphw00f_parses_fingerprint_json(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/graphw00f/fingerprint.json").read_text()
    wrapper = Graphw00fWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 1
    assert results[0] == Graphw00fResult(
        url="https://api.pure.app/graphql",
        engine="apollo",
        implementation="Apollo Server",
    )


def test_graphw00f_parse_handles_no_engine(tmp_path: Path) -> None:
    wrapper = Graphw00fWrapper(log_dir=tmp_path)
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []
    assert wrapper.parse(stdout='{"url": "x"}', stderr="", returncode=0) == []


def test_graphw00f_build_argv_targets_url() -> None:
    wrapper = Graphw00fWrapper()
    argv = wrapper.build_argv("https://api.pure.app/graphql")
    assert argv[0] == "graphw00f"
    assert "-d" in argv
    assert "-t" in argv
    assert "https://api.pure.app/graphql" in argv
