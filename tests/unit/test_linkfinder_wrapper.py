from pathlib import Path

from pentora.wrappers.linkfinder import LinkFinderWrapper


def test_linkfinder_parses_cli_endpoints(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/linkfinder/endpoints.txt").read_text()
    wrapper = LinkFinderWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 5
    assert "/api/v1/users" in results
    assert "/api/v1/orders?id=" in results


def test_linkfinder_build_argv_runs_via_python() -> None:
    wrapper = LinkFinderWrapper()
    argv = wrapper.build_argv("https://api.pure.app/app.js")
    assert "LinkFinder.py" in argv
    assert "-i" in argv
    assert "https://api.pure.app/app.js" in argv
    assert "-o" in argv
    assert "cli" in argv
