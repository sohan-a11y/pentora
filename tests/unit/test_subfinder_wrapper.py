from pathlib import Path

from pentora.wrappers.subfinder import SubfinderWrapper


def test_subfinder_parses_newline_separated_subs(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/subfinder/two_subs.txt").read_text()
    wrapper = SubfinderWrapper(log_dir=tmp_path)
    result = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert result == ["api.pure.app", "cdn.pure.app"]


def test_subfinder_build_argv_uses_domain() -> None:
    wrapper = SubfinderWrapper()
    argv = wrapper.build_argv("pure.app")
    assert argv == ["subfinder", "-d", "pure.app", "-silent", "-all"]
