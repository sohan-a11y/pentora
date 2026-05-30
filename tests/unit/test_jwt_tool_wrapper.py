from pathlib import Path

from pentora.wrappers.jwt_tool import JwtToolWrapper


def test_jwt_tool_detects_alg_none_success(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/jwt_tool/alg_none_success.txt").read_text()
    wrapper = JwtToolWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 1
    assert results[0].attack == "alg-none"
    assert results[0].vulnerable is True
    assert "forged" in results[0].evidence.lower()


def test_jwt_tool_detects_brute_success(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/jwt_tool/brute_success.txt").read_text()
    wrapper = JwtToolWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 1
    assert results[0].attack == "brute-secret"
    assert results[0].vulnerable is True
    assert "secret123" in results[0].evidence


def test_jwt_tool_brute_failure_is_not_vulnerable(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/jwt_tool/brute_fail.txt").read_text()
    wrapper = JwtToolWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 1
    assert results[0].attack == "brute-secret"
    assert results[0].vulnerable is False


def test_jwt_tool_build_argv_alg_none() -> None:
    wrapper = JwtToolWrapper()
    argv = wrapper.build_argv("eyJ.eyJ.sig", "alg-none")
    assert "jwt_tool" in argv[0] or argv[0] == "jwt_tool"
    assert "eyJ.eyJ.sig" in argv
    assert "-X" in argv
    assert "a" in argv


def test_jwt_tool_build_argv_brute_secret_uses_wordlist() -> None:
    wrapper = JwtToolWrapper()
    argv = wrapper.build_argv("eyJ.eyJ.sig", "brute-secret")
    assert "-C" in argv
    assert "-d" in argv


def test_jwt_tool_build_argv_kid_injection() -> None:
    wrapper = JwtToolWrapper()
    argv = wrapper.build_argv("eyJ.eyJ.sig", "kid-injection")
    assert "-I" in argv
    assert "kid" in argv
