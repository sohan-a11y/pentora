from pathlib import Path

from pentora.wrappers.secretfinder import Secret, SecretFinderWrapper


def test_secretfinder_parses_json_secrets(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/secretfinder/secrets.json").read_text()
    wrapper = SecretFinderWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 4  # 1 google + 1 aws + 2 stripe
    file_url = "https://api.pure.app/static/app.js"
    google = Secret(
        type="google_api",
        value="AIzaSyD-EXAMPLEEXAMPLEEXAMPLEEXAMPLE1234",
        file_url=file_url,
    )
    assert google in results
    stripe = [s for s in results if s.type == "stripe_secret"]
    assert len(stripe) == 2


def test_secretfinder_parse_handles_empty(tmp_path: Path) -> None:
    wrapper = SecretFinderWrapper(log_dir=tmp_path)
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_secretfinder_build_argv_uses_url_and_json() -> None:
    wrapper = SecretFinderWrapper()
    argv = wrapper.build_argv("https://api.pure.app/static/app.js")
    assert "SecretFinder.py" in argv
    assert "-i" in argv
    assert "https://api.pure.app/static/app.js" in argv
    assert "-o" in argv
    assert "json" in argv
