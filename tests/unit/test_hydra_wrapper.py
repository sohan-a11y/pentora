from pathlib import Path

from pentora.wrappers.hydra import HydraCredential, HydraWrapper


def test_hydra_parses_found_credentials(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/hydra/found.txt").read_text()
    wrapper = HydraWrapper(log_dir=tmp_path)
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2
    assert HydraCredential(host="x.com", login="admin", password="Password123") in results
    assert HydraCredential(host="x.com", login="root", password="toor") in results


def test_hydra_no_creds_returns_empty(tmp_path: Path) -> None:
    wrapper = HydraWrapper(log_dir=tmp_path)
    out = "Hydra v9.5\n[STATUS] attack finished\n0 valid passwords found\n"
    assert wrapper.parse(stdout=out, stderr="", returncode=0) == []


def test_hydra_build_argv_for_http_post_form() -> None:
    wrapper = HydraWrapper()
    argv = wrapper.build_argv(
        host="x.com",
        userlist="users.txt",
        passlist="passwords.txt",
        form_path="/login:user=^USER^&pass=^PASS^:F=invalid",
        service="https-post-form",
    )
    assert argv[0] == "hydra"
    assert "-L" in argv
    assert "users.txt" in argv
    assert "-P" in argv
    assert "passwords.txt" in argv
    assert "x.com" in argv
    assert "https-post-form" in argv
