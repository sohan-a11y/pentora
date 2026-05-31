from pathlib import Path

from pentora.wrappers.interactsh import InteractshSession, InteractshWrapper


def test_interactsh_parses_token_and_interactions() -> None:
    fixture = Path("tests/fixtures/interactsh/with_interactions.txt").read_text()
    wrapper = InteractshWrapper()
    sessions = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(sessions) == 1
    session = sessions[0]
    assert isinstance(session, InteractshSession)
    assert "abc123xyz" in session.token
    assert len(session.interactions) == 2
    assert "203.0.113.42" in session.interactions[0]


def test_interactsh_no_interactions() -> None:
    fixture = Path("tests/fixtures/interactsh/no_interactions.txt").read_text()
    wrapper = InteractshWrapper()
    sessions = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(sessions) == 1
    assert "def456uvw" in sessions[0].token
    assert sessions[0].interactions == []


def test_interactsh_unknown_token_when_missing() -> None:
    wrapper = InteractshWrapper()
    sessions = wrapper.parse(stdout="", stderr="", returncode=0)
    assert len(sessions) == 1
    assert "unknown" in sessions[0].token
    assert sessions[0].interactions == []


def test_interactsh_build_argv() -> None:
    wrapper = InteractshWrapper()
    argv = wrapper.build_argv()
    assert "interactsh-client" in argv[0]
    assert "-v" in argv


def test_interactsh_parses_token_from_stderr() -> None:
    stderr = "Your unique interactsh subdomain: xyz789.oast.fun"
    wrapper = InteractshWrapper()
    sessions = wrapper.parse(stdout="", stderr=stderr, returncode=0)
    assert "xyz789" in sessions[0].token
