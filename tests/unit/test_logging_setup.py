from pathlib import Path

from pentora.logging_setup import log_tool_invocation, setup_logging


def test_setup_logging_creates_log_file(tmp_path: Path) -> None:
    setup_logging(tmp_path / "logs" / "pentora.log")
    assert (tmp_path / "logs").is_dir()


def test_log_tool_invocation_writes_record(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs" / "tool-invocations"
    log_dir.mkdir(parents=True)
    log_tool_invocation(
        log_dir=log_dir,
        tool="subfinder",
        argv=["subfinder", "-d", "pure.app"],
        stdout="api.pure.app\ncdn.pure.app\n",
        stderr="",
        returncode=0,
        duration_ms=2340,
    )
    files = list(log_dir.glob("*-subfinder.json"))
    assert len(files) == 1
    text = files[0].read_text()
    assert "api.pure.app" in text
    assert "\"returncode\": 0" in text
