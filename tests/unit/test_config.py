from pathlib import Path

from pentora.config import Config, load_config


def test_load_config_defaults_only() -> None:
    cfg = load_config()
    assert cfg.rate_limit == 10
    assert cfg.threads == 50
    assert cfg.proxy == "auto"


def test_user_config_overrides_defaults(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("defaults:\n  rate_limit: 25\n  proxy: zap\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    cfg = load_config()
    assert cfg.rate_limit == 25
    assert cfg.proxy == "zap"
    assert cfg.threads == 50  # unchanged default


def test_cli_overrides_win(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("defaults:\n  rate_limit: 25\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    cfg = load_config(cli_overrides={"rate_limit": 100})
    assert cfg.rate_limit == 100


def test_env_var_api_key_interpolation(tmp_path: Path, monkeypatch) -> None:
    user_cfg = tmp_path / "config.yaml"
    user_cfg.write_text("api_keys:\n  shodan: $MY_SHODAN_KEY\n")
    monkeypatch.setenv("PENTORA_CONFIG", str(user_cfg))
    monkeypatch.setenv("MY_SHODAN_KEY", "secret-token-123")
    cfg = load_config()
    assert cfg.api_keys["shodan"] == "secret-token-123"
