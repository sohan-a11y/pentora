"""Tests for LLM provider factory."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import pentora.llm.factory as factory_module
from pentora.llm.factory import make_provider
from pentora.llm.nvidia import NvidiaProvider
from pentora.llm.ollama import OllamaProvider
from pentora.llm.openrouter import OpenRouterProvider


def test_make_ollama(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", tmp_path / "last-llm.yaml")
    provider = make_provider("ollama", "llama3")
    assert isinstance(provider, OllamaProvider)
    assert provider.name == "ollama"


def test_make_openrouter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", tmp_path / "last-llm.yaml")
    provider = make_provider("openrouter", "claude-3-haiku")
    assert isinstance(provider, OpenRouterProvider)


def test_make_nvidia(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", tmp_path / "last-llm.yaml")
    provider = make_provider("nvidia", "llama3")
    assert isinstance(provider, NvidiaProvider)


def test_make_unknown_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", tmp_path / "last-llm.yaml")
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        make_provider("gpt5-super", "gpt5-super")


def test_make_last_no_cache_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "last-llm.yaml"
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", cache)
    with pytest.raises(ValueError, match="no previous choice cached"):
        make_provider("last", "whatever")


def test_make_last_uses_cached_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "last-llm.yaml"
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", cache)
    # First call caches "ollama"
    make_provider("ollama", "llama3")
    assert cache.exists()
    saved = yaml.safe_load(cache.read_text())
    assert saved["provider"] == "ollama"
    assert saved["model"] == "llama3"
    # "last" should resolve back to ollama
    provider = make_provider("last", "ignored")
    assert isinstance(provider, OllamaProvider)


def test_make_last_overrides_model_from_arg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "last-llm.yaml"
    monkeypatch.setattr(factory_module, "_LAST_LLM_PATH", cache)
    cache.write_text(yaml.dump({"provider": "nvidia", "model": "stored-model"}))
    # When last is used, cached model takes precedence over the passed model
    provider = make_provider("last", "new-model")
    assert isinstance(provider, NvidiaProvider)
