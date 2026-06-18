"""LLM provider factory with last-choice caching."""
from __future__ import annotations

from pathlib import Path

import yaml

from pentora.llm.base import LLMProvider

_LAST_LLM_PATH = Path.home() / ".pentora" / "last-llm.yaml"


def make_provider(name: str, model: str) -> LLMProvider:
    """Instantiate an LLM provider by name, caching the choice.

    Pass ``name="last"`` to reuse the previously cached provider + model.
    """
    from pentora.llm.nvidia import NvidiaProvider
    from pentora.llm.ollama import OllamaProvider
    from pentora.llm.openrouter import OpenRouterProvider

    if name == "last":
        if not _LAST_LLM_PATH.exists():
            msg = (
                "--llm-provider last: no previous choice cached at "
                f"{_LAST_LLM_PATH}"
            )
            raise ValueError(msg)
        cfg: dict[str, str] = yaml.safe_load(_LAST_LLM_PATH.read_text())
        name = cfg["provider"]
        model = cfg.get("model", model)

    _LAST_LLM_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LAST_LLM_PATH.write_text(yaml.dump({"provider": name, "model": model}), encoding="utf-8")

    providers: dict[str, LLMProvider] = {
        "ollama": OllamaProvider(),
        "openrouter": OpenRouterProvider(),
        "nvidia": NvidiaProvider(),
    }
    if name not in providers:
        msg = f"Unknown LLM provider: {name!r}. Choose: ollama, openrouter, nvidia, last"
        raise ValueError(msg)
    return providers[name]
