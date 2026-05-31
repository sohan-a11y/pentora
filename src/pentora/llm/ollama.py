"""Ollama local LLM provider."""
from __future__ import annotations

import httpx

from pentora.llm.base import LLMResponse, Message


class OllamaProvider:
    """LLM provider backed by a local Ollama instance."""

    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self._base_url = base_url.rstrip("/")

    async def chat(
        self, messages: list[Message], model: str, temperature: float = 0.2
    ) -> LLMResponse:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": m.role, "content": m.content} for m in messages
                    ],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data: dict[str, object] = resp.json()

        msg = data.get("message")
        content = str(msg.get("content", "")) if isinstance(msg, dict) else ""
        ptok = data.get("prompt_eval_count")
        ctok = data.get("eval_count")
        return LLMResponse(
            content=content,
            model=str(data.get("model", model)),
            provider="ollama",
            prompt_tokens=int(ptok) if isinstance(ptok, int) else 0,
            completion_tokens=int(ctok) if isinstance(ctok, int) else 0,
        )
