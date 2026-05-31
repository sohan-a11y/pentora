"""NVIDIA NIM LLM provider — OpenAI-compatible API."""
from __future__ import annotations

import os

import httpx

from pentora.llm.base import LLMResponse, Message

_BASE_URL = "https://integrate.api.nvidia.com/v1"


class NvidiaProvider:
    """LLM provider backed by NVIDIA NIM API (integrate.api.nvidia.com)."""

    name = "nvidia"

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("NVIDIA_API_KEY", "")

    async def chat(
        self, messages: list[Message], model: str, temperature: float = 0.2
    ) -> LLMResponse:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{_BASE_URL}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": m.role, "content": m.content} for m in messages
                    ],
                    "temperature": temperature,
                },
            )
            resp.raise_for_status()
            data: dict[str, object] = resp.json()

        choices = data.get("choices")
        content = ""
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict):
                    content = str(msg.get("content", ""))

        usage = data.get("usage")
        ptok = 0
        ctok = 0
        if isinstance(usage, dict):
            ptok_raw = usage.get("prompt_tokens")
            ctok_raw = usage.get("completion_tokens")
            ptok = int(ptok_raw) if isinstance(ptok_raw, int) else 0
            ctok = int(ctok_raw) if isinstance(ctok_raw, int) else 0

        return LLMResponse(
            content=content,
            model=str(data.get("model", model)),
            provider="nvidia",
            prompt_tokens=ptok,
            completion_tokens=ctok,
        )
