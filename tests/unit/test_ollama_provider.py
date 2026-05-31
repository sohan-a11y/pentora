"""Tests for Ollama LLM provider."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from pentora.llm.base import Message
from pentora.llm.ollama import OllamaProvider

BASE = "http://localhost:11434"


@respx.mock
@pytest.mark.asyncio
async def test_ollama_chat_success() -> None:
    respx.post(f"{BASE}/api/chat").mock(
        return_value=Response(
            200,
            json={
                "model": "llama3",
                "message": {"role": "assistant", "content": "Here is the analysis."},
                "prompt_eval_count": 42,
                "eval_count": 18,
            },
        )
    )
    provider = OllamaProvider()
    msgs = [Message(role="user", content="Analyze this endpoint")]
    result = await provider.chat(msgs, model="llama3")
    assert result.content == "Here is the analysis."
    assert result.model == "llama3"
    assert result.provider == "ollama"
    assert result.prompt_tokens == 42
    assert result.completion_tokens == 18


@respx.mock
@pytest.mark.asyncio
async def test_ollama_chat_uses_correct_payload() -> None:
    route = respx.post(f"{BASE}/api/chat").mock(
        return_value=Response(
            200,
            json={
                "model": "mistral",
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": 10,
                "eval_count": 5,
            },
        )
    )
    provider = OllamaProvider()
    msgs = [
        Message(role="system", content="You are a security expert"),
        Message(role="user", content="Find XSS"),
    ]
    await provider.chat(msgs, model="mistral", temperature=0.1)
    assert route.called
    sent = route.calls[0].request.content
    import json
    payload = json.loads(sent)
    assert payload["model"] == "mistral"
    assert payload["stream"] is False
    assert len(payload["messages"]) == 2
