"""Tests for OpenRouter LLM provider."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from pentora.llm.base import Message
from pentora.llm.openrouter import OpenRouterProvider

BASE = "https://openrouter.ai/api/v1"


@respx.mock
@pytest.mark.asyncio
async def test_openrouter_chat_success() -> None:
    respx.post(f"{BASE}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "model": "anthropic/claude-3-haiku",
                "choices": [
                    {"message": {"role": "assistant", "content": "Found XSS vulnerability"}}
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 25},
            },
        )
    )
    provider = OpenRouterProvider(api_key="test-key")
    msgs = [Message(role="user", content="Analyze for XSS")]
    result = await provider.chat(msgs, model="anthropic/claude-3-haiku")
    assert result.content == "Found XSS vulnerability"
    assert result.provider == "openrouter"
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 25


@respx.mock
@pytest.mark.asyncio
async def test_openrouter_sends_auth_header() -> None:
    route = respx.post(f"{BASE}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "model": "openai/gpt-4o",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )
    )
    provider = OpenRouterProvider(api_key="my-secret-key")
    await provider.chat([Message(role="user", content="test")], model="openai/gpt-4o")
    assert route.called
    assert "Bearer my-secret-key" in route.calls[0].request.headers["authorization"]
