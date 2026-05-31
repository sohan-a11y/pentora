"""Tests for NVIDIA NIM LLM provider."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from pentora.llm.base import Message
from pentora.llm.nvidia import NvidiaProvider

BASE = "https://integrate.api.nvidia.com/v1"


@respx.mock
@pytest.mark.asyncio
async def test_nvidia_chat_success() -> None:
    respx.post(f"{BASE}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                "choices": [
                    {"message": {"role": "assistant", "content": "SQLi detected at /api/login"}}
                ],
                "usage": {"prompt_tokens": 80, "completion_tokens": 15},
            },
        )
    )
    provider = NvidiaProvider(api_key="nvapi-test")
    msgs = [Message(role="user", content="Check for SQLi")]
    result = await provider.chat(msgs, model="nvidia/llama-3.1-nemotron-70b-instruct")
    assert result.content == "SQLi detected at /api/login"
    assert result.provider == "nvidia"
    assert result.prompt_tokens == 80
    assert result.completion_tokens == 15


@respx.mock
@pytest.mark.asyncio
async def test_nvidia_sends_auth_header() -> None:
    route = respx.post(f"{BASE}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "model": "nvidia/mistral-nemo-12b-instruct",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )
    )
    provider = NvidiaProvider(api_key="nvapi-secret")
    await provider.chat([Message(role="user", content="test")], model="nvidia/mistral-nemo-12b-instruct")
    assert route.called
    assert "Bearer nvapi-secret" in route.calls[0].request.headers["authorization"]
