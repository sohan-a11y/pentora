"""LLM provider abstraction — protocol, Message, LLMResponse."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol


@dataclass
class Message:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMProvider(Protocol):
    name: str

    async def chat(
        self, messages: list[Message], model: str, temperature: float = 0.2
    ) -> LLMResponse: ...
