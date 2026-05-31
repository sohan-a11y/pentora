"""AI module base — requires --ai-mode and a provider."""
from __future__ import annotations

from pathlib import Path

from pentora.llm.base import LLMProvider
from pentora.modules.base import PhaseModule

_PROMPTS_DIR = Path(__file__).parent.parent.parent / "llm" / "prompts"


class AIModule(PhaseModule):
    """Base class for LLM-powered phase modules."""

    def __init__(
        self,
        provider: LLMProvider,
        model: str,
        sanitize: bool = True,
    ) -> None:
        self.provider = provider
        self.model = model
        self.sanitize = sanitize

    def _load_prompt(self, name: str) -> str:
        """Load a system prompt from the prompts directory."""
        prompt_path = _PROMPTS_DIR / f"{name}.txt"
        if prompt_path.exists():
            return prompt_path.read_text().strip()
        return ""
