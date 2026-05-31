"""AI-powered WAF bypass payload mutator."""
from __future__ import annotations

import json
import logging

from pentora.context import ScanContext
from pentora.finding import Finding
from pentora.llm.base import Message
from pentora.llm.sanitizer import sanitize
from pentora.modules.ai.base import AIModule

log = logging.getLogger(__name__)


class WafMutatorModule(AIModule):
    """Ask LLM to generate WAF bypass mutations for a blocked payload.

    This module is typically invoked as a helper rather than a standalone
    phase.  The ``payload`` and ``waf_error`` context come from ctx.extra.
    """

    name = "ai.waf_mutator"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        payload = str(ctx.extra.get("blocked_payload", "<script>alert(1)</script>"))
        waf_error = str(ctx.extra.get("waf_error", "WAF blocked request"))

        system_prompt = self._load_prompt("waf_mutator")
        user_content = f"Blocked payload: {payload}\nWAF error: {waf_error}"
        if self.sanitize:
            user_content = sanitize(user_content, target_host=None)

        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_content),
        ]
        try:
            response = await self.provider.chat(messages, model=self.model)
        except Exception as e:  # noqa: BLE001
            log.warning("waf_mutator_llm_failed", extra={"error": str(e)})
            return []

        mutations: list[str] = []
        try:
            raw = response.content.strip()
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start >= 0 and end > start:
                mutations = json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            log.warning("waf_mutator_parse_failed", extra={"response": response.content[:200]})

        # Store mutations in extra for downstream use
        ctx.extra["waf_mutations"] = mutations
        return []
