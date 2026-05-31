"""AI-powered pivot advisor — suggest next attack steps."""
from __future__ import annotations

import json
import logging

from pentora.context import ScanContext
from pentora.finding import Finding, Severity
from pentora.llm.base import Message
from pentora.llm.sanitizer import sanitize
from pentora.modules.ai.base import AIModule

log = logging.getLogger(__name__)


class PivotAdvisorModule(AIModule):
    """For each Critical/High finding, ask LLM for next attack steps."""

    name = "ai.pivot_advisor"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        assert ctx.store is not None
        all_findings = await ctx.store.all()
        high_findings = [
            f for f in all_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        system_prompt = self._load_prompt("pivot_advisor")

        for finding in high_findings[:10]:  # cap at 10
            user_content = (
                f"Finding: {finding.title}\n"
                f"Endpoint: {finding.endpoint}\n"
                f"Evidence: {finding.evidence}\n"
                f"Severity: {finding.severity.value}"
            )
            if self.sanitize:
                user_content = sanitize(user_content, target_host=None)

            messages = [
                Message(role="system", content=system_prompt),
                Message(role="user", content=user_content),
            ]
            try:
                response = await self.provider.chat(messages, model=self.model)
            except Exception as e:  # noqa: BLE001
                log.warning("pivot_advisor_llm_failed", extra={"error": str(e)})
                continue

            next_steps: list[object] = []
            try:
                raw = response.content.strip()
                start = raw.find("[")
                end = raw.rfind("]") + 1
                if start >= 0 and end > start:
                    next_steps = json.loads(raw[start:end])
            except (json.JSONDecodeError, ValueError):
                next_steps = [response.content]

            # Store in finding.extra — note Finding is not frozen, extra is a dict
            finding.extra["suggested_next_steps"] = next_steps

        return []
