"""AI-powered executive report polisher."""
from __future__ import annotations

import logging
from pathlib import Path

from pentora.context import ScanContext
from pentora.finding import Finding
from pentora.llm.base import Message
from pentora.llm.sanitizer import sanitize
from pentora.modules.ai.base import AIModule

log = logging.getLogger(__name__)


class ReportPolisherModule(AIModule):
    """Load all findings and ask LLM for an executive summary."""

    name = "ai.report_polisher"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        assert ctx.store is not None
        all_findings = await ctx.store.all()

        # Summarize findings to keep LLM prompt short
        summary_lines = []
        for f in all_findings[:30]:  # cap at 30
            summary_lines.append(
                f"[{f.severity.value.upper()}] {f.title} @ {f.endpoint}"
            )

        if not summary_lines:
            summary_lines = ["No findings recorded."]

        system_prompt = self._load_prompt("report_polisher")
        user_content = "\n".join(summary_lines)
        if self.sanitize:
            user_content = sanitize(user_content, target_host=None)

        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_content),
        ]
        try:
            response = await self.provider.chat(messages, model=self.model)
        except Exception as e:  # noqa: BLE001
            log.warning("report_polisher_llm_failed", extra={"error": str(e)})
            return []

        # Write executive summary to output dir
        summary_path: Path = ctx.output_dir / "executive-summary.md"
        summary_path.write_text(
            f"# Executive Summary\n\n{response.content}\n"
        )
        log.info("executive_summary_written", extra={"path": str(summary_path)})
        return []
