"""AI-powered business logic fuzzer."""
from __future__ import annotations

import json
import logging

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.llm.base import Message
from pentora.llm.sanitizer import sanitize
from pentora.modules.ai.base import AIModule

log = logging.getLogger(__name__)


class LogicFuzzerModule(AIModule):
    """Ask LLM to generate business logic test cases and execute them."""

    name = "ai.logic_fuzzer"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        assert ctx.store is not None

        # Gather recon/discovery endpoints
        all_findings = await ctx.store.all()
        endpoints = list({f.endpoint for f in all_findings if f.endpoint.startswith("http")})
        if not endpoints:
            endpoints = [ctx.target]

        system_prompt = self._load_prompt("logic_fuzzer")
        user_content = f"Target: {ctx.target}\nEndpoints: {json.dumps(endpoints[:10])}"
        if self.sanitize:
            user_content = sanitize(user_content, target_host=None)

        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_content),
        ]
        try:
            response = await self.provider.chat(messages, model=self.model)
        except Exception as e:  # noqa: BLE001
            log.warning("logic_fuzzer_llm_failed", extra={"error": str(e)})
            return []

        test_cases: list[dict[str, object]] = []
        try:
            # Extract JSON array from response
            raw = response.content.strip()
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start >= 0 and end > start:
                test_cases = json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            log.warning("logic_fuzzer_parse_failed", extra={"response": response.content[:200]})
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            for tc in test_cases:
                endpoint = str(tc.get("endpoint", ctx.target))
                method = str(tc.get("method", "POST")).upper()
                body = tc.get("body", {})
                try:
                    if method == "GET":
                        resp = await client.get(endpoint)
                    else:
                        resp = await client.post(endpoint, json=body)
                except httpx.HTTPError:
                    continue
                if resp.status_code < 400:
                    finding = Finding(
                        module=self.name,
                        title=f"AI logic test: {str(tc.get('test', 'unknown'))[:80]}",
                        endpoint=endpoint,
                        method=method,
                        evidence=f"HTTP {resp.status_code} — test passed unexpectedly",
                        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                        description="LLM-generated business logic test yielded a successful response.",  # noqa: E501
                        source="pentora",
                    )
                    findings.append(finding)
                    await ctx.store.add(finding)

        return findings
