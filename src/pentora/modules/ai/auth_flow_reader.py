"""AI-powered auth flow analyzer."""
from __future__ import annotations

import json
import logging

import httpx

from pentora.context import ScanContext
from pentora.finding import Finding
from pentora.llm.base import Message
from pentora.llm.sanitizer import sanitize
from pentora.modules.ai.base import AIModule

log = logging.getLogger(__name__)

_DEFAULT_LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/account/login"]


class AuthFlowReaderModule(AIModule):
    """Fetch login page HTML and ask LLM to identify the auth mechanism."""

    name = "ai.auth_flow_reader"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        base = ctx.target.rstrip("/")
        html = await self._fetch_login_page(base)
        if not html:
            return []

        system_prompt = self._load_prompt("auth_flow_reader")
        user_content = f"URL: {base}\n\n{html[:4000]}"  # cap to avoid token overflow
        if self.sanitize:
            user_content = sanitize(user_content, target_host=None)

        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_content),
        ]
        try:
            response = await self.provider.chat(messages, model=self.model)
        except Exception as e:  # noqa: BLE001
            log.warning("auth_flow_reader_llm_failed", extra={"error": str(e)})
            return []

        auth_data: dict[str, object] = {}
        try:
            raw = response.content.strip()
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                auth_data = json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            auth_data = {"raw_response": response.content}

        # Write to recon output
        out_path = ctx.output_dir / "recon" / "auth-flow.json"
        out_path.write_text(json.dumps(auth_data, indent=2))
        log.info("auth_flow_written", extra={"path": str(out_path)})
        return []

    async def _fetch_login_page(self, base: str) -> str:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            for path in _DEFAULT_LOGIN_PATHS:
                try:
                    resp = await client.get(f"{base}{path}")
                    if resp.status_code == 200:
                        return resp.text
                except httpx.HTTPError:
                    continue
        return ""
