"""Tests for AI-powered modules using a fake LLM provider."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from httpx import Response

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.llm.base import LLMProvider, LLMResponse, Message
from pentora.modules.ai.auth_flow_reader import AuthFlowReaderModule
from pentora.modules.ai.logic_fuzzer import LogicFuzzerModule
from pentora.modules.ai.pivot_advisor import PivotAdvisorModule
from pentora.modules.ai.report_polisher import ReportPolisherModule
from pentora.modules.ai.waf_mutator import WafMutatorModule
from pentora.scope import Scope


class FakeLLM:
    """Fake LLM provider for tests — returns a canned response."""

    name = "fake"

    def __init__(self, content: str = "[]") -> None:
        self._content = content

    async def chat(
        self, messages: list[Message], model: str, temperature: float = 0.2
    ) -> LLMResponse:
        return LLMResponse(
            content=self._content,
            model=model,
            provider="fake",
            prompt_tokens=10,
            completion_tokens=5,
        )


def _ctx(tmp_path: Path, extra: dict[str, object] | None = None) -> ScanContext:
    ctx = ScanContext(
        target="https://example.com",
        output_dir=tmp_path,
        config=Config(),
        scope=Scope(include=["example.com"]),
        extra=extra or {},
    )
    return ctx


# ─── LogicFuzzerModule ──────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_logic_fuzzer_executes_test_cases(tmp_path: Path) -> None:
    test_cases = json.dumps([
        {"test": "access protected without auth", "endpoint": "https://example.com/api/admin",
         "method": "GET", "body": {}}
    ])
    llm = FakeLLM(content=test_cases)
    module = LogicFuzzerModule(provider=llm, model="fake")

    # Mock the HTTP call to the endpoint
    respx.get("https://example.com/api/admin").mock(return_value=Response(200, text="admin page"))

    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await module.run(ctx)
    assert len(findings) == 1
    assert findings[0].module == "ai.logic_fuzzer"


@pytest.mark.asyncio
async def test_logic_fuzzer_handles_bad_json(tmp_path: Path) -> None:
    llm = FakeLLM(content="not valid json at all")
    module = LogicFuzzerModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    findings = await module.run(ctx)
    assert findings == []


# ─── WafMutatorModule ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_mutator_stores_mutations(tmp_path: Path) -> None:
    mutations = json.dumps(["<SCRIPT>alert(1)</SCRIPT>", "javascript:alert(1)", "%3Cscript%3E"])
    llm = FakeLLM(content=mutations)
    module = WafMutatorModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path, extra={"blocked_payload": "<script>", "waf_error": "blocked"})
    await ctx.prepare()
    await module.run(ctx)
    assert "waf_mutations" in ctx.extra
    assert len(ctx.extra["waf_mutations"]) == 3  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_waf_mutator_empty_on_bad_json(tmp_path: Path) -> None:
    llm = FakeLLM(content="invalid json")
    module = WafMutatorModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    await module.run(ctx)
    assert ctx.extra.get("waf_mutations") == []


# ─── ReportPolisherModule ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_polisher_writes_summary(tmp_path: Path) -> None:
    llm = FakeLLM(content="Overall risk is high. The main issues are...")
    module = ReportPolisherModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    # Add a finding to store
    f = Finding(
        module="auth",
        title="No rate limit",
        endpoint="https://example.com/login",
        method="POST",
        evidence="tested",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    )
    await ctx.store.add(f)  # type: ignore[union-attr]
    await module.run(ctx)
    summary = tmp_path / "executive-summary.md"
    assert summary.exists()
    content = summary.read_text()
    assert "Executive Summary" in content
    assert "Overall risk is high" in content


@pytest.mark.asyncio
async def test_report_polisher_no_findings(tmp_path: Path) -> None:
    llm = FakeLLM(content="No issues found.")
    module = ReportPolisherModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    result = await module.run(ctx)
    assert result == []


# ─── PivotAdvisorModule ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pivot_advisor_annotates_critical_findings(tmp_path: Path) -> None:
    """Pivot advisor must run without error and call LLM for critical findings."""
    call_count = 0

    class CountingLLM:
        name = "counting"
        steps = json.dumps([
            {"step": "Try SSRF", "rationale": "Internal ports reachable", "risk_level": "high"}
        ])

        async def chat(
            self, messages: list[Message], model: str, temperature: float = 0.2
        ) -> LLMResponse:
            nonlocal call_count
            call_count += 1
            return LLMResponse(content=self.steps, model=model, provider="counting")

    module = PivotAdvisorModule(provider=CountingLLM(), model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    critical_finding = Finding(
        module="injection",
        title="SQL Injection",
        endpoint="https://example.com/api",
        method="GET",
        evidence="error in query",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    await ctx.store.add(critical_finding)  # type: ignore[union-attr]
    result = await module.run(ctx)
    # Module returns empty list (pivot advice added to finding objects, not as new findings)
    assert result == []
    # LLM was called once for the one critical finding
    assert call_count == 1


@pytest.mark.asyncio
async def test_pivot_advisor_skips_low_findings(tmp_path: Path) -> None:
    llm = FakeLLM(content="[]")
    module = PivotAdvisorModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    low_finding = Finding(
        module="headers",
        title="Missing CSP",
        endpoint="https://example.com/",
        method="GET",
        evidence="no csp header",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    await ctx.store.add(low_finding)  # type: ignore[union-attr]
    await module.run(ctx)
    assert "suggested_next_steps" not in low_finding.extra


# ─── AuthFlowReaderModule ───────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_auth_flow_reader_writes_json(tmp_path: Path) -> None:
    auth_data = {
        "auth_type": "form",
        "token_location": "cookie",
        "two_fa_mechanism": "none",
        "login_endpoint": "/login",
        "notes": "Standard username/password form",
    }
    respx.get("https://example.com/login").mock(
        return_value=Response(200, html="<form><input name=email><input name=password></form>")
    )
    llm = FakeLLM(content=json.dumps(auth_data))
    module = AuthFlowReaderModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    await module.run(ctx)
    auth_file = tmp_path / "recon" / "auth-flow.json"
    assert auth_file.exists()
    data = json.loads(auth_file.read_text())
    assert data["auth_type"] == "form"


@respx.mock
@pytest.mark.asyncio
async def test_auth_flow_reader_no_login_page(tmp_path: Path) -> None:
    # All login paths return 404
    for path in ["/login", "/signin", "/auth/login", "/account/login"]:
        respx.get(f"https://example.com{path}").mock(return_value=Response(404))
    llm = FakeLLM(content="{}")
    module = AuthFlowReaderModule(provider=llm, model="fake")
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    result = await module.run(ctx)
    assert result == []
