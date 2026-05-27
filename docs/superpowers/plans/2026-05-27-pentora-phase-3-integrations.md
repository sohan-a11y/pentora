# Pentora Phase 3 — Integrations (Burp + ZAP + LLM)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Follow TDD pattern established in Phase 1.

**Pre-requisite:** Phase 2 complete. Tag `pentora-phase-2-complete` exists.

**Goal:** Add Burp Suite Pro REST API integration, OWASP ZAP fallback, pluggable LLM provider abstraction (Ollama / OpenRouter / NVIDIA NIM), and the 5 AI-powered modules from spec §5.18.

**Exit criteria:** `pentora scan https://target.com --proxy burp` routes scans through Burp Pro REST API. `pentora scan https://target.com --ai-mode --llm-provider ollama --llm-model qwen2.5-coder:7b` runs AI-powered modules with prompts sanitized.

**Phase tag at completion:** `git tag pentora-phase-3-complete`

---

## Module Group 17 — Burp Suite REST API integration

Spec ref: §5.17 (Burp portion)

### Task 74: Burp REST client

**Files:**
- Create: `src/pentora/proxy/__init__.py`
- Create: `src/pentora/proxy/base.py` (ProxyClient Protocol)
- Create: `src/pentora/proxy/burp.py`
- Create: `tests/unit/test_burp_client.py`

**`proxy/base.py`:**

```python
"""Common interface for Burp / ZAP integrations."""
from __future__ import annotations
from typing import Protocol

from pentora.finding import Finding


class ProxyClient(Protocol):
    name: str
    base_url: str

    async def is_alive(self) -> bool: ...
    async def add_to_scope(self, urls: list[str]) -> None: ...
    async def start_active_scan(self, urls: list[str]) -> str: ...
    async def wait_for_scan(self, scan_id: str, poll_interval_s: int = 5, timeout_s: int = 3600) -> None: ...
    async def get_findings(self) -> list[Finding]: ...
    async def export_xml(self, output_path: str) -> None: ...
```

**`proxy/burp.py`:** Implements `ProxyClient` for the `burp-rest-api` extension (https://github.com/vmware-archive/burp-rest-api).

Endpoints used:
- `GET /burp/versions` — health check
- `PUT /burp/target/scope?url={url}` — add to scope
- `POST /burp/scanner/scans/active?baseUrl={url}` — start active scan
- `GET /burp/scanner/status` — overall progress (returns int 0-100)
- `GET /burp/scanner/issues` — list issues (JSON)
- `GET /burp/report?reportType=XML` — export XML

Use `httpx.AsyncClient`. Map Burp severity (`High`/`Medium`/`Low`/`Information`) → Pentora `Severity`. Map Burp issue's `evidence.requestResponse.request` (base64) into Finding's `request_raw`.

**Test with respx mocking all 6 endpoints.** Assertions:
- `is_alive()` returns True when `/versions` returns 200
- `add_to_scope()` calls PUT with correct query param
- `start_active_scan()` returns scan id
- `wait_for_scan()` polls until status=100, then returns
- `get_findings()` returns `list[Finding]` with `source="burp"`
- `export_xml()` writes XML file

### Task 75: Burp CA cert auto-install + extension installer

**Files:**
- Create: `src/pentora/proxy/cert_install.py`
- Create: `src/pentora/proxy/extension_installer.py`
- Create: `tests/unit/test_cert_install.py`

`cert_install.py`:
- Fetch `http://127.0.0.1:8080/cert` (Burp returns DER-encoded CA when proxy is running)
- Convert DER → PEM via `cryptography.x509`
- Copy to `/usr/local/share/ca-certificates/burp.crt` (Debian/Kali)
- Run `update-ca-certificates` via subprocess (needs sudo — prompt if not root)
- Also install into Firefox cert store if Firefox installed

`extension_installer.py`:
- Download `burp-rest-api-2.1.0.jar` from GitHub releases
- Drop into `~/.pentora/burp-extensions/`
- Print instructions for one-time Burp setup: "Extender → Add → File → choose this jar"

### Task 76: Wire Burp into orchestrator

When `--proxy burp` is set:
1. Orchestrator instantiates `BurpClient`, checks `is_alive()`. If false, print clear error and exit.
2. After recon phase, calls `add_to_scope(discovered_live_hosts)`.
3. After discovery phase, calls `start_active_scan(discovered_endpoints)`.
4. After Pentora's own modules complete, calls `wait_for_scan()` then `get_findings()`.
5. Adds Burp's findings to `ctx.store` with `source="burp"`.
6. Calls `export_xml(ctx.output_dir / "burp-export.xml")`.

Update `cli.py` to thread `--proxy` flag through. Update `test_cli_scan_integration.py` with a respx-mocked Burp.

---

## Module Group 18 — OWASP ZAP REST API integration

Spec ref: §5.17 (ZAP portion)

### Task 77: ZAP REST client

**Files:**
- Create: `src/pentora/proxy/zap.py`
- Create: `tests/unit/test_zap_client.py`

Implements `ProxyClient` for ZAP daemon mode (`zap.sh -daemon -port 8090 -config api.key=YOURKEY`).

Endpoints:
- `GET /JSON/core/view/version/` — health
- `GET /JSON/spider/action/scan/?url={url}&apikey=...` — spider
- `GET /JSON/spider/view/status/?scanId={id}` — progress
- `GET /JSON/ascan/action/scan/?url={url}&apikey=...` — active scan
- `GET /JSON/ascan/view/status/?scanId={id}` — progress
- `GET /JSON/core/view/alerts/?baseurl={url}` — get alerts
- `GET /OTHER/core/other/xmlreport/` — XML export

Same Protocol implementation, same tests pattern.

Auto-detection: if `--proxy auto` (default), Pentora probes Burp's 1337 first, ZAP's 8090 second; picks whichever responds. Fall through to `none` (skip proxy phase) if neither responds.

---

## Module Group 19 — LLM Provider abstraction

Spec ref: §6

### Task 78: LLMProvider Protocol + sanitizer

**Files:**
- Create: `src/pentora/llm/__init__.py`
- Create: `src/pentora/llm/base.py`
- Create: `src/pentora/llm/sanitizer.py`
- Create: `tests/unit/test_sanitizer.py`

**`llm/base.py`:**

```python
"""LLM provider abstraction."""
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
    async def chat(self, messages: list[Message], model: str, temperature: float = 0.2) -> LLMResponse: ...
```

**`llm/sanitizer.py`:** Strip PII / target identifiers before sending to remote providers.

- Replace hostnames matching target's root → `<target-host>`
- Replace IPv4 / IPv6 → `<ip>`
- Replace email addresses → `<email>`
- Replace UUIDs, JWT tokens, hex strings ≥ 32 chars → `<token>`
- Replace numeric IDs in URLs → `<id>`

Tests cover each replacement category.

### Task 79: Ollama provider

**Files:**
- Create: `src/pentora/llm/ollama.py`
- Create: `tests/unit/test_ollama_provider.py`

POST `http://localhost:11434/api/chat` with `{"model": ..., "messages": [...], "stream": false}`. Parse response.

Test with respx mocking the Ollama endpoint.

### Task 80: OpenRouter provider

**Files:**
- Create: `src/pentora/llm/openrouter.py`
- Create: `tests/unit/test_openrouter_provider.py`

POST `https://openrouter.ai/api/v1/chat/completions` with OpenAI-format body. Reads `OPENROUTER_API_KEY` from env.

Test with respx.

### Task 81: NVIDIA NIM provider

**Files:**
- Create: `src/pentora/llm/nvidia.py`
- Create: `tests/unit/test_nvidia_provider.py`

POST `https://integrate.api.nvidia.com/v1/chat/completions` (OpenAI-compat). Reads `NVIDIA_API_KEY` from env.

### Task 82: Provider factory + last-llm cache

**Files:**
- Create: `src/pentora/llm/factory.py`
- Create: `tests/unit/test_llm_factory.py`

```python
def make_provider(name: str, model: str) -> LLMProvider:
    if name == "last":
        cache = Path.home() / ".pentora" / "last-llm.yaml"
        if not cache.exists():
            raise ValueError("--llm-provider last requested but no previous choice cached")
        cfg = yaml.safe_load(cache.read_text())
        name = cfg["provider"]; model = cfg["model"]
    if name == "ollama": return OllamaProvider(model=model)
    if name == "openrouter": return OpenRouterProvider(model=model)
    if name == "nvidia": return NvidiaProvider(model=model)
    raise ValueError(f"Unknown provider: {name}")
```

After successful provider instantiation, write `{"provider": name, "model": model}` to `~/.pentora/last-llm.yaml`.

---

## Module Group 20 — AI-powered modules

Spec ref: §5.18

### Task 83: AI module base + prompt loader

**Files:**
- Create: `src/pentora/modules/ai/__init__.py`
- Create: `src/pentora/modules/ai/base.py`
- Create: `src/pentora/llm/prompts/` directory

`ai/base.py`:

```python
class AIModule(PhaseModule):
    """Phase module that requires --ai-mode and an LLM provider."""

    def __init__(self, provider: LLMProvider, model: str, sanitize: bool = True):
        self.provider = provider
        self.model = model
        self.sanitize = sanitize
```

`prompts/` directory contains a `.txt` file per AI module's system prompt — kept out of source code so tweaks don't require Python edits.

### Tasks 84–88: Five AI modules

For each, follow Phase 1 TDD pattern. Each module is ~100 LOC + ~80 LOC tests.

#### Task 84: `modules/ai/logic_fuzzer.py`

Given the discovered API endpoints + the profile name (e.g., `dating`), prompts LLM to generate 5–10 business-logic test cases. For each test case, attempts the request, evaluates response. Emits Finding for unexpected behavior.

Prompt template at `prompts/logic_fuzzer.txt`. Returns JSON-structured test cases.

#### Task 85: `modules/ai/waf_mutator.py`

Used as fallback inside InjectionModule: when sqlmap/dalfox payloads all return 403/406/501, calls the LLM with the failing payload + observed WAF error to generate mutated payloads (Unicode normalization, comment injection, double-encoding, base64).

Tries each mutation; if any returns 200 instead of 403, the WAF bypass succeeded.

#### Task 86: `modules/ai/report_polisher.py`

Runs LAST in the orchestrator pipeline (after all reporters). Loads the raw findings, asks LLM to write a single-page client executive summary. Output appended to `summary.html` as a new `<section id="executive-summary">`.

Sanitizer always-on for this module (executive summaries should not contain real customer data — describe categories not specifics).

#### Task 87: `modules/ai/pivot_advisor.py`

Triggers when a "surprise" finding occurs (e.g., admin panel discovered, exposed Swagger doc). Asks LLM for next 3 attack steps. Adds these as `extra.suggested_next_steps` on the finding object.

#### Task 88: `modules/ai/auth_flow_reader.py`

Fetches login page HTML + JS. Asks LLM to identify the auth flow type (form-based, OAuth, magic-link, JWT-Bearer, OTP-2FA). Output written to `recon/auth-flow.json` and used by AuthModule to tailor its checks.

### Task 89: Wire `--ai-mode` into CLI

Add CLI options:

```python
@click.option("--ai-mode", is_flag=True, help="Enable LLM-powered modules")
@click.option("--llm-provider", type=click.Choice(["ollama", "openrouter", "nvidia", "last"]))
@click.option("--llm-model", default=None)
@click.option("--no-sanitize-llm", is_flag=True)
```

When `--ai-mode` is set:
- Require `--llm-provider` (else click error)
- Instantiate provider via factory
- Append AI modules to module list (in order: auth_flow_reader → logic_fuzzer → pivot_advisor → report_polisher; waf_mutator is invoked inline by InjectionModule when needed)
- Save `{provider, model}` to `~/.pentora/last-llm.yaml`

When `--ai-mode` NOT set: skip all AI modules entirely.

### Task 90: Phase 3 exit gate

- [ ] All tests pass with coverage ≥ 80%
- [ ] `ruff` + `mypy --strict` clean
- [ ] Update CHANGELOG.md
- [ ] Tag: `git tag pentora-phase-3-complete`

---

## Phase 3 Self-Review

1. **Spec coverage:** §5.17 (Burp + ZAP) → Module Groups 17–18. §6 (LLM provider abstraction) → Module Group 19. §5.18 (AI modules) → Module Group 20. All covered. ✅
2. **Placeholder scan:** None. ✅
3. **Type consistency:** `ProxyClient` Protocol used by `BurpClient` and `ZapClient`. `LLMProvider` Protocol used by `OllamaProvider`, `OpenRouterProvider`, `NvidiaProvider`. `Message` dataclass shared. ✅
4. **AI modules don't fire silently:** every AI module call goes through sanitizer (configurable off), logged to `logs/llm-invocations/`, and inert when `--ai-mode` not set. ✅
