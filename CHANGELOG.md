# Changelog

## [0.3.0] — 2026-05-31

### Phase 3: Proxy & LLM Integrations

353 tests, 89% coverage. ruff + mypy --strict clean. Tagged `pentora-phase-3-complete`.

#### Prep Refactors

- `Orchestrator` now accepts optional `on_phase_start` / `on_phase_end` async callbacks
- `ScanContext` gains `extra: dict[str, object]`, `proxy_url: str | None`, and `http_client()` factory

#### Module Group 17 — Burp REST API (Tasks 74-76)

- `src/pentora/proxy/base.py` — `ProxyClient` Protocol (6 methods)
- `src/pentora/proxy/burp.py` — `BurpClient`: is_alive, add_to_scope, start_active_scan, wait_for_scan, get_findings, export_xml
- `src/pentora/proxy/cert_install.py` — fetch + install Burp CA cert
- `src/pentora/proxy/extension_installer.py` — print Burp REST API extension instructions
- Orchestrator wired: after recon → add_to_scope; after discovery → start_active_scan; post-all → wait + collect + export

#### Module Group 18 — ZAP REST (Task 77)

- `src/pentora/proxy/zap.py` — `ZapClient`: all 6 ProxyClient methods via ZAP JSON API
- Auto-detect mode: probe Burp 1337, then ZAP 8090; skip if neither responds
- CLI: `--proxy burp|zap|none|auto` flag added to `scan` command

#### Module Group 19 — LLM Provider Abstraction (Tasks 78-82)

- `src/pentora/llm/base.py` — `LLMProvider` Protocol, `Message`, `LLMResponse` dataclasses
- `src/pentora/llm/sanitizer.py` — PII stripper: host, IPv4/IPv6, email, UUID, JWT, hex tokens, URL numeric IDs
- `src/pentora/llm/ollama.py` — Ollama local provider
- `src/pentora/llm/openrouter.py` — OpenRouter (OpenAI-format) provider
- `src/pentora/llm/nvidia.py` — NVIDIA NIM provider
- `src/pentora/llm/factory.py` — `make_provider()` with last-choice caching at `~/.pentora/last-llm.yaml`

#### Module Group 20 — AI Modules (Tasks 83-89)

- `src/pentora/modules/ai/base.py` — `AIModule` base (provider, model, sanitize)
- `src/pentora/modules/ai/logic_fuzzer.py` — LLM generates 5 business-logic test cases and executes them
- `src/pentora/modules/ai/waf_mutator.py` — LLM generates WAF bypass payload variants
- `src/pentora/modules/ai/report_polisher.py` — LLM writes executive summary to `executive-summary.md`
- `src/pentora/modules/ai/pivot_advisor.py` — LLM suggests next attack steps for Critical/High findings
- `src/pentora/modules/ai/auth_flow_reader.py` — LLM analyzes login page HTML → writes `recon/auth-flow.json`
- `src/pentora/llm/prompts/` — 5 system prompt files

#### CLI Additions

- `--ai-mode` — enables LLM modules (requires `--llm-provider`)
- `--llm-provider ollama|openrouter|nvidia|last`
- `--llm-model` — model name passed to provider
- `--no-sanitize-llm` — disable PII stripping
- `--apk <path>` — path to Android APK (stored in `ctx.extra["apk_path"]`)
- `--proxy burp|zap|none|auto`

---

## [0.2.0] — 2026-05-31

### Phase 2: 16-Module Attack Suite

All 16 modules now wired into PHASE_MAP. 288 tests, 91% coverage.

#### Security Utilities

- `src/pentora/security/secret_patterns.py` — 14 regex patterns (AWS, Stripe, GitHub, Slack, Google, Twilio, SendGrid, Mapbox, JWT, SSH, Generic, NVIDIA)
- `src/pentora/security/csp_evaluator.py` — CSP header analyzer (unsafe-inline, unsafe-eval, wildcard, missing object-src/base-uri/frame-ancestors)
- `src/pentora/data/takeover_fingerprints.py` — 15 subdomain takeover service fingerprints
- `src/pentora/data/takeover_fingerprints.py` — 15 subdomain takeover service fingerprints

#### New Modules (Tasks 53-69)

| # | Module | Phase Key | Summary |
|---|--------|-----------|---------|
| 1 | DisclosureModule | `disclosure` | JS secret scan, source-map exposure, HTML comment mining |
| 2 | TransportModule | `transport` | testssl TLS scan, HSTS check, mixed-content detection |
| 3 | HeadersModule | `headers` | CSP evaluation, X-Content-Type, X-Frame, Referrer, Permissions-Policy |
| 4 | CorsModule | `cors` | Reflected origin, null origin, wildcard+credentials |
| 5 | TakeoverModule | `takeover` | 15 service fingerprints (GitHub Pages, S3, Heroku, Azure, ...) |
| 6 | RateLimitModule | `ratelimit` | 30-request burst test on auth/login/otp endpoints |
| 7 | MobileModule | `mobile` | apktool + jadx + MobSF, graceful degradation if tools absent |
| 8 | CloudModule | `cloud` | Firebase/.json, Azure blob, GCS, S3 bucket probing |

#### New Wrappers (Tasks 54-68)

- `testssl.py` (TlsScanWrapper) — JSON output parser, TlsIssue dataclass
- `sslscan.py` (SslscanWrapper) — XML output parser, SslIssue dataclass
- `subzy.py` (SubzyWrapper) — JSON parser, SubzyFinding dataclass
- `apktool.py` (ApktoolWrapper) — APK decompiler
- `jadx.py` (JadxWrapper) — Java decompiler
- `mobsf.py` (MobsfWrapper) — REST client, MobsfIssue dataclass
- `s3scanner.py` (S3ScannerWrapper) — JSON parser, S3BucketFinding dataclass
- `awsbucketdump.py` (AwsBucketDumpWrapper) — text parser, BucketDumpResult dataclass

#### Integration Test (Task 72)

- `tests/integration/test_full_scan_mocked.py` — full 16-module orchestrator run with all wrappers mocked, all 4 reporters verified

---

## [0.1.0] — 2026-05-27

### Phase 1: Foundation

- Project scaffold (pyproject.toml, ruff, mypy, pytest, CI)
- Core models: Finding, CVSS v3.1 scorer, Severity
- Scope resolver with wildcard + exclude + forbidden-TLD support
- 3-layer YAML config loader with env-var interpolation
- Async SQLite FindingsStore
- ScanContext + output dir prep + scope.lock writer
- Logging setup (structlog + per-tool JSON invocation log)
- ToolWrapper ABC + subfinder + httpx wrappers
- PhaseModule ABC + ReconModule (vertical slice)
- Reporters: JSON, Markdown, HTML (Jinja2), per-finding folder
- Orchestrator
- CLI: scan / setup / doctor / update / report / import-results / list-profiles / list-modules
- `--dry-run` flag
- GitHub Actions CI (lint + type + test on Python 3.11 + 3.12)
- README skeleton
