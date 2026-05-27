# Pentora Implementation — Master Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. This master plan delegates to four phase plans; execute them in order.

**Goal:** Build Pentora v1.0 — single-command autonomous web app pentest orchestrator on Kali Linux with Burp/ZAP REST integration, pluggable LLM backends, and 11 importable report formats.

**Architecture:** Async-first Python CLI (Click + asyncio). Each phase = a self-contained module with uniform `run(context) -> List[Finding]` interface. Tool wrappers are isolated per external tool. Findings persisted to SQLite + per-finding folders. Reporters read from the store.

**Tech Stack:**
- Python 3.11+
- CLI: Click 8.x
- Async I/O: asyncio + aiohttp + httpx
- Browser automation: Playwright
- Persistence: aiosqlite + filesystem
- Templating: Jinja2
- Mocking: respx (HTTP), pytest-mock
- Testing: pytest + pytest-asyncio + pytest-cov
- Linting: ruff
- Type checking: mypy --strict
- Package: pyproject.toml (PEP 621)
- Docker: multi-stage Dockerfile
- CI: GitHub Actions

**Spec reference:** `docs/superpowers/specs/2026-05-27-pentora-design.md`

---

## Repository File Structure

```
pentora/
├── pyproject.toml
├── README.md
├── LICENSE                       # AGPLv3
├── CHANGELOG.md
├── install.sh                    # Kali one-line install
├── Dockerfile                    # Multi-stage build
├── docker-compose.yml            # For Ollama + MobSF dev stack
├── .gitignore
├── .github/workflows/
│   ├── ci.yml                    # lint + type + test on push
│   └── release.yml               # PyPI + Docker on tag
├── src/pentora/
│   ├── __init__.py               # version
│   ├── __main__.py               # python -m pentora
│   ├── cli.py                    # Click entry point + subcommands
│   ├── config.py                 # YAML config loader (3-layer)
│   ├── profile.py                # Profile system (dating/saas/...)
│   ├── scope.py                  # Scope resolver
│   ├── context.py                # ScanContext dataclass
│   ├── store.py                  # SQLite findings store
│   ├── finding.py                # Finding model + CVSS
│   ├── orchestrator.py           # Phase scheduling
│   ├── logging_setup.py          # structlog + tool invocation log
│   ├── notify.py                 # Discord/Slack/Telegram webhooks
│   ├── wrappers/                 # External tool wrappers
│   │   ├── base.py
│   │   ├── subfinder.py / amass.py / assetfinder.py / findomain.py
│   │   ├── naabu.py / nmap.py / httpx_tool.py
│   │   ├── katana.py / kiterunner.py / gau.py / waybackurls.py / hakrawler.py
│   │   ├── ffuf.py / feroxbuster.py / dirsearch.py
│   │   ├── arjun.py / paramspider.py / linkfinder.py / secretfinder.py
│   │   ├── nuclei.py / sqlmap.py / ghauri.py / nosqlmap.py
│   │   ├── dalfox.py / xsstrike.py / commix.py / tplmap.py / smuggler.py
│   │   ├── oralyzer.py / jwt_tool.py
│   │   ├── testssl.py / sslscan.py
│   │   ├── subzy.py / subjack.py
│   │   ├── gowitness.py / interactsh.py
│   │   ├── gitleaks.py / trufflehog.py
│   │   ├── wafw00f.py / whatweb.py / wappalyzer.py
│   │   ├── theharvester.py
│   │   ├── s3scanner.py / awsbucketdump.py
│   │   ├── mobsf.py / apktool.py / jadx.py
│   │   └── graphw00f.py / clairvoyance.py
│   ├── modules/                  # Phase modules (one per §5.x in spec)
│   │   ├── base.py               # PhaseModule ABC
│   │   ├── recon.py / discovery.py / auth.py / authz.py
│   │   ├── injection.py / upload.py / ssrf.py / logic.py
│   │   ├── disclosure.py / transport.py / headers.py / cors.py
│   │   ├── takeover.py / ratelimit.py / mobile.py / cloud.py
│   │   └── ai/                   # --ai-mode modules
│   │       ├── logic_fuzzer.py / waf_mutator.py
│   │       ├── report_polisher.py / pivot_advisor.py
│   │       └── auth_flow_reader.py
│   ├── llm/                      # LLM provider abstraction
│   │   ├── base.py               # LLMProvider Protocol
│   │   ├── ollama.py / openrouter.py / nvidia.py
│   │   ├── sanitizer.py          # PII stripping
│   │   └── prompts/              # Prompt templates per AI module
│   ├── proxy/                    # Burp + ZAP REST clients
│   │   ├── base.py / burp.py / zap.py
│   │   ├── cert_install.py       # Auto-install CA cert
│   │   └── extension_installer.py # Auto-fetch burp-rest-api.jar
│   ├── reporters/                # Output formats
│   │   ├── base.py / html.py / json_reporter.py / markdown.py
│   │   ├── sarif.py / csv_reporter.py
│   │   ├── defectdojo.py / faraday.py
│   │   ├── burp_xml.py / zap_xml.py / har.py
│   │   └── finding_folder.py     # Per-finding folder bundles
│   ├── templates/                # Jinja2 templates
│   │   ├── report.html / report.css
│   │   ├── finding.md.j2 / poc.sh.j2 / poc.py.j2
│   │   └── email_summary.html
│   ├── wordlists/                # Tiny baked-in defaults
│   │   ├── common-api.txt / common-dirs.txt
│   │   └── jwt-secrets-top1k.txt
│   ├── data/
│   │   ├── profiles/             # YAML profile definitions
│   │   │   ├── generic.yaml / dating.yaml / saas.yaml
│   │   │   ├── fintech.yaml / ecommerce.yaml
│   │   ├── fingerprints/         # Takeover service fingerprints
│   │   └── forbidden-domains.txt # .mil / .gov / hospital safe list
│   └── version.py
└── tests/
    ├── conftest.py
    ├── fixtures/                 # Frozen tool outputs for parser tests
    │   ├── subfinder/ amass/ nuclei/ sqlmap/ jwt_tool/ ...
    ├── unit/                     # All pure-Python tests
    ├── integration/              # With respx-mocked HTTP
    └── e2e/
        ├── juice_shop_compose.yml
        └── test_juice_shop.sh
```

---

## Phase Plan Index

Execute these phase plans **in order**. Each one is self-contained, ships working software, and has its own commit history.

| # | Plan | What it produces | Plan file |
|---|------|------------------|-----------|
| 1 | **Foundation** | Project scaffold + core framework + first reporters + end-to-end vertical slice (recon module against mock target produces HTML/JSON report) | `2026-05-27-pentora-phase-1-foundation.md` |
| 2 | **All security modules** | All 16 vulnerability/recon modules wired up with their tool wrappers | `2026-05-27-pentora-phase-2-modules.md` |
| 3 | **Integrations** | Burp REST + ZAP REST + LLM providers (Ollama/OpenRouter/NVIDIA) + AI-powered modules | `2026-05-27-pentora-phase-3-integrations.md` |
| 4 | **Release** | All remaining reporters + setup.sh + Dockerfile + PyPI/Docker CI + Juice Shop e2e test + README | `2026-05-27-pentora-phase-4-release.md` |

**Why 4 plans, not 1:** Each phase is independently testable and shippable. After Phase 1 you can already run `pentora <url>` and get an HTML report (recon-only). After Phase 2 you have all attack coverage. Phase 3 adds the proxy/AI flair. Phase 4 makes it publishable.

---

## Cross-Phase Conventions

These apply to every task in every phase plan:

### TDD discipline (RED → GREEN → REFACTOR → COMMIT)

For every code change:
1. **Write failing test first**
2. **Run test, see it fail** (proves the test exercises the new behavior)
3. **Write minimal code to pass**
4. **Run test, see it pass**
5. **Refactor if needed, re-run tests**
6. **Commit with conventional commit message** (`feat:`, `fix:`, `refactor:`, `test:`, `chore:`, `docs:`)

### File size discipline

- Hard cap: **400 lines per file** (excluding tests)
- If a file approaches 400 lines, split before adding more
- Tool wrappers: one file per tool, no exceptions

### Naming conventions

- Modules: `snake_case`
- Classes: `PascalCase`
- Tool wrappers: `Wrapper` suffix (`SubfinderWrapper`)
- Module classes: `Module` suffix (`ReconModule`)
- Test files: `test_<unit-under-test>.py`
- Test names: `test_<behavior>_<condition>` (e.g., `test_scope_resolver_blocks_out_of_scope_domain`)

### Type discipline

- All public functions have type annotations
- `mypy --strict` must pass on `src/pentora/`
- Use `Protocol` for swappable interfaces (LLM provider, Reporter, etc.)

### Commit cadence

Commit at every GREEN. Do not bundle multiple unrelated changes. Examples:

```
feat(scope): allow wildcard subdomain matching
test(scope): cover wildcard subdomain edge cases
refactor(orchestrator): extract phase scheduler into separate class
fix(reporter/html): escape angle brackets in finding descriptions
```

### Test pyramid targets

- **80%+ line coverage** on `src/pentora/`, enforced in CI
- **Unit:** every parser, every config code path, every reporter
- **Integration (mocked HTTP via respx):** every tool wrapper, every proxy client, every LLM provider
- **E2E (live):** one happy-path scan against locally-running OWASP Juice Shop (docker)

### Definition of "Done" for each phase

Phase is complete when:
1. All tasks in the phase plan are checked
2. `pytest` passes (all phases combined)
3. `ruff check .` passes
4. `mypy --strict src/pentora/` passes
5. Coverage ≥ 80% on touched files
6. CHANGELOG.md updated with the phase's changes
7. Tag pushed: `git tag pentora-phase-N-complete`

---

## Estimated Effort

| Phase | LOC | Tasks (approx) | Realistic hours of focused work |
|-------|-----|----------------|---------------------------------|
| 1 — Foundation | ~2,500 | 35 | 12–18 |
| 2 — All modules | ~5,000 | 80 | 30–40 |
| 3 — Integrations | ~2,000 | 25 | 10–15 |
| 4 — Release | ~1,500 | 20 | 6–10 |
| **Total** | **~11,000** | **~160** | **60–80 focused hours** |

These are conservative estimates. Realistically a competent Python engineer with the spec + plans does this over 2–3 weeks of solid work.

---

## Self-Review (Master Plan)

1. **Spec coverage:** All 16 module categories from §5 are mapped to phases 1–2. Burp/ZAP from §5.17 + §17 → phase 3. LLM §5.18 + §6 → phase 3. Output formats §9 → split across phases 1 (HTML/JSON/MD/finding-folder) and 4 (the rest). Setup §10 → phase 4. Testing §11 → cross-phase conventions. ✅
2. **Placeholder scan:** No "TBD" in this master plan. ✅
3. **Type consistency:** This is the overview — concrete types defined in phase plans. ✅
4. **Phase plans exist:** Will be written next, one file each.
