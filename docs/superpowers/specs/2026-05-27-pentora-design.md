# Pentora — Autonomous Web Application Pentest Orchestrator

**Date:** 2026-05-27
**Status:** Design — approved
**Author:** Drafted via brainstorming session
**Target release:** v1.0 (production-ready, publishable)
**License:** AGPLv3
**Distribution:** PyPI + GitHub release (one-line install.sh) + Docker image (ghcr.io)

---

## 1. Problem Statement

Web pentesters and bug bounty hunters today juggle 30–80 separate command-line tools (subfinder, amass, nuclei, sqlmap, ffuf, dalfox, jwt_tool, testssl.sh, MobSF, Burp Suite, etc.). A typical engagement against a single target involves:

- Manually chaining tool outputs through bash pipelines or notebooks
- Re-typing the same flags and config across tools
- Manually configuring Burp Suite proxy, scope, and active scanner
- Manually assembling findings into a client-grade report
- Repeating the entire dance for every new engagement

**Existing "all-in-one" tools** (Sn1per, reconftw, Osmedeus, Vajra) solve part of this but each has gaps: outdated UIs, no Burp REST API integration, weak exploitation phase, no opinionated profiles for common app categories (dating apps, SaaS, fintech), inconsistent report formats, no LLM-assisted modules.

**Pentora** is a single-binary CLI for Kali Linux that runs a full deterministic web-app pentest end-to-end from one command, integrates Burp Pro via REST API (with ZAP as a free fallback), produces client-grade importable reports, and offers an *optional* `--ai-mode` flag that engages a pluggable local or cloud LLM for the narrow set of tasks where reasoning genuinely beats rules.

## 2. Goals & Non-Goals

### Goals (v1.0)

- Single command: `pentora <url>` runs every phase end-to-end
- Zero LLM required for 90% of findings — fast, deterministic, reproducible
- Optional `--ai-mode` with 3 swappable LLM backends: **Ollama** (local), **OpenRouter** (cloud aggregator), **NVIDIA NIM** (cloud)
- Burp Suite Pro REST API integration: auto-configure proxy listener, auto-add scope, auto-start active scanner, pull issues into unified report
- ZAP REST API integration as drop-in free alternative
- Comprehensive coverage: all 10 phases from the OWASP WSTG + business logic + mobile (APK) + GraphQL + WebSocket + cloud-specific
- 11 importable output formats: HTML, JSON, Markdown, SARIF, Burp XML, ZAP XML, HAR, DefectDojo JSON, CSV summary, executable PoC scripts, raw HTTP request/response files + screenshots
- Cross-platform: Kali Linux primary, Windows-supported for the LLM-only modules
- Resume support, caching, scope file, rate limiting, profile system (dating-app / saas / fintech / ecommerce)
- One-line install on a fresh Kali via `setup.sh`
- Dry-run mode (`--dry-run`) for end-to-end validation without touching real targets

### Non-Goals (v1.0)

- Not an exploitation framework (we identify and prove, we don't post-exploit shells)
- Not for network-layer pentesting (no nmap NSE coverage beyond service detection)
- Not for Active Directory / internal corp testing
- Not a GUI tool (CLI + HTML report only — GUI is future v2 consideration)
- Not a SaaS / hosted service (runs entirely on the pentester's box)
- Not a vulnerability *intelligence* feed (we use existing nuclei templates + CVE DB)

## 3. Target Users

1. **Bug bounty hunters** — wants speed, wants single-command convenience, wants clean PoC artifacts ready to paste into HackerOne / Bugcrowd
2. **Independent pentesters** — needs reproducible reports for clients, needs Burp integration for chain-of-custody
3. **AppSec engineers** at companies — needs to scan internal staging environments on a schedule
4. **Security students / CTF players** — needs an opinionated tool that teaches what to check and where

## 4. High-Level Architecture

```
                            ┌────────────────────────────────┐
                            │   pentora <url> [flags]        │
                            │   (Click-based Python CLI)     │
                            └────────────────┬───────────────┘
                                             │
                                             ▼
                            ┌────────────────────────────────┐
                            │       Orchestrator Core        │
                            │  - Loads config + profile      │
                            │  - Resolves scope              │
                            │  - Schedules phases (parallel) │
                            │  - Maintains findings store    │
                            │  - Routes events to reporters  │
                            └────────────────┬───────────────┘
                                             │
        ┌────────────────────────────────────┼─────────────────────────────────┐
        │                                    │                                  │
        ▼                                    ▼                                  ▼
┌─────────────────┐              ┌─────────────────────┐              ┌────────────────────┐
│  Phase Modules  │              │  Proxy Integrations │              │  LLM Providers     │
│  (16 modules)   │              │  Burp REST / ZAP    │              │  (--ai-mode only)  │
└────────┬────────┘              └──────────┬──────────┘              └─────────┬──────────┘
         │                                  │                                    │
         ▼                                  ▼                                    ▼
┌─────────────────┐              ┌─────────────────────┐              ┌────────────────────┐
│  Tool Wrappers  │              │  HTTP Clients       │              │  Ollama / OR / NIM │
│  subfinder,     │              │  - aiohttp          │              │  - Function calls  │
│  nuclei, sqlmap,│              │  - httpx (async)    │              │  - RAG over        │
│  jwt_tool, etc. │              │  - browser via      │              │    HackTricks +    │
│                 │              │    Playwright       │              │    OWASP WSTG      │
└────────┬────────┘              └──────────┬──────────┘              └─────────┬──────────┘
         │                                  │                                    │
         └──────────────┬───────────────────┴────────────────────────────────────┘
                        │
                        ▼
              ┌──────────────────────┐
              │   Findings Store     │
              │   (SQLite + files)   │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Multi-Reporter     │
              │   HTML/JSON/SARIF/   │
              │   Burp/ZAP/HAR/...   │
              └──────────────────────┘
```

### Key design principles

1. **Async-first**: Heavy use of `asyncio` so 50+ tool invocations + HTTP probes run concurrently
2. **Each phase = a Python module with a uniform interface** (`run(context) -> List[Finding]`)
3. **Tool wrappers are isolated** — each external tool gets its own `wrapper.py` that handles install check, command construction, output parsing
4. **Findings store is the single source of truth** — every reporter reads from it
5. **No global state** — context is passed explicitly so tests are easy

## 5. Module Breakdown — Every Feature in v1.0

### 5.1 Recon (`pentora.modules.recon`)

| Sub-module | Tools wrapped | What it checks |
|------------|---------------|----------------|
| `subdomains` | subfinder, amass (passive), assetfinder, findomain, sublist3r | Subdomain enumeration via passive sources (crt.sh, securitytrails, virustotal, etc.) |
| `dns` | dnsx, puredns, dnsgen | DNS resolution, permutation, wildcard detection |
| `cert_transparency` | crt.sh, censys API, certspotter | Cert log mining for extra hostnames |
| `port_scan` | naabu, nmap (top-1000 + service detect) | Open ports + service version |
| `http_probe` | httpx, httprobe | Which subdomains have live HTTP/HTTPS |
| `fingerprint` | whatweb, wappalyzer-cli, webanalyze | Tech stack, framework, CMS, server |
| `waf_detect` | wafw00f | WAF identification |
| `screenshot` | gowitness | Visual map of attack surface |
| `wayback` | waybackurls, gau, gauplus, hakrawler | Historical URLs from Wayback Machine, common crawl, AlienVault OTX |
| `github_recon` | gitleaks, trufflehog (org-level if user provides GH org name) | Leaked secrets in public repos |
| `asn_lookup` | bgp.he.net API | ASN / IP-range enumeration |
| `email_harvest` | theHarvester | Public-domain email addresses (for credential stuffing context) |
| `shodan_censys` | Optional (user API keys) | Internet-wide host intel |

### 5.2 Content Discovery (`pentora.modules.discovery`)

| Sub-module | Tools | Checks |
|------------|-------|--------|
| `dir_brute` | ffuf, feroxbuster | Directory + file fuzzing with curated wordlists per profile |
| `param_discovery` | arjun, paramspider, x8 | Hidden GET/POST parameters |
| `js_secrets` | LinkFinder, SecretFinder, jsleaks | API endpoints + hardcoded keys inside JS bundles |
| `api_endpoints` | katana, kiterunner | Crawl + brute-force API routes |
| `swagger_probe` | Built-in | `/swagger.json`, `/openapi.yaml`, `/api/docs`, `/api/v*/docs` |
| `graphql_probe` | graphw00f, clairvoyance, in-house probe | `/graphql`, introspection, field suggestions |
| `backup_files` | Built-in | `.bak`, `.old`, `.swp`, `~`, `.DS_Store` |
| `vcs_exposure` | Built-in | `.git/config`, `.git/HEAD`, `.svn/entries`, `.hg/store` |
| `env_exposure` | Built-in | `.env`, `.env.production`, `.env.local`, `config.yml` |

### 5.3 Authentication (`pentora.modules.auth`)

| Sub-module | Tools | Checks |
|------------|-------|--------|
| `login_brute` | hydra (optional, with provided wordlists) | Rate limit + lockout detection on login endpoint |
| `enumeration` | Built-in timing analysis | Email/username enumeration via login + forgot-password |
| `otp_brute` | ffuf | 4/6-digit OTP brute force (with throttle + scope guard) |
| `jwt_attacks` | jwt_tool | `alg:none`, RS→HS confusion, weak HMAC secret brute, kid injection, JKU/X5U abuse, expiration validation |
| `oauth_flaws` | Built-in | State param missing/static, open redirect on redirect_uri, PKCE missing |
| `password_reset` | Built-in | Reset token entropy, expiry, re-use, host-header injection |
| `session_mgmt` | Built-in | Cookie flags (Secure/HttpOnly/SameSite), session fixation, logout invalidation |
| `mfa_bypass` | Built-in | Re-submit login w/o MFA, response tampering on `mfa_required` |

### 5.4 Authorization / IDOR (`pentora.modules.authz`)

| Sub-module | Tools | Checks |
|------------|-------|--------|
| `idor_numeric` | Built-in (requires 2 test accounts) | Iterate IDs ±1, ±10, ±100; diff responses |
| `idor_uuid` | Built-in | Try replacing UUIDs across accounts |
| `idor_base64` | Built-in | Decode IDs, try mutations |
| `bola` | Built-in (Autorize-style diff engine) | Per-endpoint response diff with B's token vs A's data |
| `bfla` | Built-in | Try admin-only endpoints (`/admin/*`, `/internal/*`) with low-priv token |
| `mass_assignment` | Built-in | Inject `role: admin`, `isPremium: true`, `id_verified: true` into PUT bodies |
| `vertical_escalation` | Built-in | Same as BFLA but with permission-name guessing (`*/promote`, `*/grant`) |

### 5.5 Injection (`pentora.modules.injection`)

| Sub-module | Tools | Checks |
|------------|-------|--------|
| `sqli` | sqlmap, ghauri | Auto-detect injection points from discovery phase, run sqlmap with `--batch --crawl=2 --forms` |
| `nosqli` | NoSQLMap | MongoDB-style injection (`$gt`, `$ne`, `$where`) |
| `xss` | dalfox, XSStrike | Reflected + stored + DOM via headless browser verification |
| `command_inj` | commix | OS command injection on identified params |
| `ssti` | tplmap | Server-side template injection ({{7*7}}, ${7*7}, #{7*7}) |
| `xxe` | Built-in payloads | XML external entity (only on XML endpoints detected during discovery) |
| `crlf` | Built-in | Header injection via `\r\n` in params |
| `host_header` | Built-in | Host header poisoning |
| `open_redirect` | oralyzer | Open redirect on `?next=`, `?redirect=`, `?url=` |
| `smuggling` | smuggler | HTTP request smuggling (CL.TE, TE.CL, TE.TE) |
| `ldap_inj` | Built-in payloads | LDAP injection on enterprise SSO surfaces |

### 5.6 File Upload (`pentora.modules.upload`)

- Extension bypass (`.php.jpg`, `.phtml`, `%00.php`, double-ext)
- Content-Type bypass
- Magic-byte polyglots
- SVG XSS (`<svg onload=alert(1)>`)
- ImageMagick CVE payloads (CVE-2016-3714 "imagetragick" + descendants)
- Path traversal in filename (`../../../etc/passwd`)
- Large-file DoS check (with explicit consent)

### 5.7 SSRF (`pentora.modules.ssrf`)

- Cloud metadata probes: AWS (`169.254.169.254`), GCP (`metadata.google.internal`), Azure (`169.254.169.254/metadata`), DigitalOcean
- Internal IP probing on identified URL-accepting params
- Out-of-band detection via **interactsh** (ProjectDiscovery) — auto-spun-up client, no setup needed
- DNS rebinding scaffold (generates rebind hostnames, user opts in to actively exploit)
- Webhook validation tests

### 5.8 Business Logic (`pentora.modules.logic`)

Rules-based v1.0 modules — `--ai-mode` enhances these with LLM-generated tests:

- **Race conditions** — turbo-intruder-style: same request 20× in parallel, look for inconsistent responses
- **Workflow skip** — try POSTing to step N+1 without doing step N
- **Negative quantities** — `quantity: -1`, `price: -100`, `amount: -50`
- **Integer overflow** — `quantity: 2147483647`, `amount: 9999999999999999`
- **Currency manipulation** — change `currency` field, change `price` field directly
- **Premium bypass** — toggle `isPremium`, `subscription`, `tier`, `plan` fields in request bodies
- **Coupon abuse** — apply same coupon N times
- **Profile/feature manipulation** — toggle visibility, verified flags

### 5.9 Information Disclosure (`pentora.modules.disclosure`)

- Stack trace triggering (malformed JSON, oversized payloads, weird unicode)
- Source map exposure (`.js.map` fetch + parse)
- API key extraction from JS (regex: AWS, Stripe, Twilio, SendGrid, Mapbox, Google, GitHub PAT, Slack)
- Internal IP leakage in responses
- Software version disclosure (headers: `Server`, `X-Powered-By`, `X-AspNet-Version`)
- Verbose error messages
- Hidden HTML comments

### 5.10 Transport Security (`pentora.modules.transport`)

| Tool | Checks |
|------|--------|
| `testssl.sh` | Full TLS/SSL audit: version, cipher suites, cert chain, vulnerabilities (Heartbleed, POODLE, CRIME, BEAST, BREACH, etc.) |
| `sslscan` | Backup/cross-check |
| Built-in | HSTS header + preload status |
| Built-in | Mixed content detection (HTTPS page loading HTTP) |

### 5.11 Security Headers (`pentora.modules.headers`)

- CSP analysis via Google's **csp-evaluator** algorithm (ported, no external API call)
- HSTS (max-age, includeSubDomains, preload)
- X-Frame-Options / CSP `frame-ancestors`
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- COEP, COOP, CORP (Cross-Origin Embedder/Opener/Resource Policy)
- Cookie flag audit (Secure, HttpOnly, SameSite, prefixed `__Secure-` / `__Host-`)

### 5.12 CORS (`pentora.modules.cors`)

- Wildcard `*` origin
- Reflected origin (`Origin: evil.com` → `Access-Control-Allow-Origin: evil.com`)
- Null origin
- Subdomain wildcard misconfig
- Credentials + wildcard combo

### 5.13 Subdomain Takeover (`pentora.modules.takeover`)

- Wrap **subzy** + **subjack** + in-house fingerprint matcher
- Check against 80+ services (GitHub Pages, AWS S3, Heroku, Shopify, Fastly, etc.)

### 5.14 Rate Limiting / DoS (`pentora.modules.ratelimit`)

- Login rate limit
- API rate limit (per-endpoint sampling)
- Password reset rate limit
- OTP request rate limit
- ReDoS detection on search/regex inputs (timing-based, controlled)
- Resource exhaustion test (with explicit `--allow-aggressive` flag, off by default)

### 5.15 Mobile (APK) Analysis (`pentora.modules.mobile`)

- Auto-download APK from Google Play (via `gplaycli` if package name provided)
- Decompile with **apktool** + **jadx**
- Run **MobSF** locally (Docker)
- Extract API endpoints, hardcoded secrets, deeplinks, exported components
- SSL pinning detection
- Insecure data storage flags
- Janus / StrandHogg vuln checks

### 5.16 Cloud-Specific (`pentora.modules.cloud`)

- S3 bucket enum via **s3scanner**, **awsbucketdump**
- Azure blob enum
- GCS bucket probing
- Firebase open-DB exposure
- Open Elasticsearch / MongoDB checks (on attack-surface IPs)
- AWS IAM credential validation (if creds found in JS)

### 5.17 Proxy Integrations (`pentora.modules.proxy`)

**Burp Suite Pro** (preferred when available):
- Detect Burp running (probe `http://127.0.0.1:1337/burp/versions`)
- If `burp-rest-api` extension not loaded, prompt user to install (auto-download `.jar`)
- Auto-add target to scope: `POST /burp/target/scope`
- Configure proxy listener: `POST /burp/configuration`
- Trigger active scan: `POST /burp/scanner/scans/active`
- Poll scan status, pull issues: `GET /burp/scanner/issues`
- Import results into Pentora's findings store with provenance tag `source: burp`
- Auto-install Burp CA cert in system trust store (`/usr/local/share/ca-certificates/burp.crt`)

**OWASP ZAP** (free fallback):
- Same flow via ZAP's `/JSON/...` REST endpoints
- Spider + active scan
- Pull alerts

User picks at runtime: `--proxy burp` or `--proxy zap` (auto-detects which is running if not specified).

### 5.18 LLM-Powered Modules (`pentora.modules.ai`) — enabled only with `--ai-mode`

| Module | What the LLM actually does | Why a rule can't |
|--------|----------------------------|------------------|
| `logic_fuzzer` | Given app type + observed endpoints + HTML samples, generates business-logic test cases | Requires reading the app's purpose |
| `waf_mutator` | When stock payloads return 403/406, mutates them (Unicode normalization, comment injection, double-encoding) | Combinatorial space too large for rules |
| `report_polisher` | Rewrites raw finding JSON into polished prose section for client report | Templates always sound robotic |
| `pivot_advisor` | When tool finds unexpected artifact (e.g., admin panel), suggests next 3 attack steps | Open-ended reasoning |
| `auth_flow_reader` | Reads login page HTML + JS, identifies multi-step auth flow | HTML parsing rules cover 60% of cases; LLM closes the gap |

## 6. LLM Provider Abstraction

Pluggable provider interface:

```python
class LLMProvider(Protocol):
    name: str
    async def chat(self, messages: list[Message], tools: list[Tool] | None = None) -> Response: ...

# Concrete providers:
class OllamaProvider(LLMProvider): ...        # localhost:11434
class OpenRouterProvider(LLMProvider): ...    # api.openrouter.ai
class NvidiaNIMProvider(LLMProvider): ...     # integrate.api.nvidia.com
```

**Selection at runtime:**
```bash
pentora <url> --ai-mode \
  --llm-provider ollama \
  --llm-model qwen2.5-coder:7b

pentora <url> --ai-mode \
  --llm-provider openrouter \
  --llm-model anthropic/claude-3.5-sonnet

pentora <url> --ai-mode \
  --llm-provider nvidia \
  --llm-model meta/llama-3.1-70b-instruct
```

**API keys** read from env vars: `OPENROUTER_API_KEY`, `NVIDIA_API_KEY`. Ollama needs no key.

**No default provider.** When `--ai-mode` is on, `--llm-provider` is required. This is intentional — a pentester must consciously decide where each scan's data goes. The previous choice is remembered in `~/.pentora/last-llm.yaml` so the user can re-use it next run with `--llm-provider last`, but there is no global default that could leak data silently.

**Privacy guardrail:** When AI mode is on, Pentora sanitizes outbound prompts by default — strips hostnames, real user IDs, API responses with PII. User can disable with `--no-sanitize-llm`.

## 7. CLI Design

### Primary command

```bash
pentora <url>                           # runs default profile, all phases
```

### Common flags

```bash
--profile dating|saas|fintech|ecommerce|generic   # tunes wordlists + business-logic tests
--scope-file scope.txt                            # in/out of scope domains + paths
--token-a "Bearer ...."                            # first test account auth token
--token-b "Bearer ...."                            # second test account auth token (enables IDOR)
--rate-limit 10                                   # req/sec ceiling (default 10)
--threads 50                                      # concurrent tool workers (default 50)
--output ./reports/pure-app-2026-05-27/           # report destination
--resume                                          # resume an interrupted scan
--dry-run                                         # print what would run, exit 0
--cache-recon 7d                                  # reuse recon results younger than X
--proxy burp|zap|none                             # default: auto-detect
--ai-mode                                         # enable LLM modules
--llm-provider ollama|openrouter|nvidia
--llm-model <model-id>
--no-sanitize-llm                                 # disable PII stripping in LLM prompts
--allow-aggressive                                # opt-in to DoS-adjacent tests
--phases recon,auth,injection                     # run a subset of phases
--exclude-phases mobile,cloud                     # skip phases
--notify discord|slack|telegram:<webhook-url>     # ping on completion / on critical finding
--compare ./reports/pure-app-2026-04-01/          # diff against previous scan
```

### Subcommands

```bash
pentora setup                  # install all tools (Kali)
pentora doctor                 # diagnose missing tools, missing API keys
pentora update                 # update nuclei templates, wordlists, fingerprints
pentora report ./findings.db   # regenerate reports from an existing findings DB
pentora import burp ./out.xml  # ingest Burp scan into Pentora findings store
pentora list-profiles
pentora list-modules
```

## 8. Configuration System

**Three layers (later wins):**

1. **Built-in defaults** (shipped in package)
2. **User config** at `~/.pentora/config.yaml`
3. **CLI flags**

`~/.pentora/config.yaml` example:

```yaml
profiles:
  dating:
    extra_business_logic_tests:
      - match_without_consent
      - location_spoofing
      - private_photo_access_without_match
    wordlists:
      api_endpoints: ~/.pentora/wordlists/dating-api-endpoints.txt

api_keys:
  shodan: $SHODAN_API_KEY
  censys: $CENSYS_API_KEY
  github: $GITHUB_TOKEN
  openrouter: $OPENROUTER_API_KEY
  nvidia: $NVIDIA_API_KEY

defaults:
  rate_limit: 10
  threads: 50
  proxy: auto
  llm_provider: ollama
  llm_model: qwen2.5-coder:7b
```

## 9. Output Formats — All Importable

Every report directory is laid out identically:

```
reports/pure-app-2026-05-27_143012/
├── summary.html                  # rich HTML report (open in browser)
├── summary.md                    # markdown for editing
├── summary.json                  # everything machine-readable
├── findings.sarif                # GitHub / VSCode-compatible
├── findings.csv                  # spreadsheet summary
├── findings.defectdojo.json      # import into DefectDojo
├── findings.faraday.json         # import into Faraday
├── burp-export.xml               # importable into Burp Pro (Target > Site map > Import)
├── zap-export.xml                # importable into OWASP ZAP
├── traffic.har                   # full HTTP archive (open in DevTools / Burp)
├── findings/
│   ├── 2026-05-27_143055_idor_user_profile/
│   │   ├── finding.json          # structured data
│   │   ├── finding.md            # human-readable writeup
│   │   ├── request.http          # raw HTTP request (replay in Burp Repeater)
│   │   ├── response.http         # raw HTTP response
│   │   ├── poc.sh                # executable bash PoC
│   │   ├── poc.py                # executable python PoC
│   │   ├── screenshot.png        # visual proof
│   │   └── curl.txt              # one-line curl reproducer
│   └── ... (one folder per finding)
├── recon/
│   ├── subdomains.txt
│   ├── live-hosts.txt
│   ├── ports.json
│   ├── tech-stack.json
│   ├── screenshots/
│   └── wayback-urls.txt
├── logs/
│   ├── pentora.log               # tool's own log
│   ├── tool-invocations/         # exact commands + stdout/stderr for every tool run
│   └── transcript.json           # event log of the whole scan
└── scope.lock                    # exact scope used for this run (for audit)
```

**Why per-finding folder layout:** When you submit to HackerOne / a client report, you grab one folder and you have request, response, PoC, screenshot, all in one place. No assembly needed.

## 10. Setup & Installation

### One-line install on Kali

```bash
curl -fsSL https://raw.githubusercontent.com/<user>/pentora/main/install.sh | bash
```

`install.sh` will:
1. Verify Kali (or Debian-derivative)
2. `apt install` system dependencies (`build-essential`, `python3-pip`, `golang`, `docker`)
3. `go install` Go-based tools: subfinder, amass, nuclei, naabu, httpx, katana, ffuf, gau, gowitness, interactsh, dalfox, subzy, etc.
4. `pip install` Python-based tools: arjun, paramspider, jwt_tool, sqlmap (Kali has built-in), commix, xsstrike, dirsearch, mobsf-cli, NoSQLMap
5. Clone GitHub-only tools to `~/.pentora/tools/`: LinkFinder, SecretFinder, smuggler
6. Download nuclei-templates + commonspeak wordlists + SecLists subset to `~/.pentora/wordlists/`
7. Install Pentora itself via `pip install -e .`
8. Run `pentora doctor` to verify everything

**Optional steps (interactive prompts):**
- Install + start Ollama? Pull `qwen2.5-coder:7b`?
- Install Burp Pro REST API extension (`burp-rest-api.jar`)?
- Install ZAP daemon?
- Install Docker + pull MobSF image?

### Distribution methods

1. **PyPI**: `pip install pentora` — Python tooling auto-installs, user runs `pentora setup` for the rest
2. **GitHub release** — full installer
3. **Docker image** — `docker run -v $PWD:/out ghcr.io/<user>/pentora:v1 <url>` — works on Windows/Mac, all tools pre-baked
4. **Kali package** (stretch goal — `apt install pentora` via Kali community repo)

## 11. Testing Strategy

| Layer | What's tested | How |
|-------|---------------|-----|
| **Unit** | Parsers (subfinder output, nuclei JSON, sqlmap, jwt_tool, etc.), scorers (CVSS calc), config loader, scope resolver | pytest, no network |
| **Module logic** | Each phase module's decision tree | pytest with mocked tool wrappers |
| **Tool wrappers** | Command construction, output parsing | pytest with frozen fixture outputs |
| **Reporters** | All 11 output formats render correctly from a fixture findings DB | pytest snapshot tests |
| **LLM providers** | Each provider correctly formats requests, parses responses | pytest with `respx` mocks (no real API calls) |
| **Burp REST client** | All API calls + parsing | pytest with `respx` mock of Burp REST API |
| **ZAP REST client** | Same | pytest with respx mock |
| **CLI** | Every flag combination | pytest + Click's `CliRunner` |
| **End-to-end (dry-run)** | `pentora --dry-run <url>` exits 0 and emits a plausible plan | pytest |
| **End-to-end (live)** | Against **OWASP Juice Shop** running locally in Docker | shell-script integration test |
| **End-to-end (live, harder)** | Against **DVWA**, **WebGoat**, **PortSwigger labs** | manual run with documented checklist |

**Coverage target:** 80% line coverage on `pentora/` package, enforced in CI.

## 12. Security & Legal

- Bold warning on first run: "Only use against systems you own or have written authorization to test."
- Refuse to scan a curated list of forbidden domains (military, government TLDs, hospitals) — overridable with `--i-know-what-im-doing`
- Scope file is **enforced** — every HTTP request goes through scope resolver; out-of-scope = skipped + logged
- Rate limit defaults are conservative (10 req/s) — `--allow-aggressive` is opt-in
- All operations are logged to `pentora.log` with timestamps for legal / chain-of-custody

## 13. Roadmap

| Version | What's in |
|---------|-----------|
| **v1.0** (this spec) | Everything above |
| v1.1 | GUI dashboard (FastAPI + HTMX), scheduled scans, multi-tenant report storage |
| v1.2 | Plugin SDK for community modules |
| v1.3 | Cloud-native: scan from Pentora SaaS API (still self-hostable) |
| v2.0 | Active exploitation modules (with strict opt-in), C2-lite integration |

## 14. References — Tools We Aggregate

### Recon
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [amass](https://github.com/owasp-amass/amass)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [findomain](https://github.com/Findomain/Findomain)
- [sublist3r](https://github.com/aboul3la/Sublist3r)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [puredns](https://github.com/d3mondev/puredns)
- [naabu](https://github.com/projectdiscovery/naabu)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [gowitness](https://github.com/sensepost/gowitness)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gau](https://github.com/lc/gau)
- [hakrawler](https://github.com/hakluke/hakrawler)
- [whatweb](https://github.com/urbanadventurer/WhatWeb)
- [wafw00f](https://github.com/EnableSecurity/wafw00f)
- [theHarvester](https://github.com/laramies/theHarvester)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)

### Content Discovery
- [ffuf](https://github.com/ffuf/ffuf)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [dirsearch](https://github.com/maurosoria/dirsearch)
- [arjun](https://github.com/s0md3v/Arjun)
- [paramspider](https://github.com/devanshbatham/paramspider)
- [x8](https://github.com/Sh1Yo/x8)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [SecretFinder](https://github.com/m4ll0k/SecretFinder)
- [kiterunner](https://github.com/assetnote/kiterunner)
- [graphw00f](https://github.com/dolevf/graphw00f)
- [clairvoyance](https://github.com/nikitastupin/clairvoyance)

### Vulnerability Scanning
- [nuclei](https://github.com/projectdiscovery/nuclei) + [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [ghauri](https://github.com/r0oth3x49/ghauri)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [dalfox](https://github.com/hahwul/dalfox)
- [XSStrike](https://github.com/s0md3v/XSStrike)
- [commix](https://github.com/commixproject/commix)
- [tplmap](https://github.com/epinna/tplmap)
- [oralyzer](https://github.com/r0075h3ll/Oralyzer)
- [smuggler](https://github.com/defparam/smuggler)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [interactsh](https://github.com/projectdiscovery/interactsh)
- [subzy](https://github.com/PentestPad/subzy)
- [subjack](https://github.com/haccer/subjack)

### TLS / Headers / CORS
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [sslscan](https://github.com/rbsec/sslscan)
- [csp-evaluator](https://github.com/google/csp-evaluator) (algorithm ported)
- [corsy](https://github.com/s0md3v/Corsy)

### Cloud
- [s3scanner](https://github.com/sa7mon/S3Scanner)
- [awsbucketdump](https://github.com/jordanpotti/AWSBucketDump)
- [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)

### Mobile
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [apktool](https://github.com/iBotPeaches/Apktool)
- [jadx](https://github.com/skylot/jadx)

### Proxies
- [burp-rest-api](https://github.com/vmware-archive/burp-rest-api) (Burp Pro extension)
- [OWASP ZAP](https://github.com/zaproxy/zaproxy)

### Existing "all-in-one" tools we learn from (and improve on)
- [Sn1per](https://github.com/1N3/Sn1per)
- [reconftw](https://github.com/six2dez/reconftw)
- [Osmedeus](https://github.com/j3ssie/osmedeus)
- [Vajra](https://github.com/r3curs1v3-pr0xy/vajra)
- [Nettacker (OWASP)](https://github.com/OWASP/Nettacker)
- [Sudomy](https://github.com/screetsec/Sudomy)
- [bbot](https://github.com/blacklanternsecurity/bbot)

### Knowledge sources for `--ai-mode` RAG
- [OWASP WSTG](https://github.com/OWASP/wstg)
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP API Security Top 10](https://github.com/OWASP/API-Security)

---

## 15. Locked Decisions

1. ✅ Tool name: **Pentora**
2. ✅ LLM default: **None** — `--llm-provider` is required when `--ai-mode` is on. Last choice cached at `~/.pentora/last-llm.yaml`, recallable via `--llm-provider last`.
3. ✅ License: **AGPLv3**
4. ✅ Distribution: **PyPI + GitHub release (install.sh) + Docker image (ghcr.io)** — all three at v1.0 launch.

## 16. Delivery Notes

Building all of §5 + §6 + §7 + §9 + §10 in a single chat session is not realistic — this is a 10–15kLOC codebase. The implementation plan (next step) will break this into 30–50 ordered sub-tasks, each verifiable on its own. Some sub-tasks will be executed live in this session; the larger ones will produce complete files that you commit and verify on your Kali box. Every module ships with unit tests covering parsers, scorers, and reporters. End-to-end validation happens against OWASP Juice Shop / DVWA before you point Pentora at a paying client.
