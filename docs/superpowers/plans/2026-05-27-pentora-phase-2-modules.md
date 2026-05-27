# Pentora Phase 2 — All Security Modules

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Each task group below corresponds to one of the 15 security modules from spec §5.2–§5.16. Tasks follow Phase 1's TDD pattern: write failing test → run → implement → run → commit.

**Pre-requisite:** Phase 1 (foundation) complete. Tag `pentora-phase-1-complete` exists.

**Goal:** Implement every security module from spec §5.2 through §5.16. By the end of Phase 2, `pentora scan https://target.com --phases all` runs all 16 phases (incl. Phase 1's recon) and emits comprehensive findings.

**Architecture conventions (carried from Phase 1):**
- TDD: failing test → implement → passing test → commit
- One tool wrapper per file (mirrors Phase 1's `subfinder.py`, `httpx_tool.py`)
- One phase module per file
- All wrappers extend `ToolWrapper` (see Phase 1 Task 9)
- All modules extend `PhaseModule` (see Phase 1 Task 12)
- File size cap: 400 lines (excluding tests)

**Tool wrapper pattern (template — used for every tool in this phase):**

```python
"""<TOOL> — <one-line description>."""
from __future__ import annotations
from dataclasses import dataclass
from pentora.wrappers.base import ToolWrapper


@dataclass
class <Tool>Result:
    # fields parsed from tool output
    ...


class <Tool>Wrapper(ToolWrapper):
    tool_name = "<binary-name>"
    install_check_argv = ["<binary-name>", "-version"]

    def build_argv(self, *args, **kwargs):
        return [self.tool_name, ...]

    def parse(self, stdout, stderr, returncode):
        # parse stdout into list of <Tool>Result
        ...
```

**Module pattern (template):**

```python
"""<Module> — <one-line description>."""
from __future__ import annotations
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule


class <Name>Module(PhaseModule):
    name = "<phase-key>"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        # 1. gather inputs (from prior phase outputs in ctx.output_dir/recon/*)
        # 2. invoke wrappers
        # 3. emit findings
        return findings
```

---

## Module Group 1 — Content Discovery (`pentora.modules.discovery`)

Spec ref: §5.2

### Tasks 24–30: Tool wrappers

For each tool below, follow Phase 1 Task 10 pattern (write fixture → test parser → test argv → write wrapper → commit). Each wrapper is ~50 LOC.

- [ ] **Task 24:** `wrappers/ffuf.py` — parses ffuf `-of json` output → list of `FfufHit(url, status, length)`
- [ ] **Task 25:** `wrappers/arjun.py` — parses Arjun JSON → list of `ArjunParam(endpoint, name, method)`
- [ ] **Task 26:** `wrappers/paramspider.py` — parses ParamSpider txt output
- [ ] **Task 27:** `wrappers/linkfinder.py` — runs LinkFinder via `python3 LinkFinder.py -i URL -o cli` and parses
- [ ] **Task 28:** `wrappers/secretfinder.py` — parses SecretFinder output → list of `Secret(type, value, file_url)`
- [ ] **Task 29:** `wrappers/katana.py` — parses katana JSONL → list of crawled URLs
- [ ] **Task 30:** `wrappers/graphw00f.py` — parses graphw00f fingerprint output

### Task 31: Built-in probes (swagger, graphql, backup/.git/.env)

**Files:**
- Create: `src/pentora/modules/discovery_probes.py`
- Create: `tests/unit/test_discovery_probes.py`

Probes to implement (each one tested with respx mocks):

```python
SWAGGER_PATHS = ["/swagger.json", "/openapi.yaml", "/openapi.json", "/api/docs",
                 "/api-docs", "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
BACKUP_PATTERNS = [".bak", ".old", ".swp", "~", ".save", ".orig"]
VCS_PATHS = ["/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/store/00manifest.i"]
ENV_PATHS = ["/.env", "/.env.local", "/.env.production", "/.env.development"]
```

Each returns a `DiscoveryHit(url, kind, evidence)` dataclass. Status codes 200/401/403/206 = hit; 404/0 = miss.

### Task 32: DiscoveryModule

**Files:**
- Create: `src/pentora/modules/discovery.py`
- Create: `tests/unit/test_discovery_module.py`

The module:
1. Reads live hosts from `ctx.output_dir/recon/live-hosts.txt` (written by ReconModule — extend ReconModule to write this file as part of Task 32)
2. For each live host, runs ffuf with `wordlists/common-dirs.txt`, arjun (param discovery), katana (crawler), and the built-in probes
3. Emits findings for swagger exposure (Medium, info disclosure), graphql introspection enabled (Medium), VCS exposure (High), env file exposure (Critical)

CVSS examples:
- `.env` exposed: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (score 7.5)
- `.git/config` exposed: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (score 7.5)
- Swagger publicly accessible: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (score 5.3)
- GraphQL introspection enabled: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (score 5.3)

### Task 33: Wire DiscoveryModule into CLI phase_map

Add `"discovery": DiscoveryModule` to `phase_map` in `cli.py`. Update `--phases all` resolution to include it. Update test in `test_cli_scan_integration.py` to assert `--phases discovery` works with mocked wrappers.

Commit: `feat(discovery): add discovery module covering dirs/params/swagger/graphql/vcs/env`

---

## Module Group 2 — Authentication (`pentora.modules.auth`)

Spec ref: §5.3

### Tasks 34–37: Tool wrappers

- [ ] **Task 34:** `wrappers/jwt_tool.py` — wraps `jwt_tool.py`, supports modes `--alg-none`, `--brute-secret`, `--kid-injection`. Parses output → list of `JwtAttackResult(attack, vulnerable, evidence)`.
- [ ] **Task 35:** `wrappers/hydra.py` — wraps hydra for login brute. Optional, only invoked with explicit `--allow-brute` flag.
- [ ] **Task 36:** Helper module `pentora.auth.timing_oracle` — sends N requests measuring response time delta. Used for username-enumeration via timing.
- [ ] **Task 37:** Helper `pentora.auth.otp_brute` — async fuzzer for 4/6-digit OTPs against an endpoint, with throttle.

### Task 38: AuthModule

**Files:**
- Create: `src/pentora/modules/auth.py`
- Create: `tests/unit/test_auth_module.py`

Sub-checks:

1. **Rate-limit detection** — fire N=20 wrong passwords; if all return 401 without 429, log a finding "No rate limit on login" (High).
2. **Account enumeration** — POST to login with `existing@test.com` (assumed to exist) and `nonexistent@x.y.z.invalid`; if response time differs by >200ms consistently, log "Username enumeration via timing" (Medium).
3. **OTP brute** — only if `--allow-brute` AND ctx.config marks OTP endpoint discovered. Use otp_brute helper.
4. **JWT analysis** — if any cookie or Authorization header contains JWT, run jwt_tool for `--alg-none`, `--brute-secret`, `--kid-injection`. Any successful attack = Critical finding.
5. **Password reset** — POST `/forgot-password` with target email twice in quick succession; check if same token issued (Medium if so).
6. **Session management** — login, then logout, then retry original token. If token still works, log "Logout does not invalidate token server-side" (High).
7. **Cookie flags audit** — fetch any Set-Cookie; check Secure/HttpOnly/SameSite. Missing flag = Low.

Commit each sub-check separately following TDD pattern.

---

## Module Group 3 — Authorization / IDOR (`pentora.modules.authz`)

Spec ref: §5.4

### Task 39: AuthzModule with Autorize-style diff engine

**Files:**
- Create: `src/pentora/modules/authz.py`
- Create: `src/pentora/authz/diff_engine.py`
- Create: `tests/unit/test_diff_engine.py`
- Create: `tests/unit/test_authz_module.py`

**Pre-requisite:** Both `--token-a` and `--token-b` must be provided. If only one, AuthzModule logs a warning and returns `[]`.

**Diff engine** (`diff_engine.py`):

```python
@dataclass
class DiffResult:
    similar: bool       # bodies "essentially identical"
    ratio: float        # 0.0-1.0
    diff: str           # unified diff for report

def compare_responses(resp_a: str, resp_b: str) -> DiffResult: ...
```

Uses `difflib.SequenceMatcher` ratio. Threshold: >0.85 ratio = "similar" (likely same data returned to both users = IDOR).

**Module logic:**

1. Crawl endpoints from `ctx.output_dir/recon/wayback-urls.txt` + katana output
2. Filter to endpoints containing numeric IDs, UUIDs, or base64-looking strings
3. For each candidate endpoint:
   - Issue request with token A → record response A
   - Replace the ID with B's known ID → issue with token A → record response A'
   - Issue same A' request with token B → record response B'
   - Compare: if A' similar to B' (B's data leaked through A's auth), emit Critical finding
4. Test BFLA: try `/admin/*` paths with token A → if 200 returned, Critical
5. Test mass-assignment: PUT to `/me` with extra fields `{"role": "admin", "isPremium": true, "id_verified": true}` → if 200 + GET reflects change, Critical

CVSS for IDOR returning PII: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (score 6.5).
CVSS for BFLA admin access: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` (score 9.0).

---

## Module Group 4 — Injection (`pentora.modules.injection`)

Spec ref: §5.5

### Tasks 40–47: Tool wrappers

- [ ] **Task 40:** `wrappers/sqlmap.py` — invokes `sqlmap -r request.txt --batch --crawl=2 --level=3 --risk=2`. Parses output for "[INFO] the back-end DBMS is" and "[CRITICAL]". Returns list of `SqlmapFinding(parameter, dbms, technique, evidence)`.
- [ ] **Task 41:** `wrappers/ghauri.py` — similar to sqlmap, Ghauri's output format.
- [ ] **Task 42:** `wrappers/dalfox.py` — invokes `dalfox url URL --silence --output-format json`. Parses → list of `DalfoxHit(param, payload, type, severity)`.
- [ ] **Task 43:** `wrappers/xsstrike.py` — wraps XSStrike for stored XSS scenarios.
- [ ] **Task 44:** `wrappers/commix.py` — wraps commix for OS command injection.
- [ ] **Task 45:** `wrappers/tplmap.py` — SSTI detection.
- [ ] **Task 46:** `wrappers/smuggler.py` — HTTP request smuggling.
- [ ] **Task 47:** `wrappers/oralyzer.py` — open redirect.

### Task 48: InjectionModule

**Files:**
- Create: `src/pentora/modules/injection.py`
- Create: `tests/unit/test_injection_module.py`

For each candidate endpoint (from discovery phase output), prioritize wrappers based on detected tech:
- HTML form / `?q=` / `?search=` → dalfox, xsstrike, commix
- Numeric param `?id=42` → sqlmap, ghauri
- Body with `{{...}}` reflected → tplmap
- `?next=`, `?redirect=`, `?url=` → oralyzer

NoSQLi check via built-in payloads (no separate wrapper): inject `{"$gt": ""}` into JSON bodies, detect auth bypass.

Each successful injection → Critical or High finding with raw request/response saved.

---

## Module Group 5 — File Upload (`pentora.modules.upload`)

Spec ref: §5.6

### Task 49: UploadModule (built-in payloads)

**Files:**
- Create: `src/pentora/modules/upload.py`
- Create: `src/pentora/data/upload_payloads/` (php, jsp, html, svg, polyglot.gif)
- Create: `tests/unit/test_upload_module.py`

1. Identify upload endpoints from discovery (forms with `<input type="file">`, multipart POST endpoints)
2. For each, attempt:
   - Naive `.php` upload → if 200, Critical
   - `.php.jpg` → check stored URL → if reachable AND executed (response is HTML rendered by PHP), Critical
   - `.svg` with `<svg onload=alert(1)>` → if stored AND viewable, High (stored XSS)
   - `polyglot.gif` (GIF89a + ImageMagick exploit) → log even on accept
   - Filename `../../../etc/passwd.jpg` → if filename used in storage path, may write outside upload dir

---

## Module Group 6 — SSRF (`pentora.modules.ssrf`)

Spec ref: §5.7

### Tasks 50–51

- [ ] **Task 50:** `wrappers/interactsh.py` — wraps `interactsh-client` for OOB detection. Spawns interactsh-client, captures generated subdomain, polls for interactions.
- [ ] **Task 51:** `src/pentora/modules/ssrf.py` + tests

SsrfModule scans for URL-accepting parameters (`?url=`, `?callback=`, `?webhook=`, `?image_url=`, `?redirect=`, etc.) from discovery output. For each:

1. Inject `http://169.254.169.254/latest/meta-data/` (AWS metadata) — Critical if 200 + token text returned
2. Inject `http://metadata.google.internal/` — same
3. Inject `http://127.0.0.1:22` / `http://127.0.0.1:6379` (Redis) → High if response differs from external
4. Inject `http://<interactsh-token>.oast.fun/` — High if interactsh receives DNS or HTTP request (proves OOB SSRF)

---

## Module Group 7 — Business Logic (`pentora.modules.logic`)

Spec ref: §5.8

### Task 52: LogicModule (rules-based; AI mode enhances in Phase 3)

**Files:**
- Create: `src/pentora/modules/logic.py`
- Create: `tests/unit/test_logic_module.py`

Sub-tests:

1. **Race condition** — `asyncio.gather` 30 identical requests to e.g. coupon-redeem endpoint; check for inconsistency
2. **Workflow skip** — POST directly to `/checkout/confirm` without `/checkout/start` step
3. **Negative quantities** — modify quantity/price/amount fields to `-1`, `-100`
4. **Integer overflow** — `2147483647`, `9999999999999999`
5. **Currency** — change `"USD"` to `"EUR"` keeping amount
6. **Premium bypass** — toggle `isPremium`, `subscription`, `tier`, `plan`, `is_verified` in request bodies
7. **Coupon reuse** — apply same coupon code N times

Per-profile customization: if `profile=dating`, add tests for `match_without_consent`, `location_spoofing`, `private_photo_access_without_match`.

---

## Module Group 8 — Information Disclosure (`pentora.modules.disclosure`)

Spec ref: §5.9

### Task 53: DisclosureModule

**Files:**
- Create: `src/pentora/modules/disclosure.py`
- Create: `src/pentora/data/secret_patterns.yaml` (regex library)
- Create: `tests/unit/test_disclosure_module.py`

`secret_patterns.yaml`:

```yaml
- name: AWS Access Key ID
  pattern: 'AKIA[0-9A-Z]{16}'
  severity: HIGH
- name: AWS Secret Access Key
  pattern: '(?i)aws.{0,20}?(?:secret|private).{0,20}?[''"]([0-9a-zA-Z/+]{40})[''"]'
  severity: CRITICAL
- name: Stripe Live Secret
  pattern: 'sk_LIVE_STRIPE_PREFIX_[0-9a-zA-Z]{24,}'
  severity: CRITICAL
- name: Stripe Test Secret
  pattern: 'sk_TEST_STRIPE_PREFIX_[0-9a-zA-Z]{24,}'
  severity: MEDIUM
- name: GitHub PAT
  pattern: 'ghp_[A-Za-z0-9]{36}'
  severity: HIGH
- name: GitHub fine-grained PAT
  pattern: 'github_pat_[A-Za-z0-9_]{82}'
  severity: HIGH
- name: Slack Bot Token
  pattern: 'xox[baprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+'
  severity: HIGH
- name: Google API Key
  pattern: 'AIza[0-9A-Za-z\\-_]{35}'
  severity: MEDIUM
- name: Twilio Account SID
  pattern: 'AC[0-9a-fA-F]{32}'
  severity: MEDIUM
- name: SendGrid API Key
  pattern: 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}'
  severity: HIGH
- name: Mapbox Token
  pattern: 'pk\\.eyJ[A-Za-z0-9_-]{20,}'
  severity: LOW
- name: JWT
  pattern: 'eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}'
  severity: LOW   # informational — needs further analysis
- name: Private SSH Key
  pattern: '-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
  severity: CRITICAL
- name: Generic API Key context
  pattern: '(?i)(?:api[_-]?key|apikey|secret)[\s:=]+[''"]([A-Za-z0-9_\-]{20,})[''"]'
  severity: MEDIUM
```

Module fetches each JS file collected during discovery (from LinkFinder, katana), runs every regex, emits one finding per match (deduplicated by id).

Other disclosure checks:
- **Source maps**: GET `.js.map` for each JS — if 200, log finding (Medium) with original source path leakage example
- **Stack trace trigger**: POST malformed JSON (e.g., `{"a":}`) to detected API endpoints; check response for `Traceback`, `at ` lines, `Stack:`, `Exception:` → Medium finding
- **Verbose error**: payload `{"a": -1, "b": null}` to varied endpoints; look for SQL errors, ORM errors → High if SQL error leaks query
- **HTML comments**: parse all crawled HTML, regex `<!--[\s\S]*?-->`. Filter out short ones, but flag comments containing `TODO`, `FIXME`, `XXX`, `password`, `internal`, `staging`

---

## Module Group 9 — Transport Security (`pentora.modules.transport`)

Spec ref: §5.10

### Tasks 54–55

- [ ] **Task 54:** `wrappers/testssl.py` — invokes `testssl.sh --jsonfile out.json URL`. Parses JSON → list of `TlsIssue(id, severity, finding, cve)`. testssl.sh exit codes and JSON format are stable; map severities directly.
- [ ] **Task 55:** `wrappers/sslscan.py` — backup cross-check, parses XML output.

### Task 56: TransportModule

For the target + each live host:
1. Run testssl.sh → emit one finding per `MEDIUM`+ issue from testssl
2. Check HSTS header presence + parameters (max-age, includeSubDomains, preload) → Medium if missing or weak
3. Mixed content detection: fetch HTML, look for `http://` resource URLs → Medium

---

## Module Group 10 — Security Headers (`pentora.modules.headers`)

Spec ref: §5.11

### Task 57: HeadersModule with ported csp-evaluator algorithm

**Files:**
- Create: `src/pentora/modules/headers.py`
- Create: `src/pentora/security/csp_evaluator.py`
- Create: `tests/unit/test_csp_evaluator.py`
- Create: `tests/unit/test_headers_module.py`

`csp_evaluator.py` port (Google's CSP evaluator algorithm) — checks for:
- `unsafe-inline` in script-src
- `unsafe-eval`
- Plaintext `*` in script-src or default-src
- Missing `object-src 'none'`
- Missing `base-uri 'self'` or `'none'`
- Weak hosts in script-src (e.g., `https:` alone)
- Missing or weak `frame-ancestors`

HeadersModule fetches the target, parses all relevant headers, emits findings:
- Missing CSP → Medium
- Weak CSP (csp-evaluator flags any HIGH issue) → Medium
- Missing HSTS → Medium
- Missing X-Frame-Options / `frame-ancestors` → Medium
- Missing X-Content-Type-Options → Low
- Missing Referrer-Policy → Low
- Missing Permissions-Policy → Low
- Cookie without Secure/HttpOnly/SameSite → Low/Medium per missing flag

---

## Module Group 11 — CORS (`pentora.modules.cors`)

Spec ref: §5.12

### Task 58: CorsModule

**Files:**
- Create: `src/pentora/modules/cors.py`
- Create: `tests/unit/test_cors_module.py`

For each endpoint, send GET with:
- `Origin: https://evil.com` → if response has `Access-Control-Allow-Origin: https://evil.com`, log High
- `Origin: null` → if reflected, High
- `Origin: https://target.com.evil.com` → if reflected via partial-match bug, High
- Wildcard `*` + credentials → Critical (browser blocks but server is misconfigured)

---

## Module Group 12 — Subdomain Takeover (`pentora.modules.takeover`)

Spec ref: §5.13

### Tasks 59–60

- [ ] **Task 59:** `wrappers/subzy.py` — parses subzy JSON output.
- [ ] **Task 60:** `src/pentora/modules/takeover.py` + 80-service fingerprint database in `src/pentora/data/fingerprints/`. Subdomains with dangling CNAMEs + matching fingerprint = Critical finding.

---

## Module Group 13 — Rate Limiting (`pentora.modules.ratelimit`)

Spec ref: §5.14

### Task 61: RateLimitModule

**Files:**
- Create: `src/pentora/modules/ratelimit.py`
- Create: `tests/unit/test_ratelimit_module.py`

For login, password-reset, OTP-request, and a sampled set of API endpoints:
1. Fire 30 requests in 5 seconds
2. Count responses with status 429 / 503 / Retry-After header
3. If <3/30 responses are throttled → log "No effective rate limit on <endpoint>" finding (High for auth endpoints, Medium for API)

Always uses `ctx.config.rate_limit` as global ceiling — never exceeds the user's rate-limit setting overall, but burst-tests within scope.

---

## Module Group 14 — Mobile / APK Analysis (`pentora.modules.mobile`)

Spec ref: §5.15

### Tasks 62–65

- [ ] **Task 62:** `wrappers/apktool.py` — decompile APK.
- [ ] **Task 63:** `wrappers/jadx.py` — Java decompile.
- [ ] **Task 64:** `wrappers/mobsf.py` — invokes locally-running MobSF instance (Docker container). Uploads APK, polls for analysis, downloads JSON report. MobSF Docker started by `pentora setup` (Phase 4).
- [ ] **Task 65:** `src/pentora/modules/mobile.py`

Only runs if `--apk PATH` flag passed to `pentora scan`. Module:
1. Calls apktool + jadx to extract source
2. Greps source for API endpoints (matches against discovered ones to expand surface)
3. Runs secret_patterns.yaml regex against decompiled source
4. Calls MobSF for SSL pinning detection, insecure storage, exported components, intent vulnerabilities
5. Translates MobSF "high"/"medium" issues into Pentora findings

---

## Module Group 15 — Cloud (`pentora.modules.cloud`)

Spec ref: §5.16

### Tasks 66–69

- [ ] **Task 66:** `wrappers/s3scanner.py` — wraps s3scanner.
- [ ] **Task 67:** `wrappers/awsbucketdump.py` — for permission enumeration.
- [ ] **Task 68:** Built-in probes: Azure blob (`{name}.blob.core.windows.net`), GCS (`storage.googleapis.com/{name}`), Firebase (`{name}.firebaseio.com/.json`)
- [ ] **Task 69:** `src/pentora/modules/cloud.py`

For each subdomain + company-name guess derived from target:
1. Run s3scanner against permutations
2. Probe Azure/GCS/Firebase patterns
3. Firebase `/.json` open-DB check → Critical if data returned
4. Open Elasticsearch on found IPs (port 9200) → Critical
5. If creds discovered in disclosure phase, validate against AWS STS GetCallerIdentity (read-only) → Critical if valid

---

## Module Group 16 — wire-up + integration test

### Task 70: Wire all modules into `phase_map` in CLI

Update `phase_map` dict in `cli.py`:

```python
from pentora.modules import (
    recon, discovery, auth, authz, injection, upload, ssrf, logic,
    disclosure, transport, headers, cors, takeover, ratelimit, mobile, cloud,
)

phase_map = {
    "recon": recon.ReconModule,
    "discovery": discovery.DiscoveryModule,
    "auth": auth.AuthModule,
    "authz": authz.AuthzModule,
    "injection": injection.InjectionModule,
    "upload": upload.UploadModule,
    "ssrf": ssrf.SsrfModule,
    "logic": logic.LogicModule,
    "disclosure": disclosure.DisclosureModule,
    "transport": transport.TransportModule,
    "headers": headers.HeadersModule,
    "cors": cors.CorsModule,
    "takeover": takeover.TakeoverModule,
    "ratelimit": ratelimit.RateLimitModule,
    "mobile": mobile.MobileModule,
    "cloud": cloud.CloudModule,
}
```

### Task 71: Update `list-modules` subcommand to list all 16

In `cli.py`:

```python
@main.command("list-modules")
def list_modules() -> None:
    """List available phase modules."""
    from pentora.cli import phase_map  # or factor phase_map out
    for k in phase_map:
        click.echo(k)
```

### Task 72: End-to-end test against mocked target

**Files:**
- Create: `tests/integration/test_full_scan_mocked.py`

Mock every wrapper's `run()` to return empty / fixture data. Invoke `pentora scan --phases all --dry-run` and assert exit 0. Then re-run without `--dry-run`, assert all 16 phases attempted (via log inspection), all reporters produced output, no exceptions raised.

### Task 73: Phase 2 exit gate

- [ ] Run full test suite + coverage: `pytest --cov=pentora --cov-report=term-missing` → all pass, ≥ 80%
- [ ] `ruff check src/ tests/` clean
- [ ] `mypy --strict src/pentora/` clean
- [ ] Update CHANGELOG.md with Phase 2 entries
- [ ] Tag: `git tag pentora-phase-2-complete`

---

## Phase 2 Self-Review

1. **Spec coverage:** §5.2 Discovery → Module Group 1; §5.3 Auth → Group 2; §5.4 Authz → Group 3; §5.5 Injection → Group 4; §5.6 Upload → Group 5; §5.7 SSRF → Group 6; §5.8 Logic → Group 7; §5.9 Disclosure → Group 8; §5.10 Transport → Group 9; §5.11 Headers → Group 10; §5.12 CORS → Group 11; §5.13 Takeover → Group 12; §5.14 RateLimit → Group 13; §5.15 Mobile → Group 14; §5.16 Cloud → Group 15. All 15 module categories covered. ✅
2. **Placeholder scan:** No "TBD"; sub-tasks deferred to subagent execution with the wrapper-template pattern. Each module has concrete checks listed.
3. **Type consistency:** All wrappers extend `ToolWrapper`. All modules extend `PhaseModule`. Both defined in Phase 1.
4. **Granularity caveat:** This phase plan is denser than Phase 1 — each "Task NN" corresponds to ~5 bite-sized sub-steps the executing subagent will produce. The pattern (write fixture → test parser → test argv → write wrapper → commit) is established in Phase 1 Task 10 and Task 11 and repeats identically. If executing inline, the executing-plans skill will expand each Task into its own commit cycle.
