# Changelog

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
