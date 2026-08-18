# Pentora

![GitHub License](https://img.shields.io/github/license/sohan-a11y/pentora?style=flat-square)
![GitHub Last Commit](https://img.shields.io/github/last-commit/sohan-a11y/pentora?style=flat-square)
![GitHub Stars](https://img.shields.io/github/stars/sohan-a11y/pentora?style=flat-square)
![GitHub Forks](https://img.shields.io/github/forks/sohan-a11y/pentora?style=flat-square)

[![Skills](https://skillicons.dev/icons?i=python,docker,fastapi)](https://skillicons.dev)


> Autonomous web application pentest orchestrator. One command. All phases. Production-ready reports.

[![CI](https://github.com/sohan-a11y/pentora/actions/workflows/ci.yml/badge.svg)](https://github.com/sohan-a11y/pentora/actions)
[![Release](https://github.com/sohan-a11y/pentora/actions/workflows/release.yml/badge.svg)](https://github.com/sohan-a11y/pentora/actions/workflows/release.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Coverage: 89%](https://img.shields.io/badge/coverage-89%25-brightgreen)]()

## What it is

Pentora runs a full web-application penetration test from a single command. It chains 60+ open-source security tools, integrates with Burp Suite Pro and OWASP ZAP, optionally invokes local or cloud LLMs for novel payloads, and produces 11 importable report formats.

**16 security phases**: recon, discovery, auth, authz, injection, upload, ssrf, logic, disclosure, transport, headers, cors, takeover, ratelimit, mobile, cloud.

## Install

### One-line (Kali Linux / Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/sohan-a11y/pentora/main/install.sh | bash
```

### From PyPI

```bash
pip install pentora
pentora doctor   # verify all tools installed
```

### Docker

```bash
docker pull ghcr.io/sohan-a11y/pentora:latest
docker run --rm ghcr.io/sohan-a11y/pentora:latest scan https://target.com --phases recon
```

### From source

```bash
git clone https://github.com/sohan-a11y/pentora
cd pentora
pip install -e ".[dev]"
pentora doctor
```

## Usage

```bash
# Basic scan (recon only)
pentora scan https://target.com

# Full scan — all 16 phases
pentora scan https://target.com --phases all

# Profile-tuned scan
pentora scan https://target.com --profile dating --phases all
pentora scan https://target.com --profile fintech --phases all
pentora scan https://target.com --profile saas    --phases all

# Route traffic through proxy
pentora scan https://target.com --proxy burp   # Burp Suite Pro at :1337
pentora scan https://target.com --proxy zap    # OWASP ZAP at :8090
pentora scan https://target.com --proxy auto   # auto-detect whichever is running

# AI-powered modules
pentora scan https://target.com \
    --ai-mode \
    --llm-provider ollama \
    --llm-model qwen2.5-coder:7b

pentora scan https://target.com \
    --ai-mode \
    --llm-provider openrouter \
    --llm-model anthropic/claude-3.5-sonnet

# Mobile / APK analysis
pentora scan https://target.com --apk ./app.apk --phases mobile

# Selective reporters
pentora scan https://target.com --reporter json,sarif,html

# Resume interrupted scan
pentora scan https://target.com --resume --output ./previous-output

# Cache recon results for 7 days
pentora scan https://target.com --cache-recon 7d

# Webhook notifications
pentora scan https://target.com --notify "discord:https://discord.com/api/webhooks/..."
pentora scan https://target.com --notify "slack:https://hooks.slack.com/services/..."
pentora scan https://target.com --notify "telegram:TOKEN:CHATID"

# Diff two scan results
pentora compare ./scan-2025-01/ ./scan-2025-02/

# Dry run — print plan, don't execute
pentora scan https://target.com --dry-run --phases all
```

## Profiles

```bash
pentora list-profiles
```

| Profile   | Description |
|-----------|-------------|
| generic   | General-purpose web application |
| dating    | Dating apps — location spoofing, private photo access, age verification |
| saas      | SaaS platforms and B2B applications |
| fintech   | Financial technology and payment platforms |
| ecommerce | E-commerce and retail platforms |

## Output Formats

All 11 reporters run by default. Use `--reporter name1,name2` to filter.

| Format | File | Import into |
|--------|------|-------------|
| JSON | `summary.json` | Splunk, Elastic, custom dashboards |
| Markdown | `summary.md` | GitHub Issues, Jira, Confluence |
| HTML | `summary.html` | Browser, email |
| Per-finding folder | `findings/` | Manual review, evidence bundles |
| SARIF 2.1.0 | `findings.sarif` | GitHub Code Scanning, VS Code |
| CSV | `findings.csv` | Excel, Google Sheets |
| DefectDojo | `findings.defectdojo.json` | DefectDojo generic importer |
| Faraday | `findings.faraday.json` | Faraday import |
| Burp XML | `burp-export.xml` | Burp Suite Issues tab |
| ZAP XML | `zap-export.xml` | OWASP ZAP Alerts |
| HAR | `traffic.har` | Browser DevTools, Postman |

## Burp Suite Setup

1. Start Burp Suite Pro, enable the REST API in **Settings > Suite > REST API** on port 1337.
2. Run: `pentora scan https://target.com --proxy burp`
3. Pentora adds discovered hosts to Burp scope and triggers an active scan.
4. Import `burp-export.xml` into the Burp Issues tab for consolidated view.

## OWASP ZAP Setup

1. Start ZAP and enable API access (default port 8090).
2. Run: `pentora scan https://target.com --proxy zap`
3. ZAP active scan runs alongside Pentora phases.
4. Import `zap-export.xml` via ZAP > Report > Import.

## AI Mode

Pentora includes 5 AI-powered modules:

| Module | What it does |
|--------|-------------|
| logic_fuzzer | Generates business-logic test cases via LLM |
| waf_mutator | Mutates payloads to evade WAFs |
| auth_flow_reader | Analyzes auth flows for weaknesses |
| pivot_advisor | Suggests lateral movement paths |
| report_polisher | Rewrites findings in clear, client-ready language |

Supported providers: **Ollama** (local), **OpenRouter** (cloud), **NVIDIA NIM** (cloud GPU).

```bash
# Pull a model for Ollama
ollama pull qwen2.5-coder:7b

# Use with Pentora
pentora scan https://target.com --ai-mode --llm-provider ollama --llm-model qwen2.5-coder:7b
```

## Management Commands

```bash
pentora setup        # Install all required tools
pentora doctor       # Check tool availability
pentora update       # Update nuclei templates
pentora list-modules # Show all 16 phase modules
pentora list-profiles # Show all 5 profiles
pentora compare DIR_A DIR_B  # Diff two scans
```

## Acknowledgements

Pentora orchestrates and integrates these excellent open-source tools:

- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain enumeration
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing
- [nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability scanner
- [katana](https://github.com/projectdiscovery/katana) — Web crawler
- [ffuf](https://github.com/ffuf/ffuf) — Content discovery
- [dalfox](https://github.com/hahwul/dalfox) — XSS scanner
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQL injection
- [ghauri](https://github.com/r0oth3x49/ghauri) — Advanced SQL injection
- [jwt_tool](https://github.com/ticarpi/jwt_tool) — JWT testing
- [testssl.sh](https://github.com/drwetter/testssl.sh) — TLS/SSL testing
- [waybackurls](https://github.com/tomnomnom/waybackurls) — Historical URLs
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) — JS link extraction
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) — Secret detection
- [paramspider](https://github.com/devanshbatham/ParamSpider) — Parameter discovery
- [arjun](https://github.com/s0md3v/Arjun) — HTTP parameter discovery
- [commix](https://github.com/commixproject/commix) — Command injection
- [tplmap](https://github.com/epinna/tplmap) — Template injection
- [xsstrike](https://github.com/s0md3v/XSStrike) — Advanced XSS
- [wafw00f](https://github.com/EnableSecurity/wafw00f) — WAF detection
- [hydra](https://github.com/vanhauser-thc/thc-hydra) — Credential brute-force
- [subzy](https://github.com/PentestPad/subzy) — Subdomain takeover
- [hakrawler](https://github.com/hakluke/hakrawler) — Fast web crawler
- [interactsh](https://github.com/projectdiscovery/interactsh) — Out-of-band interaction
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Mobile security
- [OWASP ZAP](https://github.com/zaproxy/zaproxy) — Web app scanner
- [Burp Suite](https://portswigger.net/burp) — Web security testing platform

## License

AGPLv3. See [LICENSE](LICENSE).

## Legal

**Only use Pentora against systems you own or have written authorization to test.** Unauthorized testing is illegal. Pentora refuses by default to scan `.mil`, `.gov`, and a curated list of forbidden TLDs.