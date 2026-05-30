# Pentora

> Autonomous web application pentest orchestrator. One command. All phases. Production-ready reports.

[![CI](https://github.com/USER/pentora/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/pentora/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## What it is

Pentora runs a full web-application penetration test from a single command:

```bash
pentora https://target.example.com
```

It chains 60+ open-source security tools (subfinder, nuclei, sqlmap, dalfox, jwt_tool, testssl.sh, MobSF, …), integrates with Burp Suite Pro REST API and OWASP ZAP, optionally invokes a local or cloud LLM for novel payloads and report polish, and produces 11 importable report formats including per-finding folders with request/response/PoC/screenshot bundles.

## Status

**Pre-alpha** — Phase 1 (foundation) complete. Phase 2–4 in progress. Not yet ready for paid client work.

## Install (Kali Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/USER/pentora/main/install.sh | bash
```

## Usage

```bash
pentora scan https://target.com                                    # recon only (phase 1)
pentora scan https://target.com --phases all                        # everything
pentora scan https://target.com --profile dating                    # dating-app-tuned tests
pentora scan https://target.com --proxy burp                        # route via Burp Pro
pentora scan https://target.com --ai-mode --llm-provider ollama \
  --llm-model qwen2.5-coder:7b                                      # AI-assisted
pentora scan https://target.com --dry-run                           # print plan, don't execute
```

## License

AGPLv3. See [LICENSE](LICENSE).

## Legal

**Only use Pentora against systems you own or have written authorization to test.** Pentora refuses by default to scan `.mil` / `.gov` and a curated list of forbidden TLDs.
