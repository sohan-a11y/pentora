# Pentora Phase 4 — Release (Remaining Reporters + Setup + Distribution)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Follow TDD pattern established in Phase 1.

**Pre-requisite:** Phase 3 complete. Tag `pentora-phase-3-complete` exists.

**Goal:** Add all remaining importable report formats, the Kali installer + `pentora setup/doctor/update` subcommands, notification webhooks, resume/cache support, profile system, compare-reports, Dockerfile, PyPI + Docker CI release workflows, README polish, and the Juice Shop end-to-end test.

**Exit criteria:** A fresh Kali VM running `curl -fsSL .../install.sh | bash` ends with a working `pentora` binary that scans OWASP Juice Shop and produces all 11 report formats. PyPI release + Docker image both publishable via `git tag v1.0.0 && git push --tags`.

**Phase tag at completion:** `git tag v1.0.0` (release tag, not phase tag)

---

## Module Group 21 — Remaining 7 Reporters

Spec ref: §9

For each, write `tests/unit/test_<format>_reporter.py` first, then `src/pentora/reporters/<format>.py`. All follow Phase 1 Tasks 14–17 pattern.

### Task 91: SARIF reporter (`reporters/sarif.py`)

Output: `findings.sarif`. SARIF 2.1.0 schema (https://sarifweb.azurewebsites.net/). Maps Pentora Severity → SARIF level (`error`/`warning`/`note`). One `result` per finding. Tool metadata block at top. Imports into GitHub Code Scanning, VSCode SARIF Viewer.

Test: validate output against the SARIF schema using `jsonschema` library.

### Task 92: CSV summary reporter (`reporters/csv_reporter.py`)

Output: `findings.csv`. Columns: `severity,score,module,title,endpoint,method,evidence,remediation,source,discovered_at`. UTF-8 with BOM for Excel compatibility.

### Task 93: DefectDojo reporter (`reporters/defectdojo.py`)

Output: `findings.defectdojo.json`. DefectDojo "generic findings" format: `{"findings": [{title, severity, description, mitigation, cve, cvssv3, ...}, ...]}`. Severity values: `Critical`, `High`, `Medium`, `Low`, `Info` (Capitalized).

### Task 94: Faraday reporter (`reporters/faraday.py`)

Output: `findings.faraday.json`. Faraday's JSON import schema. Each finding becomes a vulnerability under a host entry.

### Task 95: Burp XML export reporter (`reporters/burp_xml.py`)

Output: `burp-export.xml`. Burp Suite's native XML format so users can re-import findings into Burp Pro (Target → Site map → Import). Schema is documented in Burp's docs.

If `--proxy burp` was used during scan, this reporter just copies the `burp-export.xml` already pulled from Burp. Otherwise it generates Burp-compatible XML from Pentora's findings.

### Task 96: ZAP XML export reporter (`reporters/zap_xml.py`)

Output: `zap-export.xml`. ZAP's `<OWASPZAPReport>` XML format. Same dual-path logic as Burp XML.

### Task 97: HAR reporter (`reporters/har.py`)

Output: `traffic.har`. HTTP Archive 1.2 format. Collects all `request_raw`/`response_raw` from findings + supplementary traffic logged during scan. Opens in browser DevTools, Burp, Charles Proxy, mitmweb.

### Task 98: Auto-register reporters

Modify `cli.py` to register ALL 11 reporters by default. Add `--reporter <name>,<name>` flag to opt subset.

```python
ALL_REPORTERS: list[Reporter] = [
    JsonReporter(), MarkdownReporter(), HtmlReporter(), FindingFolderReporter(),
    SarifReporter(), CsvReporter(), DefectDojoReporter(), FaradayReporter(),
    BurpXmlReporter(), ZapXmlReporter(), HarReporter(),
]
```

---

## Module Group 22 — Notification system

Spec ref: §7 (`--notify` flag)

### Task 99: Notifier

**Files:**
- Create: `src/pentora/notify.py`
- Create: `tests/unit/test_notify.py`

Supports Discord/Slack/Telegram webhooks. CLI flag format: `--notify discord:<webhook-url>` or `--notify slack:<webhook-url>` or `--notify telegram:<bot-token>:<chat-id>`.

Sends one POST per critical/high finding (configurable threshold), plus one summary POST on scan completion. Tested with respx.

---

## Module Group 23 — Resume / Cache / Profile / Compare

### Task 100: Resume support

**Files:**
- Modify: `src/pentora/orchestrator.py` to write `state.json` after each phase
- Modify: `cli.py` `scan` command to honor `--resume`
- Create: `tests/unit/test_resume.py`

When `--resume` set: read `output_dir/state.json`, skip phases already marked completed.

### Task 101: Recon cache (`--cache-recon 7d`)

Recon output (subdomains, live hosts) often doesn't change much. Cache at `~/.pentora/cache/<target>/<phase>.json` with timestamp. If `--cache-recon 7d` and cached output exists and is younger than 7 days, ReconModule short-circuits.

### Task 102: Profile system

**Files:**
- Create: `src/pentora/data/profiles/generic.yaml`
- Create: `src/pentora/data/profiles/dating.yaml`
- Create: `src/pentora/data/profiles/saas.yaml`
- Create: `src/pentora/data/profiles/fintech.yaml`
- Create: `src/pentora/data/profiles/ecommerce.yaml`
- Create: `src/pentora/profile.py`
- Create: `tests/unit/test_profile.py`

Profile YAML example (`dating.yaml`):

```yaml
name: dating
description: Tuned for dating apps (Tinder, Bumble, Pure, etc.)

wordlists:
  api_endpoints: builtin:dating-api-endpoints.txt
  dirs: builtin:common-dirs.txt

extra_business_logic_tests:
  - match_without_consent
  - location_spoofing
  - private_photo_access_without_match
  - message_without_match
  - age_verification_bypass
  - subscription_bypass_for_premium_features

extra_endpoints_to_probe:
  - /api/v*/matches
  - /api/v*/likes
  - /api/v*/messages
  - /api/v*/photos/private
  - /api/v*/users/*/photos

extra_secret_patterns: []

idor_priority_endpoints:
  - /api/v*/users/*
  - /api/v*/conversations/*
  - /api/v*/messages/*
```

`profile.py` loads + validates + makes available via `ctx.profile`.

`list-profiles` CLI subcommand: enumerate profiles dir, print name + description.

### Task 103: Compare reports

Add `pentora compare ./reports/scan-a/ ./reports/scan-b/` subcommand. Diffs the two `findings.db` files. Output:
- Findings present in B but not A: "NEW"
- Findings present in A but not B: "RESOLVED"
- Findings in both: "PERSISTS"

Useful for post-remediation re-scans.

---

## Module Group 24 — `pentora setup` / `doctor` / `update`

### Task 104: `pentora setup`

**Files:**
- Create: `install.sh` (one-line install entry)
- Modify: `src/pentora/cli.py` `setup` command

`install.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Verify Kali / Debian-derivative
if ! command -v apt >/dev/null; then
  echo "Pentora installer currently supports Debian-based distros (Kali, Ubuntu, Debian)."
  exit 1
fi

# 2. System deps
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv \
  git curl wget unzip jq build-essential \
  golang-go default-jdk docker.io

# 3. Pip install pentora
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install pentora

# 4. Run pentora's own setup (installs Go-based tools, downloads wordlists, etc.)
pentora setup
```

`pentora setup` (Python):

```python
@main.command()
@click.option("--skip-go", is_flag=True)
@click.option("--skip-docker", is_flag=True)
def setup(skip_go: bool, skip_docker: bool) -> None:
    """Install all dependent security tools (Go-based, Python-based, Docker images)."""
    from pentora.installer import run_installer
    asyncio.run(run_installer(skip_go=skip_go, skip_docker=skip_docker))
```

**Files:**
- Create: `src/pentora/installer.py`
- Create: `tests/unit/test_installer.py`

`installer.py` runs (per tool, idempotent):

```python
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "github.com/owasp-amass/amass/v4/...@master",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "gowitness": "github.com/sensepost/gowitness@latest",
    "subzy": "github.com/PentestPad/subzy@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "findomain": "github.com/Findomain/Findomain@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "trufflehog": "github.com/trufflesecurity/trufflehog/v3@latest",
    "gitleaks": "github.com/gitleaks/gitleaks/v8@latest",
}
PIP_TOOLS = ["arjun", "paramspider", "xsstrike", "commix", "wafw00f", "Sublist3r", "theHarvester", "tplmap"]
GIT_TOOLS = {  # name → repo URL
    "LinkFinder": "https://github.com/GerbenJavado/LinkFinder",
    "SecretFinder": "https://github.com/m4ll0k/SecretFinder",
    "smuggler": "https://github.com/defparam/smuggler",
    "jwt_tool": "https://github.com/ticarpi/jwt_tool",
    "graphw00f": "https://github.com/dolevf/graphw00f",
    "clairvoyance": "https://github.com/nikitastupin/clairvoyance",
}
DOCKER_IMAGES = ["opensecurity/mobile-security-framework-mobsf:latest"]

# Each install function:
#   - checks if already installed (`shutil.which`)
#   - runs install command, captures output
#   - prints colored ✓ / ✗ with elapsed time
```

After Go/pip/git tools installed, runs:
- `nuclei -update-templates`
- Downloads SecLists subset + curated wordlists to `~/.pentora/wordlists/`
- Optionally prompts for Ollama install + model pull
- Optionally prompts for Burp Pro extension install

### Task 105: `pentora doctor`

Modify `cli.py`:

```python
@main.command()
def doctor() -> None:
    """Diagnose missing tools and misconfigurations."""
    from pentora.installer import run_doctor
    rc = asyncio.run(run_doctor())
    sys.exit(rc)
```

Prints colored report:

```
Pentora doctor v0.1.0
─────────────────────────────────────────
[✓] python 3.12.4
[✓] subfinder v2.6.5
[✓] httpx v1.6.0
[✗] amass NOT FOUND  → install: pentora setup
[✓] nuclei v3.3.1   (templates: 2026-05-15)
[!] nuclei templates older than 7 days → run: pentora update
[✓] sqlmap 1.8.5
[✗] testssl.sh NOT FOUND → install: pentora setup
[✓] Burp REST API: reachable @ http://127.0.0.1:1337
[✗] Ollama: not running on localhost:11434
─────────────────────────────────────────
14/16 tools OK. 2 missing. Exit code: 1
```

Exit code = number of missing tools.

### Task 106: `pentora update`

```python
@main.command()
def update() -> None:
    """Update nuclei templates, wordlists, fingerprints."""
    # nuclei -update-templates
    # git pull on Pentora's wordlist git submodules
    # refresh takeover fingerprint DB from upstream subzy repo
```

---

## Module Group 25 — Docker image

### Task 107: Dockerfile

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `docker-compose.yml` (dev convenience)

`Dockerfile` (multi-stage):

```dockerfile
# Stage 1: Go builder for ProjectDiscovery tools
FROM golang:1.22-alpine AS gobuilder
WORKDIR /build
RUN apk add --no-cache git build-base
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/hahwul/dalfox/v2@latest \
 && go install github.com/PentestPad/subzy@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/sensepost/gowitness@latest \
 && go install github.com/hakluke/hakrawler@latest \
 && go install github.com/d3mondev/puredns/v2@latest

# Stage 2: Python runtime
FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    git curl wget jq sqlmap nikto \
    testssl.sh masscan dirb \
    libimage-exiftool-perl \
    chromium chromium-driver \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gobuilder /root/go/bin/ /usr/local/bin/

# Pentora-managed python tools
RUN pip3 install --no-cache-dir --break-system-packages \
    arjun paramspider xsstrike commix wafw00f \
    theHarvester Sublist3r

# Git-installed tools
RUN mkdir -p /opt/pentora-tools && cd /opt/pentora-tools \
 && git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git \
 && git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git \
 && git clone --depth 1 https://github.com/defparam/smuggler.git \
 && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git \
 && cd LinkFinder && pip3 install --break-system-packages -r requirements.txt && cd .. \
 && cd jwt_tool && pip3 install --break-system-packages -r requirements.txt

# Pentora itself
WORKDIR /app
COPY . /app
RUN pip3 install --no-cache-dir --break-system-packages .

# Nuclei templates baked in
RUN nuclei -update-templates -ud /opt/nuclei-templates

ENV PENTORA_WORDLISTS=/opt/pentora-tools/wordlists
ENV NUCLEI_TEMPLATES=/opt/nuclei-templates

ENTRYPOINT ["pentora"]
CMD ["--help"]
```

`.dockerignore`:
```
.git
.venv
__pycache__
*.pyc
.pytest_cache
.mypy_cache
.ruff_cache
htmlcov
build
dist
*.egg-info
reports/
out/
```

`docker-compose.yml` (dev convenience: spins up Ollama + Juice Shop alongside):

```yaml
version: "3.9"
services:
  ollama:
    image: ollama/ollama:latest
    ports: ["11434:11434"]
    volumes: ["ollama:/root/.ollama"]
  juice-shop:
    image: bkimminich/juice-shop:latest
    ports: ["3000:3000"]
  pentora:
    build: .
    depends_on: [juice-shop]
    volumes:
      - ./out:/out
    command: ["scan", "http://juice-shop:3000", "--phases", "all", "--output", "/out/juice"]
volumes:
  ollama: {}
```

### Task 108: Docker build smoke test

```bash
docker build -t pentora:dev .
docker run --rm pentora:dev --version
```

Expected: prints `pentora, version 0.1.0`.

---

## Module Group 26 — Release CI

### Task 109: `.github/workflows/release.yml`

Triggered on `git tag v*.*.*`:

```yaml
name: Release

on:
  push:
    tags: ['v*.*.*']

jobs:
  pypi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install build twine
      - run: python -m build
      - run: twine upload dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/pentora:${{ github.ref_name }}
            ghcr.io/${{ github.repository_owner }}/pentora:latest

  github-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            install.sh
            CHANGELOG.md
```

### Task 110: PyPI release dry-run

Before tagging, dry-run locally:

```bash
python -m build
twine check dist/*
```

Expected: both wheel and sdist pass twine check.

---

## Module Group 27 — Juice Shop end-to-end test

### Task 111: docker-compose for Juice Shop

**Files:**
- Create: `tests/e2e/juice_shop_compose.yml`
- Create: `tests/e2e/test_juice_shop.sh`

`juice_shop_compose.yml`:
```yaml
services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    ports: ["3000:3000"]
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000/"]
      interval: 5s
      timeout: 5s
      retries: 10
```

`test_juice_shop.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Start Juice Shop
docker compose -f juice_shop_compose.yml up -d
docker compose -f juice_shop_compose.yml wait juice-shop || true

# 2. Wait until reachable
for i in {1..30}; do
  if curl -sf http://localhost:3000/ >/dev/null; then break; fi
  sleep 2
done

# 3. Run Pentora
OUT="$(mktemp -d)"
pentora scan http://localhost:3000 \
  --phases recon,discovery,injection,headers,disclosure \
  --output "$OUT" \
  --scope-include "localhost"

# 4. Assert all 11 reports produced
for f in summary.json summary.html summary.md findings.sarif findings.csv \
         findings.defectdojo.json findings.faraday.json burp-export.xml \
         zap-export.xml traffic.har; do
  if [ ! -f "$OUT/$f" ]; then
    echo "MISSING: $f"
    docker compose -f juice_shop_compose.yml down
    exit 1
  fi
done
[ -d "$OUT/findings" ] || { echo "MISSING: findings/ folder"; exit 1; }

# 5. Assert at least one critical finding (Juice Shop has known SQLi)
CRITS=$(jq '.findings | map(select(.severity == "critical")) | length' "$OUT/summary.json")
if [ "$CRITS" -lt 1 ]; then
  echo "Expected ≥1 critical finding, got $CRITS"
  exit 1
fi

echo "✓ Juice Shop e2e passed. Reports at $OUT"
docker compose -f juice_shop_compose.yml down
```

### Task 112: README final pass

Update `README.md` with:
- Real install instructions
- Real usage examples per profile
- Section on Burp/ZAP setup
- Section on AI mode + LLM provider setup
- Output format table with import instructions per platform (Burp / ZAP / DefectDojo / Faraday / GitHub Code Scanning)
- Screenshots of HTML report (placeholder badges OK for first release)
- Contributing guidelines
- License: AGPLv3
- Security policy (`SECURITY.md` linked)
- Acknowledgements (link to every aggregated tool's repo per spec §14)

### Task 113: SECURITY.md

```markdown
# Security Policy

## Reporting Vulnerabilities

If you discover a vulnerability in Pentora itself, please email security@<your-domain> with details. We aim to respond within 72 hours.

## Responsible Use

Pentora is a penetration testing tool. **Only use it against systems you own or have written authorization to test.** Unauthorized use may violate laws including:

- USA: Computer Fraud and Abuse Act (CFAA)
- UK: Computer Misuse Act
- EU: Directive 2013/40/EU
- India: Information Technology Act, 2000 (Section 43, 66)

By using Pentora you agree you bear sole responsibility for compliance with applicable law.
```

### Task 114: CONTRIBUTING.md

Standard contributing guide: how to run tests, ruff, mypy, how to write a new module, how to add a new tool wrapper, how to submit a PR.

### Task 115: Phase 4 exit gate + v1.0.0 release

- [ ] All tests pass with coverage ≥ 80%
- [ ] `ruff` + `mypy --strict` clean
- [ ] `tests/e2e/test_juice_shop.sh` passes locally
- [ ] Docker build smoke test passes
- [ ] CHANGELOG.md updated with v1.0.0 section
- [ ] README + SECURITY + CONTRIBUTING complete
- [ ] Push tag: `git tag v1.0.0 && git push --tags`
- [ ] Verify PyPI release succeeded: `pip install pentora==1.0.0` in fresh venv
- [ ] Verify Docker image published: `docker pull ghcr.io/<user>/pentora:v1.0.0`

---

## Phase 4 Self-Review

1. **Spec coverage:**
   - §9 (11 importable output formats) → Module Group 21 covers SARIF, CSV, DefectDojo, Faraday, Burp XML, ZAP XML, HAR (the 4 remaining from Phase 1: HTML, JSON, MD, finding-folder are done). ✅
   - §7 (`--notify` flag) → Module Group 22. ✅
   - §7 (`--resume`, `--cache-recon`, `--compare`) + §8 (profile system) → Module Group 23. ✅
   - §10 (setup + install) → Module Group 24. ✅
   - §10 (Docker distribution) → Module Group 25. ✅
   - §10 (PyPI + Docker release) → Module Group 26. ✅
   - §11 (e2e Juice Shop test) → Module Group 27. ✅
   - §12 (Security & Legal) → Task 113 SECURITY.md. ✅
2. **Placeholder scan:** No "TBD". ✅
3. **Type consistency:** All reporters extend `Reporter` (Phase 1 Task 13). All commands use `cli.main` from Phase 1 Task 2. ✅
4. **Release readiness:** Tag-push triggers PyPI + Docker + GitHub release. Single install.sh tested via Juice Shop. ✅
