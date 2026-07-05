# Pentora CART Engine (`pentora-cart`)

> Continuous Automated Red Teaming — an autonomous engine that watches your web app's
> traffic, forms security hunches, and **only reports a bug when it can prove it.**

This is a separate subsystem from the classic `pentora` scanner (see the main
[README](../README.md)). Where `pentora` runs a big one-shot scan, **CART keeps running** and
only alerts you when something *new* breaks.

---

## 1. What it is, in plain terms

Imagine a tireless junior penetration tester sitting next to your app:

1. **It watches real traffic.** You browse your app through it (or feed it a saved HAR file), and
   it records every request/response as a **fact**.
2. **It forms hunches.** Rules look at those facts and say things like *"two different users and an
   `/orders/{id}` endpoint — this smells like IDOR"* — a **hypothesis**.
3. **It tries to prove each hunch.** A **playbook** fires a few careful, read-only requests to test
   the hunch against the live app.
4. **A judge decides.** A deterministic **validator** looks at the hard evidence. Only if the proof
   is reproducible does the hunch become a real **finding** with a CVSS score. Otherwise it's
   filed as *"tested — not vulnerable"* (that's your provable coverage).

The single most important rule: **the AI never decides something is a bug.** The local LLM only
*suggests where to look*. A deterministic check — leaked bytes that provably belong to another
user, a forged token that actually grants access, a measurable injection signal — is the only thing
that can mint a finding. That's what makes the findings trustworthy and low-noise.

Everything runs **locally** (the LLM is a local Ollama model). No data leaves your machine.

```
  real traffic ──▶ [ Blackboard: facts ] ──▶ rules form hunches ──▶ playbooks test them
                          ▲                                                │
                          └──────────── deterministic validator ◀─────────┘
                                        (proves → Finding, or files "tested, safe")
```

---

## 2. What it can find

| Class | What it proves before reporting |
|-------|--------------------------------|
| **JWT forge** | A token forged from a weak secret is *accepted* where the real one is denied |
| **IDOR** | User B's request returns data that provably belongs to User A |
| **BOLA** | An object *created* by User A (seen in traffic) is readable by User B |
| **SQL injection** | TRUE and FALSE payloads make the response *diverge* (boolean-based) |
| **XSS** | The payload is reflected **unescaped in an HTML page** — i.e. it would execute |
| **PII / stack-trace disclosure** | A real card/SSN/secret or a genuine server stack trace leaks in a response |

Injection payload syntax comes from a curated **payload oracle**, never hand-written guesses.

---

## 3. Install

Requires **Python 3.11+**. From the repo root:

```bash
# core engine + live-traffic capture
pip install -e ".[engine,capture]"
```

- `engine` pulls in `py-trees` (the playbook behavior-tree layer).
- `capture` pulls in `mitmproxy` (the live proxy). Omit it if you only feed HAR files.

**Optional — the local AI brain (Ollama):** the deterministic playbooks work fine without it, but
the LLM adds smarter "where to look" routing.

```bash
# install Ollama (https://ollama.com), then pull the default model:
ollama serve &
ollama pull hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M
```

> **Why an "uncensored" fine-tune?** The LLM here only does one job: classify a captured HTTP
> transaction into a vulnerability category (JSON, temperature 0) so a deterministic playbook knows
> where to look — it never decides anything is a bug (see §1). Safety-tuned base models sometimes
> refuse or hedge on this kind of "does this look exploitable" framing even for entirely benign,
> authorized security testing, which shows up as **false negatives** — hunches that never get
> raised. This community fine-tune of Qwen3.5-9B (Apache-2.0, GGUF on Hugging Face) removes those
> refusals for this narrow classification task. Prefer the stock model instead? Any Ollama tag
> works — swap it into every `model=`/`--model` below, e.g. `ollama pull qwen3.5:9b`.

---

## 4. Quick start (Python — great for Colab / notebooks)

Four lines from capture to report:

```python
from pentora.engine.app import start

MODEL = "hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M"
e = start(target="https://app.example.com", model=MODEL, scope_hosts=["app.example.com"])
e.ingest_har("traffic.har")     # a HAR export from browser DevTools (Network tab → Save all as HAR)
e.run()                         # autonomous: chain hunches → test → validate
print(e.report_markdown("report.md"))   # findings + provable coverage
```

Prefer live traffic instead of a HAR? Start the proxy and browse through it:

```python
url = e.start_proxy(port=8080)   # -> "http://127.0.0.1:8080"
# ... set your browser's HTTP proxy to that URL and click around the app ...
e.stop_proxy()
e.run()
print(e.report_markdown())
```

**Continuous mode** — save today's findings as the accepted baseline, then later only surface what
changed:

```python
e.save_baseline("baseline.json")     # today: everything known is "accepted"
# ... next run, against the same target ...
delta = e.diff_baseline("baseline.json")
print(delta.new, delta.resolved, delta.persisting)   # you only care about `new`
```

---

## 5. Run it from the command line (`pentora-cart`)

After installing, the `pentora-cart` command is available (or use `python -m pentora.engine.cli`).
It has four modes:

### `run` — one-shot scan of captured traffic
```bash
pentora-cart run --target https://app.example.com --har traffic.har --report report.md
# compare against a saved baseline while you're at it:
pentora-cart run --target https://app.example.com --har traffic.har --baseline baseline.json
```

### `baseline` — record the accepted findings
```bash
pentora-cart baseline --target https://app.example.com --har traffic.har --out baseline.json
```

### `proxy` — capture a live browser session, then scan
```bash
pentora-cart proxy --target https://app.example.com --port 8080 --report report.md
# set your browser proxy to http://127.0.0.1:8080, browse the app, then press Ctrl-C to scan
```

### `serve` — the continuous daemon (true CART)
Rescans on an interval and **alerts only on new findings**. It needs a traffic source each cycle —
either a live proxy window (`--proxy`) or a HAR to re-ingest (`--har`):

```bash
# capture live traffic for 5 min each cycle, rescan hourly, alert on anything new
pentora-cart serve --target https://app.example.com --proxy --capture 300 --interval 3600

# run a single cycle and exit (handy for cron/CI)
pentora-cart serve --target https://app.example.com --har traffic.har --once
```

**Common flags** (all modes): `--target` (required), `--scope host1 host2` (in-scope hosts),
`--model hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M` (any Ollama tag works —
see the note in §3), `--ollama-host http://127.0.0.1:11434`, `--rps 5` (global request-rate cap).

### Running it as a real service on Linux
`serve` is a foreground loop by design — let **systemd** (or Docker/`nohup`) daemonize it:

```ini
# /etc/systemd/system/pentora-cart.service
[Service]
ExecStart=pentora-cart serve --target https://app.example.com --proxy --interval 3600
Restart=always
```
```bash
sudo systemctl enable --now pentora-cart
journalctl -u pentora-cart -f      # watch for "REGRESSION: N new finding(s)"
```

---

## 6. Run it in Google Colab

Generate a ready-to-run notebook (sets up mitmproxy + a background Ollama, then runs the engine):

```python
from pentora.engine.colab import write_notebook
write_notebook("pentora_cart.ipynb", target="https://app.example.com",
                model="hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M")
```

Or open the pre-built [`colab/pentora_cart_colab.ipynb`](../colab/pentora_cart_colab.ipynb) directly
via **[colab.research.google.com/github/sohan-a11y/pentora/blob/feature/engine-core/colab/pentora_cart_colab.ipynb](https://colab.research.google.com/github/sohan-a11y/pentora/blob/feature/engine-core/colab/pentora_cart_colab.ipynb)**
— it already does all of the above and includes a self-contained demo that needs no external target.

Open the `.ipynb` in Colab and run the two cells. Nothing leaves the VM.

---

## 7. Safety — how it stays polite

Every active request passes through a single **Governor** chokepoint that enforces:

- **Read-only:** the engine never performs destructive writes. (Object-creating writes are *observed*
  from your traffic, never sent by the engine.)
- **Scope:** requests are only fired at hosts you put in `--scope`. With no scope set, it fails
  **closed** to just the target host — never "anything goes."
- **Rate limit:** a global requests-per-second cap (`--rps`) so it can't hammer a target.
- **Request budget:** a hard ceiling on how many requests a run may send.

> ⚠️ **Only run this against systems you own or are explicitly authorized to test.**

---

## 8. Reading the report

- **Findings** — confirmed, proven vulnerabilities, each with a CVSS vector/score, the evidence
  that proved it, and a reproducible PoC.
- **Coverage (tested, not vulnerable)** — every hunch the engine tested and *disproved*. This is the
  part a normal scanner can't give you: proof of what was checked, not just what was found.
- In continuous mode, the **delta** report is split into **New** (alert on these), **Resolved**
  (fixed since baseline), and **Persisting** (already known).

---

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: py_trees` / `mitmproxy` | `pip install -e ".[engine,capture]"` |
| Findings all say the LLM part was skipped | Start Ollama (`ollama serve`) and `ollama pull hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M` (or any model); deterministic playbooks still run without it |
| `ollama pull hf.co/...` seems to hang | It's downloading silently in a non-interactive shell — check `!ollama list` / `du -sh ~/.ollama/models` in another cell; a fresh pull can take a couple of minutes |
| `serve` exits immediately with "needs a traffic source" | add `--proxy` or `--har` — it refuses to pretend-monitor nothing |
| Proxy `run` returns zero findings | make sure your browser actually routed through `http://127.0.0.1:<port>` and the host is in `--scope` |
| HTTPS traffic not captured via proxy | install the mitmproxy CA cert in your browser (see mitmproxy docs) |
```
