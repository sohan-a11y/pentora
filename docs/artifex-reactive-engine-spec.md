# Artifex Reactive Engine — Design Spec v0.1

Blackboard + Forward-chaining rules (Experta) + Behavior-tree playbooks (py_trees),
driven by a local Ollama model, fed by an embedded mitmproxy capture primitive.

> This is the contract the engineering team authors rules against. Get the Fact schema
> and Primitive ABC right on paper before writing engine code — they are the tabs and
> sockets everything else plugs into.

---

## 0. Landmines (read first)

- **Model tag:** verify `qwen3.5:9b` exists at https://ollama.com/library/qwen3.5/tags.
  Published Qwen3 sizes are 4b/8b/14b/32b. Safe defaults: `qwen3:8b` (routing/classification),
  `qwen2.5-coder:7b` (payload/syntax generation). The init block is parameterized by `MODEL`.
- **Colab is a sandbox, not the deployment.** It cannot sit in-path of enterprise traffic;
  prototype against targets you drive from inside the VM.
- **Experta is unmaintained** and may fail on Python 3.11+. Test the install first; fallback
  is a small custom forward-chainer (the fact model is simple enough) or `durable_rules`.

---

## 1. The Fact Schema — what lives on the Blackboard

Every observation, hypothesis, and result is an immutable, typed `Fact` with provenance and
confidence. Rules match on `kind` + fields (the socket); rules and primitives emit new Facts
(the tab). Facts are never mutated — a changed belief is a new Fact that supersedes an old one.

```python
from __future__ import annotations
import time, uuid
from enum import Enum
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field


def _fid() -> str:
    return uuid.uuid4().hex[:12]


class Fact(BaseModel):
    """Base for everything on the blackboard. Immutable + traceable."""
    id: str = Field(default_factory=_fid)
    kind: str                                  # discriminator rules match on
    created_at: float = Field(default_factory=time.time)
    source: str                                # primitive/rule that emitted it
    confidence: float = 1.0                    # 0..1
    derived_from: list[str] = Field(default_factory=list)  # parent fact ids (provenance)
    model_config = {"frozen": True}


# ---- The 12 core fact types -------------------------------------------------

class Target(Fact):
    kind: Literal["target"] = "target"
    root: str                                  # e.g. https://app.acme.com
    scope_include: list[str] = []
    scope_exclude: list[str] = []


class HttpTransaction(Fact):
    """Raw captured request/response pair from the mitmproxy primitive."""
    kind: Literal["http_txn"] = "http_txn"
    method: str
    url: str
    req_headers: dict[str, str] = {}
    req_body: Optional[str] = None
    status: int = 0
    resp_headers: dict[str, str] = {}
    resp_body_sha: Optional[str] = None        # hash; body stored out-of-band
    role_label: Optional[str] = None           # which test identity made it


class ObservedEndpoint(Fact):
    """A canonical application action (deduped, path-templated)."""
    kind: Literal["endpoint"] = "endpoint"
    method: str
    template: str                              # /orders/{id}
    seen_count: int = 1
    auth_required: Optional[bool] = None


class Parameter(Fact):
    """An input point with an inferred semantic type."""
    kind: Literal["parameter"] = "parameter"
    endpoint_id: str                           # -> ObservedEndpoint.id
    location: Literal["path", "query", "header", "body", "cookie"]
    name: str
    semantic: Optional[str] = None             # "resource_id" | "price" | "email" | "token" | ...
    example_values: list[str] = []


class SecurityContext(Fact):
    """An authenticated identity: role, token, cookies. The 'who am I' fact."""
    kind: Literal["security_context"] = "security_context"
    role_label: str                            # visitor | user_a | user_b | admin
    rank: int = 0                              # ordering for privilege comparisons
    has_jwt: bool = False
    jwt: Optional[str] = None
    cookies: dict[str, str] = {}


class TechFingerprint(Fact):
    kind: Literal["tech"] = "tech"
    endpoint_id: Optional[str] = None
    stack: list[str] = []                      # ["nginx", "express", "cloudflare-waf"]
    waf: Optional[str] = None


class AppIntentModel(Fact):
    """The reconstructed 'what this app is supposed to do' — the crown jewel.
    Assembled by rules from endpoints, roles, param semantics, UI copy, docs."""
    kind: Literal["intent_model"] = "intent_model"
    roles: list[str] = []
    ownership_rules: list[str] = []            # "orders belong to the creating user's tenant"
    workflow_states: list[str] = []            # ["cart", "checkout", "payment", "confirmed"]
    workflow_edges: list[tuple[str, str]] = [] # allowed transitions


class Hypothesis(Fact):
    """A testable security claim + which primitive can test it."""
    kind: Literal["hypothesis"] = "hypothesis"
    claim: str                                 # "param id on /orders/{id} is IDOR-able"
    target_endpoint_id: Optional[str] = None
    suggested_primitive: Optional[str] = None  # "idor_probe"
    priority: int = 5


class AttackAttempt(Fact):
    """A recorded action taken by a playbook step, with evidence."""
    kind: Literal["attempt"] = "attempt"
    hypothesis_id: Optional[str] = None
    primitive: str
    request_ref: Optional[str] = None
    response_ref: Optional[str] = None
    outcome: Literal["success", "fail", "inconclusive"] = "inconclusive"


class Finding(Fact):
    """A CONFIRMED vulnerability. Only enters via the deterministic validator."""
    kind: Literal["finding"] = "finding"
    title: str
    endpoint_id: Optional[str] = None
    cvss_vector: str = ""
    cvss_score: float = 0.0
    evidence: str = ""
    poc: str = ""
    chain: list[str] = []                      # fact ids forming the kill chain


class TestedNegative(Fact):
    """A recorded dead-end: we tested X and it was NOT vulnerable. Provable coverage."""
    kind: Literal["tested_negative"] = "tested_negative"
    what: str                                  # "jwt alg=none on app.acme.com"
    endpoint_id: Optional[str] = None
    reason: str = ""


class Task(Fact):
    """Engine control fact: a queued/running playbook with a budget."""
    kind: Literal["task"] = "task"
    playbook: str
    args: dict[str, Any] = {}
    status: Literal["queued", "running", "done", "cancelled"] = "queued"
    budget_requests: int = 200
    depth: int = 0                             # chain depth, for runaway protection


# Bonus 13th (worth having early):
class Secret(Fact):
    kind: Literal["secret"] = "secret"
    kind_of: str                               # "aws_key" | "jwt" | "api_key"
    endpoint_id: Optional[str] = None
    redacted: str = ""                         # never store the raw secret
```

---

## 2. The Primitive Contract (ABC) — every tool wears this uniform

Whether a primitive is *embedded* (mitmproxy), *built* (repeater), or *wrapped* (sqlmap via
JSON), it implements ONE interface so the engine drives them all the same way and gets typed
Facts back — never stdout. This is the fix for the `parse(stdout)` fragility.

```python
from abc import ABC, abstractmethod
from enum import Enum
import asyncio


class BlastRadius(str, Enum):
    PASSIVE = "passive"                 # observe only, no packets to target
    ACTIVE_SAFE = "active_safe"         # sends requests, no state change
    ACTIVE_INTRUSIVE = "active_intrusive"  # may change target state (POST/DELETE)


class Capability(BaseModel):
    read_only: bool                    # engine can run these concurrently
    destructive: bool                  # blocked in read-only scans
    idempotent: bool                   # safe to retry
    blast_radius: BlastRadius
    est_requests: int = 1              # for budgeting BEFORE firing
    rate_limit_rps: float = 5.0


class RunContext(BaseModel):
    """Everything a primitive is allowed to touch. The governor lives here."""
    scope: Any                         # .assert_in_scope(url) raises if out of scope
    rate_limiter: Any                  # async token bucket
    cancel: Any                        # asyncio.Event — cooperative cancellation
    dry_run: bool = False
    budget_requests: int = 200
    llm: Any = None                    # local Ollama client (classification/routing)
    rag: Any = None                    # PayloadOracle (concrete payloads)
    blackboard: Any = None             # read sibling facts if needed
    model_config = {"arbitrary_types_allowed": True}


class PrimitiveResult(BaseModel):
    facts: list[Fact] = []             # machine-facing: goes on the blackboard
    summary: str = ""                  # human/LLM-facing one-liner
    is_error: bool = False
    partial: bool = False              # true if cancelled/timed-out with results so far
    requests_made: int = 0
    duration_s: float = 0.0


class Primitive(ABC):
    name: str                          # stable id, kills CLI name-collisions
    version: str
    input_schema: type[BaseModel]      # validated Pydantic input, no *args
    capability: Capability

    @abstractmethod
    async def run(self, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        """Do the work. MUST honor ctx.scope, ctx.dry_run, ctx.cancel, ctx.budget."""

    async def stream(self, inp: BaseModel, ctx: RunContext):
        """Optional: yield Facts as they land (long primitives like sqlmap-equivalent).
        Default: run once and yield the batch."""
        res = await self.run(inp, ctx)
        for f in res.facts:
            yield f


class Governor:
    """Wraps every primitive call. Non-negotiable safety layer."""
    async def execute(self, prim: Primitive, inp: BaseModel, ctx: RunContext) -> PrimitiveResult:
        if ctx.dry_run and prim.capability.blast_radius != BlastRadius.PASSIVE:
            return PrimitiveResult(summary=f"[dry-run] would run {prim.name}", partial=True)
        if prim.capability.destructive and getattr(ctx.scope, "read_only", False):
            return PrimitiveResult(summary=f"[blocked] {prim.name} is destructive", is_error=True)
        if prim.capability.est_requests > ctx.budget_requests:
            return PrimitiveResult(summary="[blocked] over request budget", is_error=True)
        return await prim.run(inp, ctx)
```

---

## 3. The Blackboard

```python
class Blackboard:
    """Shared, append-only fact store. The engine's single source of truth.
    Extends Pentora's existing FindingsStore concept to typed facts."""
    def __init__(self):
        self._facts: dict[str, Fact] = {}
        self._by_kind: dict[str, list[str]] = {}
        self._subscribers = []          # rules engine + playbooks wake on new facts

    def assert_fact(self, f: Fact) -> Fact:
        if f.id in self._facts:
            return f
        self._facts[f.id] = f
        self._by_kind.setdefault(f.kind, []).append(f.id)
        for cb in self._subscribers:
            cb(f)                        # forward-chaining trigger
        return f

    def query(self, kind: str, **where) -> list[Fact]:
        out = [self._facts[i] for i in self._by_kind.get(kind, [])]
        for k, v in where.items():
            out = [f for f in out if getattr(f, k, None) == v]
        return out

    def subscribe(self, cb):
        self._subscribers.append(cb)
```

---

## 4. The tabs and sockets — how rules are authored (Experta)

A rule's **socket** = the facts on its left-hand side (`@Rule(...)`) it waits for.
A rule's **tab** = the facts it asserts on the right-hand side. Same fact `kind` = same shape;
that's how independent rules interlock into a kill chain with zero hardcoded flow.

```python
from experta import KnowledgeEngine, Rule, Fact as E, MATCH, NOT, AS

# Bridge: mirror blackboard Facts into Experta working memory as E(kind=..., **fields).
# (If Experta won't install, replace this class with a 20-line custom matcher — same rules.)

class ReactiveEngine(KnowledgeEngine):

    # RULE 1 — SOCKET: a JWT was seen.  TAB: a hypothesis + a dead-end probe task.
    @Rule(E(kind="security_context", has_jwt=True, jwt=MATCH.jwt))
    def jwt_seen(self, jwt):
        self.declare(E(kind="hypothesis", claim="jwt_attackable",
                       suggested_primitive="jwt_attack", priority=8))
        self.declare(E(kind="task", playbook="jwt_playbook", status="queued"))

    # RULE 2 — SOCKET: an id-like param on an auth'd endpoint + at least two roles.
    #          TAB: an IDOR hypothesis (fires the L3 authz-graph playbook).
    @Rule(E(kind="parameter", semantic="resource_id", endpoint_id=MATCH.eid),
          E(kind="security_context", role_label="user_a"),
          E(kind="security_context", role_label="user_b"))
    def idor_candidate(self, eid):
        self.declare(E(kind="hypothesis", claim="idor", target_endpoint_id=eid,
                       suggested_primitive="idor_probe", priority=9))
        self.declare(E(kind="task", playbook="idor_playbook", args={"endpoint_id": eid}))

    # RULE 3 — SOCKET: a hypothesis exists but NO finding and NO negative yet.
    #          This is the "what if we DON'T find it" branch: after the probe runs and
    #          asserts neither a finding nor a tested_negative within budget, record the null.
    @Rule(E(kind="hypothesis", claim=MATCH.c),
          NOT(E(kind="finding")),
          NOT(E(kind="tested_negative", what=MATCH.c)))
    def ensure_negative_recorded(self, c):
        # scheduled by the governor after a playbook exhausts; keeps coverage provable
        self.declare(E(kind="tested_negative", what=c, reason="probe exhausted, no vuln"))
```

**The discipline every rule author follows:** for each hypothesis, define the *found* path
(a `finding`), the *not-found* path (a `tested_negative`), and let the governor cap depth so
chains can't run forever.

---

## 5. The playbook — ordered steps with fallback (py_trees)

Rules decide *when* to run a playbook; a behavior tree runs the ordered *how*, with explicit
success/failure fallback. Leaves call primitives through the governor.

```python
import py_trees

def jwt_playbook(ctx, jwt_fact):
    # Selector = try each until one succeeds (fallback semantics)
    root = py_trees.composites.Selector("jwt_attack", memory=True)
    root.add_children([
        PrimitiveLeaf("alg_none",     primitive="jwt_alg_none",     ctx=ctx),
        PrimitiveLeaf("brute_secret", primitive="jwt_brute_secret", ctx=ctx),
        PrimitiveLeaf("kid_inject",   primitive="jwt_kid_inject",   ctx=ctx),
    ])
    return root
# Each PrimitiveLeaf: SUCCESS asserts a Finding+forged token fact; FAILURE asserts a
# TestedNegative. A produced 'forged_admin_token' fact then trips a downstream rule -> the
# chain self-assembles.
```

---

## 6. The local AI layer — Ollama init for Colab

```bash
# ---- Colab cell 1 (bash) : install + serve + pull ----
MODEL="qwen3:8b"   # verify tag at https://ollama.com/library/qwen3.5/tags before using :9b

curl -fsSL https://ollama.com/install.sh | sh
nohup ollama serve > /tmp/ollama.log 2>&1 &
sleep 5
ollama pull "$MODEL"          # if this 404s, the tag is wrong — try qwen3:8b / qwen3:14b
ollama list                   # confirm it's present
```

```python
# ---- Colab cell 2 (python) : test the local socket ----
import requests, json

MODEL = "qwen3:8b"
OLLAMA = "http://127.0.0.1:11434"

# 1) socket alive?
print("tags:", requests.get(f"{OLLAMA}/api/tags", timeout=10).json())

# 2) strict-classification smoke test (this is the engine's real job: route/label, not chat)
prompt = {
    "model": MODEL,
    "stream": False,
    "options": {"temperature": 0},              # deterministic classification
    "format": "json",                           # force structured output
    "messages": [
        {"role": "system", "content":
         "You are a strict classifier. Given an HTTP response, output JSON "
         '{"leaked_data": true|false, "reason": "<=10 words"}. No prose.'},
        {"role": "user", "content":
         "HTTP 200 body: {\"user\":\"victim@x.com\",\"ssn\":\"***\"}"},
    ],
}
r = requests.post(f"{OLLAMA}/api/chat", json=prompt, timeout=120).json()
print("classifier says:", r["message"]["content"])
```

**Doctrine reminder:** the local model does classification / routing / intent-extraction only
(`temperature: 0`, `format: json`). It never free-writes attacks. Concrete payloads come from RAG.

---

## 7. RAG as the Payload & Syntax Oracle (not a theory teacher)

```python
from typing import Protocol

class PayloadOracle(Protocol):
    def query(self, intent: str, context: dict) -> list[str]:
        """intent='sqli time-based mysql behind cloudflare' ->
        concrete payloads/args from a curated corpus (PayloadsAllTheThings, sqlmap tampers,
        WAF-bypass sets). Returns strings the primitive fires verbatim — the LLM does not
        invent payloads, it RETRIEVES them."""
        ...
```

The LLM's job: turn an observed situation into a precise oracle *query* and pick among returned
payloads. The oracle's job: return battle-tested syntax. This keeps hallucinated payloads out of
live traffic.

---

## 8. Build order (first 90 days)

1. `Fact` schema + `Blackboard` + `Primitive` ABC + `Governor`  (the keystone — 1–2 wks)
2. Embedded **mitmproxy capture primitive** (promote `auto_capture.py`) emitting `HttpTransaction`
   / `SecurityContext` / `Parameter` facts  (1–2 wks)
3. Canonicalizer: `HttpTransaction` → `ObservedEndpoint` (Drain-style templating)  (1 wk)
4. Migrate 2–3 wrapped tools (sqlmap via `--api`/JSON, nuclei via `-jsonl`) behind the ABC  (days each)
5. Rules engine + first two playbooks (JWT, IDOR) + the deterministic validator gating `Finding`  (2–3 wks)
6. Local Ollama classifier + RAG oracle wired into `RunContext`  (1–2 wks)

Nothing enters the blackboard as a `Finding` without passing the validator. Everything else is a
`Hypothesis`, `AttackAttempt`, or `TestedNegative`.
```
