"""One-call engine facade — wire the full CART engine and drive it from a single entry point.

    from pentora.engine.app import start
    e = start(target="https://app.example.com", model="qwen3:8b")
    e.ingest_har("traffic.har")            # or e.ingest([...CapturedTxn...]); or route a browser
    e.run()                                # autonomous: capture -> chain -> validate
    print(e.report_markdown("out.md"))     # findings + provable coverage

Requires the optional playbook deps (``pip install 'pentora[engine,capture]'``).
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pentora.engine.blackboard import Blackboard
from pentora.engine.capture import CapturedTxn, CaptureInput, CapturePrimitive
from pentora.engine.cart import CartEngine
from pentora.engine.chainer import RuleEngine
from pentora.engine.disclosure import disclosure_verify_rule, disclosure_verify_runner
from pentora.engine.live import LiveProxy
from pentora.engine.llm_primitive import Classifier
from pentora.engine.llm_rules import llm_heuristic_runner, llm_route_rule
from pentora.engine.ollama_client import OllamaClassifier
from pentora.engine.playbook import jwt_rule, jwt_runner
from pentora.engine.playbook_idor import idor_rule, idor_runner
from pentora.engine.primitive import Governor, RateLimiter, RunContext, RunScope
from pentora.engine.report import build_report, write_markdown
from pentora.engine.validator import DeterministicValidator

_DEFAULT_WORDLIST = ["password", "admin", "secret", "changeme", "123456", "letmein", "secret123"]


def _host(target: str) -> str:
    return urlsplit(target).hostname or target


@dataclass
class Engine:
    target: str
    bb: Blackboard
    cart: CartEngine
    scope: RunScope
    proxy: LiveProxy | None = None

    def start_proxy(self, port: int = 8080, host: str = "127.0.0.1") -> str:
        """Start a live intercepting proxy that feeds the blackboard. Route a browser through the
        returned URL; call run() to surface findings from the traffic so far. Needs mitmproxy."""
        self.proxy = LiveProxy(self.bb, host=host, port=port, scope_hosts=self.scope.include)
        return self.proxy.start()

    def stop_proxy(self) -> None:
        if self.proxy is not None:
            self.proxy.stop()
            self.proxy = None

    def ingest(self, transactions: list[CapturedTxn]) -> int:
        """Feed captured request/response pairs through capture; return fact count."""
        asyncio.run(self.cart.governor.execute(
            CapturePrimitive(), CaptureInput(transactions=transactions),
            RunContext(scope=self.scope, blackboard=self.bb),
        ))
        return len(self.bb)

    def ingest_har(self, path: str | Path) -> int:
        """Load a browser HAR export (e.g. saved from DevTools) into the blackboard."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        txns: list[CapturedTxn] = []
        for entry in data.get("log", {}).get("entries", []):
            req = entry.get("request", {})
            resp = entry.get("response", {})
            content = resp.get("content", {}) or {}
            txns.append(CapturedTxn(
                method=req.get("method", "GET"),
                url=req.get("url", ""),
                req_headers={h["name"]: h["value"] for h in req.get("headers", [])},
                status=int(resp.get("status", 0) or 0),
                resp_body=content.get("text"),
            ))
        return self.ingest(txns)

    def run(self) -> dict[str, int]:
        """Drive the autonomous loop until fixpoint. Returns the summary."""
        return self.cart.run()

    def report(self) -> dict[str, object]:
        return build_report(self.bb, target=self.target)

    def report_markdown(self, path: str | Path = "pentora-cart-report.md") -> str:
        out = write_markdown(self.bb, Path(path), target=self.target)
        return out.read_text(encoding="utf-8")


def start(
    target: str,
    rps: float = 5.0,
    model: str = "qwen3.5:9b",
    ollama_host: str = "http://127.0.0.1:11434",
    wordlist: list[str] | None = None,
    scope_hosts: list[str] | None = None,
    classifier: Classifier | None = None,
) -> Engine:
    """Wire the full CART engine — all rules + playbooks + a rate-limited, read-only Governor —
    and return a ready-to-drive Engine. ``classifier`` lets tests inject a double for the LLM."""
    bb = Blackboard()
    chainer = RuleEngine(bb)
    for rule in (jwt_rule(), idor_rule(), llm_route_rule(), disclosure_verify_rule()):
        chainer.add_rule(rule)
    scope = RunScope(include=scope_hosts or [_host(target)], read_only=True)
    cart = CartEngine(
        bb=bb,
        chainer=chainer,
        governor=Governor(rate_limiter=RateLimiter(rps=rps)),
        validator=DeterministicValidator(),
        scope=scope,
        config={
            "ollama": classifier or OllamaClassifier(model=model, host=ollama_host),
            "wordlist": wordlist or _DEFAULT_WORDLIST,
        },
    )
    for name, runner in (
        ("jwt_playbook", jwt_runner),
        ("idor_playbook", idor_runner),
        ("llm_heuristic_playbook", llm_heuristic_runner),
        ("disclosure_verify", disclosure_verify_runner),
    ):
        cart.register(name, runner)
    return Engine(target=target, bb=bb, cart=cart, scope=scope)
