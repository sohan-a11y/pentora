"""Injection phase — SQL, XSS, SSTI, command, open-redirect, NoSQLi, smuggling."""
from __future__ import annotations

import contextlib
import re
from urllib.parse import urlparse

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import Candidate, gather_candidates
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.commix import CommixFinding, CommixWrapper
from pentora.wrappers.dalfox import DalfoxHit, DalfoxWrapper
from pentora.wrappers.ghauri import GhauriFinding, GhauriWrapper
from pentora.wrappers.oralyzer import OralyzerHit, OralyzerWrapper
from pentora.wrappers.smuggler import SmugglerFinding, SmugglerWrapper
from pentora.wrappers.sqlmap import SqlmapFinding, SqlmapWrapper
from pentora.wrappers.tplmap import TplmapFinding, TplmapWrapper
from pentora.wrappers.xsstrike import XsstrikeHit, XsstrikeWrapper

# CVSS vectors per Phase 2 plan
_SQLI_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_XSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_SSTI_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_REDIR_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
_NOSQL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
_SMUG_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N"

# Params that suggest a redirect target
_REDIRECT_PARAMS = frozenset({"next", "redirect", "url", "callback", "return", "redir", "goto"})
# Params that suggest text / XSS surface
_XSS_PARAMS = frozenset({"q", "search", "query", "name", "text", "input", "keyword", "s"})
# Numeric path segment (injection candidate for SQLi)
_NUMERIC_PATH_RE = re.compile(r"/\d+(/|$)")


def _host(url: str) -> str:
    return urlparse(url).netloc


def _is_numeric_candidate(cand: Candidate) -> bool:
    if _NUMERIC_PATH_RE.search(cand.url):
        return True
    return any(p.isdigit() or p in ("id", "pk", "user_id", "item_id", "order_id") for p in cand.params)


def _has_redirect_param(cand: Candidate) -> bool:
    return bool(_REDIRECT_PARAMS.intersection(cand.params))


def _has_xss_param(cand: Candidate) -> bool:
    return bool(_XSS_PARAMS.intersection(cand.params))


class InjectionModule(PhaseModule):
    name = "injection"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = await gather_candidates(ctx)
        if not candidates:
            return []

        log_dir = ctx.output_dir / "logs" / "tool-invocations"
        findings: list[Finding] = []
        smuggled_hosts: set[str] = set()

        async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
            for cand in candidates:
                findings += await self._run_per_candidate(cand, log_dir)
                # NoSQLi check for json_body endpoints
                if cand.kind == "json_body":
                    findings += await self._check_nosqli(client, cand)
                # Smuggler: once per unique host
                host = _host(cand.url)
                if host and host not in smuggled_hosts:
                    smuggled_hosts.add(host)
                    findings += await self._run_smuggler(cand.url, log_dir)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def _run_per_candidate(self, cand: Candidate, log_dir: object) -> list[Finding]:
        from pathlib import Path

        ld = Path(str(log_dir))
        findings: list[Finding] = []

        if _is_numeric_candidate(cand):
            findings += await self._run_sqli(cand, ld)
        if _has_xss_param(cand):
            findings += await self._run_xss(cand, ld)
        if cand.params:
            findings += await self._run_cmdi(cand, ld)
        if _has_redirect_param(cand):
            findings += await self._run_redirect(cand, ld)

        return findings

    async def _run_sqli(self, cand: Candidate, log_dir: "Path") -> list[Finding]:
        from pathlib import Path as _Path
        findings: list[Finding] = []
        for WrapperClass in (SqlmapWrapper, GhauriWrapper):
            wrapper = WrapperClass(log_dir=log_dir)
            with contextlib.suppress(ToolNotInstalled):
                results = await wrapper.run(cand.url)
                for r in results:
                    if isinstance(r, (SqlmapFinding, GhauriFinding)):
                        findings.append(
                            Finding(
                                module="injection.sqli",
                                title=f"SQL injection in parameter '{r.parameter}'",
                                endpoint=cand.url,
                                method=cand.method,
                                evidence=r.evidence,
                                cvss=CVSS.from_vector(_SQLI_VECTOR),
                                description=(
                                    f"Parameter '{r.parameter}' is injectable via {r.technique}. "
                                    f"Back-end DBMS: {r.dbms}."
                                ),
                                remediation="Use parameterized queries / prepared statements.",
                            )
                        )
        return findings

    async def _run_xss(self, cand: Candidate, log_dir: "Path") -> list[Finding]:
        findings: list[Finding] = []
        for WrapperClass in (DalfoxWrapper, XsstrikeWrapper):
            wrapper = WrapperClass(log_dir=log_dir)
            with contextlib.suppress(ToolNotInstalled):
                results = await wrapper.run(cand.url)
                for r in results:
                    if isinstance(r, DalfoxHit):
                        findings.append(
                            Finding(
                                module="injection.xss",
                                title=f"XSS in parameter '{r.param}'",
                                endpoint=cand.url,
                                method=cand.method,
                                evidence=f"Payload: {r.payload}",
                                cvss=CVSS.from_vector(_XSS_VECTOR),
                                description=f"Reflected/stored XSS in '{r.param}' ({r.type}).",
                                remediation="Encode output; enforce Content-Security-Policy.",
                            )
                        )
                    elif isinstance(r, XsstrikeHit):
                        findings.append(
                            Finding(
                                module="injection.xss",
                                title=f"XSS vector found in parameter '{r.param}'",
                                endpoint=cand.url,
                                method=cand.method,
                                evidence=f"Vector: {r.payload}",
                                cvss=CVSS.from_vector(_XSS_VECTOR),
                                description=f"XSStrike identified a working vector for '{r.param}'.",
                                remediation="Encode output; enforce Content-Security-Policy.",
                            )
                        )
        return findings

    async def _run_cmdi(self, cand: Candidate, log_dir: "Path") -> list[Finding]:
        findings: list[Finding] = []
        wrapper = CommixWrapper(log_dir=log_dir)
        with contextlib.suppress(ToolNotInstalled):
            results = await wrapper.run(cand.url)
            for r in results:
                if isinstance(r, CommixFinding):
                    findings.append(
                        Finding(
                            module="injection.cmdi",
                            title=f"Command injection in parameter '{r.parameter}'",
                            endpoint=cand.url,
                            method=cand.method,
                            evidence=r.evidence,
                            cvss=CVSS.from_vector(_SSTI_VECTOR),
                            description=f"OS command injection via '{r.parameter}' ({r.technique}).",
                            remediation="Never pass user input to shell commands; use safe APIs.",
                        )
                    )
        return findings

    async def _run_redirect(self, cand: Candidate, log_dir: "Path") -> list[Finding]:
        findings: list[Finding] = []
        wrapper = OralyzerWrapper(log_dir=log_dir)
        with contextlib.suppress(ToolNotInstalled):
            results = await wrapper.run(cand.url)
            for r in results:
                if isinstance(r, OralyzerHit):
                    findings.append(
                        Finding(
                            module="injection.open_redirect",
                            title="Open redirect",
                            endpoint=cand.url,
                            method=cand.method,
                            evidence=f"Redirects to: {r.redirect_to}",
                            cvss=CVSS.from_vector(_REDIR_VECTOR),
                            description=f"URL parameter accepts arbitrary external redirect targets.",
                            remediation="Allow-list redirect destinations; reject arbitrary URLs.",
                        )
                    )
        return findings

    async def _run_smuggler(self, url: str, log_dir: "Path") -> list[Finding]:
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
        findings: list[Finding] = []
        wrapper = SmugglerWrapper(log_dir=log_dir)
        with contextlib.suppress(ToolNotInstalled):
            results = await wrapper.run(base)
            for r in results:
                if isinstance(r, SmugglerFinding):
                    findings.append(
                        Finding(
                            module="injection.http_smuggling",
                            title=f"HTTP request smuggling ({r.technique})",
                            endpoint=base,
                            method="POST",
                            evidence=r.evidence,
                            cvss=CVSS.from_vector(_SMUG_VECTOR),
                            description=f"HTTP/1.1 {r.technique} smuggling detected.",
                            remediation="Normalize Transfer-Encoding headers; upgrade to HTTP/2.",
                        )
                    )
        return findings

    async def _check_nosqli(
        self, client: httpx.AsyncClient, cand: Candidate
    ) -> list[Finding]:
        """Built-in NoSQLi check: inject MongoDB operators and compare responses."""
        normal_payload = {"username": "test", "password": "test"}
        nosql_payloads = [
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": None}, "password": {"$ne": None}},
        ]
        try:
            normal_resp = await client.post(cand.url, json=normal_payload)
        except httpx.HTTPError:
            return []

        for payload in nosql_payloads:
            try:
                nosql_resp = await client.post(cand.url, json=payload)
            except httpx.HTTPError:
                continue
            # Different status code or markedly different response body length → suspicious
            status_differs = nosql_resp.status_code != normal_resp.status_code
            normal_len = len(normal_resp.content)
            nosql_len = len(nosql_resp.content)
            body_differs = normal_len > 0 and (nosql_len / max(normal_len, 1)) > 2.0
            if status_differs or body_differs:
                return [
                    Finding(
                        module="injection.nosqli",
                        title="NoSQL injection — authentication bypass",
                        endpoint=cand.url,
                        method="POST",
                        evidence=(
                            f"Normal: HTTP {normal_resp.status_code} ({normal_len}B); "
                            f"NoSQLi payload: HTTP {nosql_resp.status_code} ({nosql_len}B)."
                        ),
                        cvss=CVSS.from_vector(_NOSQL_VECTOR),
                        description="MongoDB operator injection bypassed authentication.",
                        remediation="Validate and sanitize JSON input; use typed schemas.",
                    )
                ]
        return []
