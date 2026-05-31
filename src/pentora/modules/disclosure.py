"""Disclosure phase -- scan JS files for secrets, source maps, and HTML comments."""
from __future__ import annotations

import re

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.security.secret_patterns import SECRET_PATTERNS

# CVSS vectors
_SECRET_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # noqa: S105
_MAP_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # noqa: S105
_COMMENT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # noqa: S105

_COMMENT_KEYWORDS = re.compile(r"todo|fixme|password|passwd|secret|internal|debug|hack", re.I)
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Pre-compile secret patterns
_COMPILED_PATTERNS = [
    (entry["name"], re.compile(entry["pattern"]), entry["severity"])
    for entry in SECRET_PATTERNS
]

_JS_CONTENT_TYPES = {"application/javascript", "text/javascript", "application/x-javascript"}
_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}


def _is_js_url(url: str) -> bool:
    return url.endswith(".js") or url.endswith(".mjs")


def _is_html_url(url: str) -> bool:
    return url.endswith(".html") or url.endswith(".htm")


def _scan_for_secrets(text: str, endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, compiled, _severity in _COMPILED_PATTERNS:
        if compiled.search(text):
            findings.append(
                Finding(
                    module="disclosure.secret",
                    title=f"Secret Disclosure: {name}",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"Pattern '{name}' matched in response body",
                    cvss=CVSS.from_vector(_SECRET_VECTOR),
                    description=f"The response body contains a potential {name} credential.",
                    remediation="Remove credentials from source code. Use environment variables.",
                )
            )
    return findings


def _scan_html_comments(text: str, endpoint: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _HTML_COMMENT_RE.finditer(text):
        comment = match.group(1)
        if _COMMENT_KEYWORDS.search(comment):
            snippet = comment.strip()[:120]
            findings.append(
                Finding(
                    module="disclosure.html_comment",
                    title="Sensitive HTML Comment",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"<!-- {snippet} -->",
                    cvss=CVSS.from_vector(_COMMENT_VECTOR),
                    description="HTML comment contains sensitive keywords (password/todo/secret).",
                    remediation="Remove developer comments containing sensitive information.",
                )
            )
            break  # one per page is enough
    return findings


class DisclosureModule(PhaseModule):
    name = "disclosure"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.store:
            return []
        all_findings = await ctx.store.all()

        # Collect JS and HTML endpoints from stored findings
        js_endpoints: list[str] = []
        html_endpoints: list[str] = []

        for f in all_findings:
            url = f.endpoint
            ct = str(f.extra.get("content_type", "")).lower().split(";")[0].strip()
            if ct in _JS_CONTENT_TYPES or _is_js_url(url):
                js_endpoints.append(url)
            elif ct in _HTML_CONTENT_TYPES or _is_html_url(url):
                html_endpoints.append(url)

        if not js_endpoints and not html_endpoints:
            return []

        results: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:  # noqa: S501
            for url in js_endpoints:
                results += await self._scan_js(client, url)
            for url in html_endpoints:
                results += await self._scan_html(client, url)

        for f in results:
            if ctx.store:
                await ctx.store.add(f)
        return results

    async def _scan_js(self, client: httpx.AsyncClient, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return []

        body = resp.text
        findings += _scan_for_secrets(body, url)

        # Check source map
        map_url = url + ".map"
        try:
            map_resp = await client.get(map_url)
            if map_resp.status_code == 200:
                findings.append(
                    Finding(
                        module="disclosure.source_map",
                        title="Source Map Exposed",
                        endpoint=map_url,
                        method="GET",
                        evidence=f"GET {map_url} returned HTTP 200",
                        cvss=CVSS.from_vector(_MAP_VECTOR),
                        description="Source map exposes original TypeScript/source filenames.",
                        remediation="Restrict source map access in production.",
                    )
                )
        except httpx.HTTPError:
            pass

        return findings

    async def _scan_html(self, client: httpx.AsyncClient, url: str) -> list[Finding]:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return []
        return _scan_html_comments(resp.text, url)
