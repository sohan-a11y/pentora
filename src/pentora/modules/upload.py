"""Upload phase -- file-upload extension-bypass and SVG-XSS checks."""
from __future__ import annotations

import re
from pathlib import Path

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.targets import gather_candidates

# CVSS for file upload RCE (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 critical)
_UPLOAD_RCE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
# CVSS for SVG XSS (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N = 8.2 high)
_UPLOAD_SVG_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"

# URL path patterns that indicate an upload endpoint
_UPLOAD_PATH_RE = re.compile(
    r"/(upload|photo|avatar|image|images|file|files|media|attachment|attachments)(/|$)",
    re.I,
)

# Payload directory (relative to this file)
_DATA_DIR = Path(__file__).parent.parent / "data" / "upload_payloads"

# Minimal test content (non-functional; actual payloads live in _DATA_DIR)
_INERT_SCRIPT_TAG = b"<" + b"?test-probe" + b"?>"
_SVG_BODY = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'


def _is_upload_candidate(endpoint: str, kind: str) -> bool:
    if kind == "upload":
        return True
    return bool(_UPLOAD_PATH_RE.search(endpoint))


def _load_payload(path: Path, fallback: bytes) -> bytes:
    """Load a payload file, returning fallback if unavailable."""
    if not path.exists():
        return fallback
    try:
        return path.read_bytes()
    except OSError:
        return fallback


class UploadModule(PhaseModule):
    name = "upload"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = await gather_candidates(ctx)
        upload_endpoints = [
            c for c in candidates
            if c.method in ("POST", "PUT") and _is_upload_candidate(c.url, c.kind)
        ]
        if not upload_endpoints:
            return []

        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            for cand in upload_endpoints:
                findings += await self._probe_endpoint(client, cand.url)

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings

    async def _probe_endpoint(
        self, client: httpx.AsyncClient, url: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        php_body = _load_payload(_DATA_DIR / "shell.php", _INERT_SCRIPT_TAG)
        svg_body = _load_payload(_DATA_DIR / "xss.svg", _SVG_BODY)

        # 1. Plain .php upload
        try:
            resp = await client.post(
                url,
                files={"file": ("shell.php", php_body, "application/octet-stream")},
            )
            if resp.status_code == 200:
                findings.append(
                    Finding(
                        module="upload.rce",
                        title="PHP file upload accepted",
                        endpoint=url,
                        method="POST",
                        evidence="Uploaded shell.php returned HTTP " + str(resp.status_code),
                        cvss=CVSS.from_vector(_UPLOAD_RCE_VECTOR),
                        description=(
                            "The server accepts .php files which enables remote code execution."
                        ),
                        remediation=(
                            "Allow-list safe file extensions; store uploads outside webroot."
                        ),
                    )
                )
        except httpx.HTTPError:
            pass

        # 2. Extension bypass (.php.jpg)
        try:
            resp = await client.post(
                url,
                files={"file": ("shell.php.jpg", php_body, "image/jpeg")},
            )
            if resp.status_code == 200:
                findings.append(
                    Finding(
                        module="upload.extension_bypass",
                        title="File extension bypass (.php.jpg) accepted",
                        endpoint=url,
                        method="POST",
                        evidence=(
                            "Uploaded shell.php.jpg: bypass returned HTTP "
                            + str(resp.status_code)
                        ),
                        cvss=CVSS.from_vector(_UPLOAD_RCE_VECTOR),
                        description="Extension bypass (double extension) may allow PHP execution.",
                        remediation="Validate the true file type, not just the extension suffix.",
                    )
                )
        except httpx.HTTPError:
            pass

        # 3. SVG with XSS payload
        try:
            resp = await client.post(
                url,
                files={"file": ("payload.svg", svg_body, "image/svg+xml")},
            )
            if resp.status_code == 200:
                findings.append(
                    Finding(
                        module="upload.svg_xss",
                        title="SVG file with XSS payload accepted",
                        endpoint=url,
                        method="POST",
                        evidence="Uploaded xss.svg returned HTTP " + str(resp.status_code),
                        cvss=CVSS.from_vector(_UPLOAD_SVG_VECTOR),
                        description=(
                            "SVG files can contain inline script; serving them enables XSS."
                        ),
                        remediation="Block SVG uploads or sanitize SVG content server-side.",
                    )
                )
        except httpx.HTTPError:
            pass

        # 4. Path traversal filename (informational probe -- no finding emitted)
        import contextlib
        with contextlib.suppress(httpx.HTTPError):
            await client.post(
                url,
                files={"file": ("../../../etc/passwd.jpg", b"not a real image", "image/jpeg")},
            )

        return findings

