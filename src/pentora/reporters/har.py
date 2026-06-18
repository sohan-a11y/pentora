"""HTTP Archive (HAR) 1.2 reporter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pentora.finding import Finding
from pentora.reporters.base import Reporter
from pentora.version import __version__


def _parse_request(raw: str, endpoint: str, method: str) -> dict[str, Any]:
    """Parse raw HTTP request text into HAR request object."""
    if not raw:
        return {
            "method": method,
            "url": endpoint,
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": -1,
        }

    lines = raw.split("\n")
    # First line: METHOD /path HTTP/1.1
    first_line = lines[0].strip() if lines else ""
    parts = first_line.split(" ", 2)
    req_method = parts[0] if parts else method
    req_path = parts[1] if len(parts) > 1 else "/"
    http_ver = parts[2] if len(parts) > 2 else "HTTP/1.1"

    # Extract Host header for full URL
    host = ""
    headers = []
    body = ""
    in_body = False
    for line in lines[1:]:
        if in_body:
            body += line + "\n"
            continue
        stripped = line.strip()
        if stripped == "":
            in_body = True
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            headers.append({"name": key.strip(), "value": value.strip()})
            if key.strip().lower() == "host":
                host = value.strip()

    # Build URL
    url = f"https://{host}{req_path}" if host and req_path.startswith("/") else endpoint

    result: dict[str, Any] = {
        "method": req_method,
        "url": url,
        "httpVersion": http_ver.strip(),
        "headers": headers,
        "queryString": [],
        "cookies": [],
        "headersSize": len(lines[0]) if lines else 0,
        "bodySize": len(body),
    }
    if body.strip():
        result["postData"] = {"mimeType": "application/json", "text": body.strip()}
    return result


def _parse_response(raw: str) -> dict[str, Any]:
    """Parse raw HTTP response text into HAR response object."""
    if not raw:
        return {
            "status": 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {"size": -1, "mimeType": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        }

    lines = raw.split("\n")
    first_line = lines[0].strip() if lines else ""
    parts = first_line.split(" ", 2)
    http_ver = parts[0] if parts else "HTTP/1.1"
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    status_text = parts[2] if len(parts) > 2 else ""

    headers = []
    body = ""
    in_body = False
    mime = ""
    for line in lines[1:]:
        if in_body:
            body += line + "\n"
            continue
        stripped = line.strip()
        if stripped == "":
            in_body = True
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            headers.append({"name": key.strip(), "value": value.strip()})
            if key.strip().lower() == "content-type":
                mime = value.strip()

    return {
        "status": status,
        "statusText": status_text.strip(),
        "httpVersion": http_ver.strip(),
        "headers": headers,
        "cookies": [],
        "content": {"size": len(body), "mimeType": mime, "text": body.strip()},
        "redirectURL": "",
        "headersSize": len(lines[0]) if lines else 0,
        "bodySize": len(body),
    }


class HarReporter(Reporter):
    name = "har"
    output_filename = "traffic.har"

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        entries = []
        for f in findings:
            entry: dict[str, Any] = {
                "startedDateTime": f.discovered_at.isoformat(),
                "time": -1,
                "request": _parse_request(f.request_raw, f.endpoint, f.method),
                "response": _parse_response(f.response_raw),
                "cache": {},
                "timings": {"send": -1, "wait": -1, "receive": -1},
                "_pentora_finding_id": f.id,
                "_pentora_module": f.module,
            }
            entries.append(entry)

        doc: dict[str, Any] = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Pentora", "version": __version__},
                "entries": entries,
            }
        }
        out = output_dir / self.output_filename
        out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return out
