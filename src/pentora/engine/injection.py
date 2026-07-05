"""Pure URL helpers for injection playbooks — pick an injection point out of a captured URL and
splice a payload into it without disturbing the other parameters. No py_trees / httpx, so it
stays trivially unit-testable and importable in the core.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def split_query_target(url: str) -> tuple[str, str, str] | None:
    """From a URL with a query string, return (base_url, first_param_name, its_value).
    ``None`` if the URL carries no query parameter to inject into."""
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    if not q:
        return None
    param, seed = q[0]                                   # first parameter is the injection point
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, param, seed or "1"


def inject_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param`` set to ``value``, preserving path and other parameters."""
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
