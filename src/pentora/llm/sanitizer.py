"""PII sanitizer — strip sensitive data before sending to remote LLMs."""
from __future__ import annotations

import re

# Matches IPv4 addresses
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Matches IPv6 addresses (simplified — covers the most common forms)
_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    r'|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}'
    r'|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}'
)

# RFC 5322-ish email
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

# UUID v4 pattern
_UUID_RE = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

# JWT token: eyJ<base64url>.<base64url>.<base64url>
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')

# Hex token >= 32 chars (API keys, session tokens, etc.)
_HEX_RE = re.compile(r'\b[0-9a-fA-F]{32,}\b')

# Numeric ID in URL path segment: /users/12345/
_URL_ID_RE = re.compile(r'(/[a-zA-Z_\-]+)/\d+(/|$)')


def sanitize(text: str, target_host: str | None = None) -> str:
    """Remove PII from text before sending to a remote LLM.

    Replacements applied (in order):
      1. target host → <target-host>
      2. JWT tokens → <jwt>   (before hex, as JWTs contain hex)
      3. UUIDs → <uuid>
      4. emails → <email>
      5. IPv4/IPv6 → <ip>
      6. hex tokens (>=32 chars) → <token>
      7. numeric URL path IDs → /segment/<id>/
    """
    # JWTs first — they look like base64 which overlaps with hex
    text = _JWT_RE.sub('<jwt>', text)

    text = _UUID_RE.sub('<uuid>', text)
    # Emails before target-host so admin@corp.com → <email>, not admin@<target-host>
    text = _EMAIL_RE.sub('<email>', text)

    if target_host:
        text = re.sub(re.escape(target_host), '<target-host>', text)
    text = _IPV4_RE.sub('<ip>', text)
    text = _IPV6_RE.sub('<ip>', text)
    text = _HEX_RE.sub('<token>', text)

    def _replace_url_id(m: re.Match[str]) -> str:
        return f'{m.group(1)}/<id>{m.group(2)}'

    return _URL_ID_RE.sub(_replace_url_id, text)
