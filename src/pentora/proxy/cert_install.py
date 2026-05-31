"""Auto-install Burp CA cert into system trust store."""
from __future__ import annotations

import subprocess
from pathlib import Path

import httpx


async def fetch_and_install_burp_ca(
    burp_proxy_url: str = "http://127.0.0.1:8080",
    cert_dest: Path | None = None,
) -> bool:
    """Fetch Burp CA from proxy, write to cert_dest, run update-ca-certificates.

    Returns True on success, False if Burp not reachable or install failed.
    """
    try:
        async with httpx.AsyncClient(verify=False, timeout=3.0) as client:  # noqa: S501
            resp = await client.get(f"{burp_proxy_url}/cert")
            resp.raise_for_status()
    except Exception:  # noqa: BLE001
        return False

    if cert_dest is None:
        cert_dest = Path("/usr/local/share/ca-certificates/burp.crt")

    try:
        cert_dest.write_bytes(resp.content)
        subprocess.run(["update-ca-certificates"], check=False)  # noqa: S603 S607
    except PermissionError:
        return False

    return True
