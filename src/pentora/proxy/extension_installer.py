"""Burp extension installer helper."""
from __future__ import annotations

from pathlib import Path

BURP_REST_API_JAR_URL = (
    "https://github.com/vmware-archive/burp-rest-api/releases/download/2.1.0/"
    "burp-rest-api-2.1.0.jar"
)


def print_extension_instructions() -> None:
    """Print instructions for installing the Burp REST API extension."""
    ext_dir = Path.home() / ".pentora" / "burp-extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)
    jar_path = ext_dir / "burp-rest-api-2.1.0.jar"
    print(  # noqa: T201
        f"To enable Burp REST API:\n"
        f"  1. Download {BURP_REST_API_JAR_URL}\n"
        f"  2. Save to {ext_dir}\n"
        f"  3. In Burp: Extender → Add → {jar_path}"
    )
