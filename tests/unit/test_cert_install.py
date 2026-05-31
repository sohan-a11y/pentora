"""Tests for Burp CA cert install and extension_installer."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import respx
from httpx import Response

from pentora.proxy.cert_install import fetch_and_install_burp_ca
from pentora.proxy.extension_installer import (
    BURP_REST_API_JAR_URL,
    print_extension_instructions,
)

PROXY_URL = "http://127.0.0.1:8080"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_install_burp_ca_success(tmp_path: Path) -> None:
    cert_bytes = b"-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----\n"
    respx.get(f"{PROXY_URL}/cert").mock(return_value=Response(200, content=cert_bytes))
    dest = tmp_path / "burp.crt"
    with patch("subprocess.run") as mock_run:
        result = await fetch_and_install_burp_ca(
            burp_proxy_url=PROXY_URL, cert_dest=dest
        )
    assert result is True
    assert dest.read_bytes() == cert_bytes
    mock_run.assert_called_once()


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_install_burp_ca_unreachable() -> None:
    respx.get(f"{PROXY_URL}/cert").mock(side_effect=Exception("connection refused"))
    result = await fetch_and_install_burp_ca(burp_proxy_url=PROXY_URL)
    assert result is False


@respx.mock
@pytest.mark.asyncio
async def test_fetch_and_install_burp_ca_permission_error(tmp_path: Path) -> None:
    cert_bytes = b"fake"
    respx.get(f"{PROXY_URL}/cert").mock(return_value=Response(200, content=cert_bytes))
    dest = tmp_path / "burp.crt"
    with patch("pathlib.Path.write_bytes", side_effect=PermissionError("denied")):
        result = await fetch_and_install_burp_ca(
            burp_proxy_url=PROXY_URL, cert_dest=dest
        )
    assert result is False


def test_print_extension_instructions(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    with patch("pathlib.Path.home", return_value=tmp_path):
        print_extension_instructions()
    captured = capsys.readouterr()
    assert "Burp REST API" in captured.out
    assert BURP_REST_API_JAR_URL in captured.out
    assert "burp-extensions" in captured.out


def test_burp_jar_url_is_correct() -> None:
    assert "burp-rest-api-2.1.0.jar" in BURP_REST_API_JAR_URL
    assert BURP_REST_API_JAR_URL.startswith("https://")
