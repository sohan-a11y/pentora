"""Tests for LLM PII sanitizer."""
from __future__ import annotations

from pentora.llm.sanitizer import sanitize


def test_sanitize_target_host() -> None:
    result = sanitize("Error on example.com/login", target_host="example.com")
    assert "example.com" not in result
    assert "<target-host>" in result


def test_sanitize_ipv4() -> None:
    result = sanitize("Found host at 192.168.1.100 responding")
    assert "192.168.1.100" not in result
    assert "<ip>" in result


def test_sanitize_email() -> None:
    result = sanitize("User admin@example.com logged in")
    assert "admin@example.com" not in result
    assert "<email>" in result


def test_sanitize_uuid() -> None:
    result = sanitize("Session id: 550e8400-e29b-41d4-a716-446655440000")
    assert "550e8400-e29b-41d4-a716-446655440000" not in result
    assert "<uuid>" in result


def test_sanitize_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = sanitize(f"Token: {jwt}")
    assert jwt not in result
    assert "<jwt>" in result


def test_sanitize_hex_token() -> None:
    token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    result = sanitize(f"API key: {token}")
    assert token not in result
    assert "<token>" in result


def test_sanitize_short_hex_preserved() -> None:
    """Hex strings shorter than 32 chars should not be replaced."""
    result = sanitize("color: #ff0000 is red")
    assert "<token>" not in result


def test_sanitize_url_numeric_id() -> None:
    result = sanitize("GET /users/12345/profile")
    assert "12345" not in result
    assert "<id>" in result


def test_sanitize_no_target_host_is_optional() -> None:
    result = sanitize("plain text with no PII")
    assert result == "plain text with no PII"


def test_sanitize_multiple_replacements() -> None:
    text = "User admin@corp.com at 10.0.0.1 accessed /orders/99999/status"
    result = sanitize(text, target_host="corp.com")
    assert "admin@" not in result
    assert "10.0.0.1" not in result
    assert "99999" not in result
