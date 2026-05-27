from pathlib import Path

import pytest

from pentora.scope import Scope, ScopeViolation


def test_scope_allows_exact_host() -> None:
    scope = Scope(include=["pure.app"])
    assert scope.is_in_scope("https://pure.app/login")


def test_scope_allows_wildcard_subdomain() -> None:
    scope = Scope(include=["*.pure.app"])
    assert scope.is_in_scope("https://api.pure.app/v1/users")
    assert scope.is_in_scope("https://cdn.pure.app/img.jpg")
    assert not scope.is_in_scope("https://pure.app/login")  # bare domain not covered by *


def test_scope_excludes_take_precedence() -> None:
    scope = Scope(include=["*.pure.app"], exclude=["admin.pure.app"])
    assert scope.is_in_scope("https://api.pure.app")
    assert not scope.is_in_scope("https://admin.pure.app/dashboard")


def test_scope_path_exclude() -> None:
    scope = Scope(include=["pure.app"], exclude_paths=["/billing/*", "/legal/*"])
    assert scope.is_in_scope("https://pure.app/profile")
    assert not scope.is_in_scope("https://pure.app/billing/invoice/123")


def test_scope_forbidden_domains_always_blocked(tmp_path: Path) -> None:
    forbidden = tmp_path / "forbidden.txt"
    forbidden.write_text(".mil\n.gov\n")
    scope = Scope(include=["*.dod.mil"], forbidden_file=forbidden)
    with pytest.raises(ScopeViolation, match="forbidden TLD"):
        scope.assert_in_scope("https://target.dod.mil/")


def test_scope_load_from_file(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment\n*.pure.app\n-admin.pure.app\n!/billing/*\n")
    scope = Scope.from_file(scope_file)
    assert scope.is_in_scope("https://api.pure.app")
    assert not scope.is_in_scope("https://admin.pure.app")
    assert not scope.is_in_scope("https://api.pure.app/billing/123")
