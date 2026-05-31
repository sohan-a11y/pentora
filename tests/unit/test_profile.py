"""Tests for profile system."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from pentora.cli import main
from pentora.data.profiles import PROFILES
from pentora.profile import load_profile


def test_five_profiles_defined() -> None:
    assert len(PROFILES) == 5


def test_all_profiles_have_name_and_description() -> None:
    for key, profile in PROFILES.items():
        assert "name" in profile, f"Profile {key} missing 'name'"
        assert "description" in profile, f"Profile {key} missing 'description'"
        assert profile["name"] == key


def test_load_profile_generic() -> None:
    p = load_profile("generic")
    assert p["name"] == "generic"
    assert "description" in p


def test_load_profile_dating() -> None:
    p = load_profile("dating")
    assert "extra_business_logic_tests" in p
    assert "idor_priority_endpoints" in p


def test_load_profile_raises_for_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown profile"):
        load_profile("nonexistent")


def test_load_all_profiles() -> None:
    for name in ["generic", "dating", "saas", "fintech", "ecommerce"]:
        p = load_profile(name)
        assert p["description"]


def test_list_profiles_command() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["list-profiles"])
    assert result.exit_code == 0
    for name in ["generic", "dating", "saas", "fintech", "ecommerce"]:
        assert name in result.output
