"""Tests for Dockerfile syntax and key content."""
from __future__ import annotations

from pathlib import Path


def test_dockerfile_exists() -> None:
    dockerfile = Path(__file__).parent.parent.parent / "Dockerfile"
    assert dockerfile.exists(), "Dockerfile not found"


def test_dockerfile_has_from() -> None:
    dockerfile = Path(__file__).parent.parent.parent / "Dockerfile"
    content = dockerfile.read_text()
    assert "FROM" in content


def test_dockerfile_has_entrypoint() -> None:
    dockerfile = Path(__file__).parent.parent.parent / "Dockerfile"
    content = dockerfile.read_text()
    assert "ENTRYPOINT" in content
    assert "pentora" in content


def test_dockerfile_has_multistage() -> None:
    dockerfile = Path(__file__).parent.parent.parent / "Dockerfile"
    content = dockerfile.read_text()
    assert content.count("FROM") >= 2, "Should be a multi-stage build"


def test_dockerignore_exists() -> None:
    dockerignore = Path(__file__).parent.parent.parent / ".dockerignore"
    assert dockerignore.exists()


def test_docker_compose_exists() -> None:
    compose = Path(__file__).parent.parent.parent / "docker-compose.yml"
    assert compose.exists()


def test_release_workflow_exists() -> None:
    workflow = Path(__file__).parent.parent.parent / ".github" / "workflows" / "release.yml"
    assert workflow.exists()
