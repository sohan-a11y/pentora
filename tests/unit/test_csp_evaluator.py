"""Tests for csp_evaluator — each weakness class."""
from __future__ import annotations

import pytest

from pentora.security.csp_evaluator import CspIssue, evaluate_csp


def test_unsafe_inline_flagged() -> None:
    issues = evaluate_csp("script-src 'self' 'unsafe-inline'")
    kinds = [i.kind for i in issues]
    assert "unsafe-inline" in kinds
    assert any(i.severity == "HIGH" for i in issues if i.kind == "unsafe-inline")


def test_unsafe_eval_flagged() -> None:
    issues = evaluate_csp("script-src 'self' 'unsafe-eval'")
    kinds = [i.kind for i in issues]
    assert "unsafe-eval" in kinds


def test_wildcard_script_src_flagged() -> None:
    issues = evaluate_csp("script-src *")
    kinds = [i.kind for i in issues]
    assert "wildcard-script" in kinds


def test_missing_object_src_flagged() -> None:
    issues = evaluate_csp("default-src 'self'")
    kinds = [i.kind for i in issues]
    assert "missing-object-src" in kinds


def test_missing_base_uri_flagged() -> None:
    issues = evaluate_csp("default-src 'self'; object-src 'none'")
    kinds = [i.kind for i in issues]
    assert "missing-base-uri" in kinds


def test_missing_frame_ancestors_flagged() -> None:
    issues = evaluate_csp("default-src 'self'; object-src 'none'; base-uri 'none'")
    kinds = [i.kind for i in issues]
    assert "no-frame-ancestors" in kinds


def test_strict_csp_no_high_issues() -> None:
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'nonce-abc'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    issues = evaluate_csp(csp)
    high = [i for i in issues if i.severity == "HIGH"]
    assert high == []


def test_evaluate_csp_returns_list_of_cspissue() -> None:
    issues = evaluate_csp("default-src *")
    assert all(isinstance(i, CspIssue) for i in issues)
