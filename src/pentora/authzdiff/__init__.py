"""authzdiff — OpenAPI-driven cross-principal authorization diff and planner."""
from __future__ import annotations

from pentora.authzdiff.matrix import AuthzCase, Role, build_matrix, load_roles
from pentora.authzdiff.replay import CaseResult, Verdict, classify
from pentora.authzdiff.spec import Endpoint, SpecDiff, load_spec, spec_diff

__all__ = [
    "AuthzCase",
    "CaseResult",
    "Endpoint",
    "Role",
    "SpecDiff",
    "Verdict",
    "build_matrix",
    "classify",
    "load_roles",
    "load_spec",
    "spec_diff",
]
