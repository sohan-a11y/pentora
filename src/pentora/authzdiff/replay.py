"""Live replay of authzdiff cases against an authorized target.

The :class:`ReplayHook` protocol decouples verdict logic from transport so
tests can inject a fake. The default hook uses httpx (already a Pentora
dependency). Every case is replayed twice: once as the caller role and once as
a control under the owner role — a 2xx only counts as a finding when the
control principal also succeeds, which rules out "endpoint simply broken".
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Any, Protocol

import httpx

from pentora.authzdiff.matrix import AuthzCase, Role

BODY_SNIPPET_CHARS = 200


@dataclass(frozen=True)
class ReplayResult:
    status_code: int
    body_snippet: str


class ReplayHook(Protocol):
    """Send one case and return the observed response."""

    def send(self, case: AuthzCase) -> ReplayResult: ...


class HttpxReplayHook:
    """ReplayHook implementation over httpx (sync client)."""

    def __init__(
        self,
        base_url: str,
        roles: list[Role],
        *,
        param_values: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers_by_role = {r.name: r.headers for r in roles}
        self._param_values = param_values or {}
        self._timeout = timeout

    def send(self, case: AuthzCase) -> ReplayResult:
        headers = dict(self._headers_by_role.get(case.caller, {}))
        url = self._base_url + self._fill_params(case.path)
        with httpx.Client(follow_redirects=True, timeout=self._timeout) as client:
            resp = client.request(case.method.lower(), url, headers=headers)
        return ReplayResult(
            status_code=resp.status_code,
            body_snippet=resp.text[:BODY_SNIPPET_CHARS],
        )

    def _fill_params(self, path: str) -> str:
        # Template params default to "1"; override via param_values.
        filled = path
        for token in set(_template_params(path)) - set(self._param_values):
            filled = filled.replace("{" + token + "}", "1")
        for token, value in self._param_values.items():
            filled = filled.replace("{" + token + "}", value)
        return filled


def _template_params(path: str) -> list[str]:
    params: list[str] = []
    start = 0
    while True:
        opening = path.find("{", start)
        if opening == -1:
            break
        closing = path.find("}", opening)
        if closing == -1:
            break
        params.append(path[opening + 1 : closing])
        start = closing + 1
    return params


class Verdict(enum.Enum):
    CRITICAL_FINDING = "critical_finding"
    EXPECTED_DENY = "expected_deny"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    method: str
    path: str
    caller: str
    status_code: int
    control_status: int
    verdict: Verdict
    body_snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "method": self.method,
            "path": self.path,
            "caller": self.caller,
            "status_code": self.status_code,
            "control_status": self.control_status,
            "verdict": self.verdict.value,
        }


def classify(case_result: ReplayResult, control_result: ReplayResult | None = None) -> Verdict:
    """Classify a foreign-access response.

    2xx on foreign access is a finding only when the control principal (owner
    role) also gets a 2xx; otherwise the endpoint state is unknown and the
    result is inconclusive.
    """
    status = case_result.status_code
    if 200 <= status < 300:
        if control_result is not None and not 200 <= control_result.status_code < 300:
            return Verdict.INCONCLUSIVE
        return Verdict.CRITICAL_FINDING
    if status in (403, 404):
        return Verdict.EXPECTED_DENY
    return Verdict.INCONCLUSIVE


def run_live(cases: list[AuthzCase], hook: ReplayHook) -> list[CaseResult]:
    """Replay every case with its owner role as control principal."""
    results: list[CaseResult] = []
    for case in cases:
        observed = hook.send(case)
        control_case = replace(case, caller=case.owner)
        control = hook.send(control_case)
        results.append(
            CaseResult(
                case_id=case.case_id,
                method=case.method,
                path=case.path,
                caller=case.caller,
                status_code=observed.status_code,
                control_status=control.status_code,
                verdict=classify(observed, control),
                body_snippet=observed.body_snippet,
            )
        )
    return results
