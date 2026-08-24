from pentora.authzdiff.matrix import AuthzCase, Role
from pentora.authzdiff.replay import (
    HttpxReplayHook,
    ReplayResult,
    Verdict,
    classify,
    run_live,
)


def _case(caller: str = "user", owner: str = "admin") -> AuthzCase:
    return AuthzCase(
        case_id="case-0001",
        method="GET",
        path="/api/users/{id}",
        caller=caller,
        owner=owner,
    )


class FakeHook:
    """Returns a canned status per caller role; records every send."""

    def __init__(self, status_by_caller: dict[str, int]) -> None:
        self.status_by_caller = status_by_caller
        self.calls: list[tuple[str, str]] = []  # (caller, owner)

    def send(self, case: AuthzCase) -> ReplayResult:
        self.calls.append((case.caller, case.owner))
        status = self.status_by_caller.get(case.caller, 500)
        return ReplayResult(status_code=status, body_snippet=f"body-{status}")


def test_classify_2xx_foreign_access_is_critical() -> None:
    assert classify(ReplayResult(200, "data")) is Verdict.CRITICAL_FINDING
    assert classify(ReplayResult(204, "")) is Verdict.CRITICAL_FINDING


def test_classify_deny_statuses_are_expected() -> None:
    assert classify(ReplayResult(403, "forbidden")) is Verdict.EXPECTED_DENY
    assert classify(ReplayResult(404, "not found")) is Verdict.EXPECTED_DENY


def test_classify_other_status_is_inconclusive() -> None:
    assert classify(ReplayResult(500, "oops")) is Verdict.INCONCLUSIVE
    assert classify(ReplayResult(401, "unauth")) is Verdict.INCONCLUSIVE


def test_classify_critical_requires_working_control_principal() -> None:
    broken_control = ReplayResult(500, "endpoint down")
    assert (
        classify(ReplayResult(200, "data"), broken_control) is Verdict.INCONCLUSIVE
    )
    ok_control = ReplayResult(200, "own data")
    assert classify(ReplayResult(200, "foreign data"), ok_control) is Verdict.CRITICAL_FINDING


def test_run_live_replays_caller_and_owner_control() -> None:
    hook = FakeHook({"user": 200, "admin": 200})
    results = run_live([_case()], hook)

    assert len(results) == 1
    result = results[0]
    # Two sends: foreign access as caller, then control as the owner role.
    assert hook.calls == [("user", "admin"), ("admin", "admin")]
    assert result.status_code == 200
    assert result.control_status == 200
    assert result.verdict is Verdict.CRITICAL_FINDING


def test_run_live_expected_deny_and_inconclusive_paths() -> None:
    denied = FakeHook({"user": 403, "admin": 200})
    results = run_live([_case()], denied)
    assert results[0].verdict is Verdict.EXPECTED_DENY

    flaky = FakeHook({"user": 302, "admin": 500})
    results = run_live([_case()], flaky)
    assert results[0].verdict is Verdict.INCONCLUSIVE

    critical_blocked_by_control = FakeHook({"user": 200, "admin": 404})
    results = run_live([_case()], critical_blocked_by_control)
    assert results[0].verdict is Verdict.INCONCLUSIVE


def test_case_result_to_dict_shape() -> None:
    results = run_live([_case()], FakeHook({"user": 404, "admin": 200}))
    payload = results[0].to_dict()
    assert payload["verdict"] == "expected_deny"
    assert payload["caller"] == "user"
    assert payload["control_status"] == 200
    assert "body_snippet" not in payload


def test_hook_fills_template_params_with_defaults_and_overrides() -> None:
    hook = HttpxReplayHook(
        "https://t.example",
        [Role("admin", {}), Role("user", {})],
        param_values={"id": "42"},
    )
    assert hook._fill_params("/api/users/{id}") == "/api/users/42"
    assert hook._fill_params("/a/{x}/b") == "/a/1/b"

    plain = HttpxReplayHook("https://t.example/", [Role("admin", {})])
    assert plain._fill_params("/a/{x}/b") == "/a/1/b"


def test_template_param_extraction() -> None:
    from pentora.authzdiff.replay import _template_params

    assert _template_params("/u/{uid}/posts/{pid}") == ["uid", "pid"]
    assert _template_params("/plain") == []
    assert _template_params("/broken/{unclosed") == []


def test_all_verdict_classes_covered() -> None:
    verdicts = {classify(ReplayResult(s, "")) for s in (200, 403, 404, 500)}
    assert verdicts == {
        Verdict.CRITICAL_FINDING,
        Verdict.EXPECTED_DENY,
        Verdict.INCONCLUSIVE,
    }
