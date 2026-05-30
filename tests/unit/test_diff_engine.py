from pentora.authz.diff_engine import DiffResult, compare_responses


def test_identical_bodies_are_similar() -> None:
    body = '{"id": 1, "name": "alice", "email": "alice@test.com"}'
    result = compare_responses(body, body)
    assert isinstance(result, DiffResult)
    assert result.similar is True
    assert result.ratio == 1.0


def test_near_identical_bodies_above_threshold_are_similar() -> None:
    a = '{"id": 1, "name": "alice", "email": "alice@example.com", "role": "user"}'
    b = '{"id": 2, "name": "alice", "email": "alice@example.com", "role": "user"}'
    result = compare_responses(a, b)
    assert result.similar is True
    assert result.ratio > 0.85


def test_different_bodies_are_not_similar() -> None:
    a = '{"id": 1, "name": "alice", "secret": "aaaaaaaaaaaaaaaaaaaa"}'
    b = '{"error": "403 Forbidden — you do not own this resource"}'
    result = compare_responses(a, b)
    assert result.similar is False
    assert result.ratio < 0.85


def test_diff_contains_unified_diff_lines() -> None:
    a = "line one\nline two\nline three\n"
    b = "line one\nCHANGED\nline three\n"
    result = compare_responses(a, b)
    assert "line two" in result.diff
    assert "CHANGED" in result.diff


def test_empty_bodies_are_similar() -> None:
    result = compare_responses("", "")
    assert result.similar is True
    assert result.ratio == 1.0
