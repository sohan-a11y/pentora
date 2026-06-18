from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import Severity
from pentora.modules.auth import DEFAULT_AUTH_CFG, AuthModule
from pentora.scope import Scope
from pentora.wrappers.jwt_tool import JwtAttackResult


def _ctx(
    tmp_path: Path, profile_cfg: dict | None = None, token_a: str | None = None
) -> ScanContext:
    cfg = Config()
    if profile_cfg is not None:
        cfg.profiles["generic"] = profile_cfg
    return ScanContext(
        target="https://t.example",
        output_dir=tmp_path,
        config=cfg,
        scope=Scope(include=["t.example"]),
        token_a=token_a,
    )


def _auth_cfg(**overrides: object) -> dict[str, object]:
    cfg = dict(DEFAULT_AUTH_CFG)
    cfg.update(overrides)
    return cfg


@pytest.mark.asyncio
@respx.mock
async def test_rate_limit_check_flags_missing_throttle(tmp_path: Path) -> None:
    respx.post("https://t.example/login").mock(return_value=httpx.Response(401))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_rate_limit(client, "https://t.example", _auth_cfg())
    assert len(findings) == 1
    assert "rate limit" in findings[0].title.lower()
    assert findings[0].severity in (Severity.MEDIUM, Severity.HIGH)


@pytest.mark.asyncio
@respx.mock
async def test_rate_limit_check_silent_when_429_returned(tmp_path: Path) -> None:
    respx.post("https://t.example/login").mock(return_value=httpx.Response(429))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_rate_limit(client, "https://t.example", _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_rate_limit_check_skips_nonexistent_login(tmp_path: Path) -> None:
    """No false positive when /login does not exist (404) — regression."""
    respx.post("https://t.example/login").mock(return_value=httpx.Response(404))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_rate_limit(client, "https://t.example", _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_rate_limit_check_skips_method_not_allowed(tmp_path: Path) -> None:
    """No false positive when /login rejects POST (405)."""
    respx.post("https://t.example/login").mock(return_value=httpx.Response(405))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_rate_limit(client, "https://t.example", _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_enumeration_check_flags_timing_delta(tmp_path: Path) -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "existing@test.com" in body:
            return httpx.Response(401, text="x" * 5000)
        return httpx.Response(401, text="x")

    respx.post("https://t.example/login").mock(side_effect=responder)
    module = AuthModule()
    # Inject a clock that reports a big delta for the "existing" user batch.
    calls = {"n": 0}

    def fake_clock() -> float:
        calls["n"] += 1
        # odd call = start (t=0), even call = stop. First 3 pairs slow, next 3 fast.
        idx = calls["n"]
        pair = (idx - 1) // 2
        is_stop = idx % 2 == 0
        if not is_stop:
            return 0.0
        return 0.5 if pair < 3 else 0.01

    async with httpx.AsyncClient() as client:
        findings = await module.check_enumeration(
            client, "https://t.example", _auth_cfg(), clock=fake_clock
        )
    assert len(findings) == 1
    assert "enumeration" in findings[0].title.lower()
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
@respx.mock
async def test_password_reset_same_token_is_flagged(tmp_path: Path) -> None:
    respx.post("https://t.example/forgot-password").mock(
        return_value=httpx.Response(200, json={"token": "static-token-123"})
    )
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_password_reset(client, "https://t.example", _auth_cfg())
    assert len(findings) == 1
    assert "reset" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_password_reset_distinct_tokens_not_flagged(tmp_path: Path) -> None:
    tokens = iter(["tok-a", "tok-b"])
    respx.post("https://t.example/forgot-password").mock(
        side_effect=lambda req: httpx.Response(200, json={"token": next(tokens)})
    )
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_password_reset(client, "https://t.example", _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_cookie_flags_missing_secure_httponly(tmp_path: Path) -> None:
    respx.get("https://t.example/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": "session=abc; Path=/"})
    )
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_cookie_flags(client, "https://t.example", _auth_cfg())
    titles = " ".join(f.title.lower() for f in findings)
    assert "secure" in titles
    assert "httponly" in titles
    assert all(f.severity in (Severity.LOW, Severity.MEDIUM) for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_cookie_flags_all_present_no_findings(tmp_path: Path) -> None:
    respx.get("https://t.example/").mock(
        return_value=httpx.Response(
            200,
            headers={"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"},
        )
    )
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_cookie_flags(client, "https://t.example", _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
async def test_jwt_check_runs_tool_and_flags_critical(tmp_path: Path) -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    module = AuthModule()
    with patch("pentora.modules.auth.JwtToolWrapper") as Jwt:
        Jwt.return_value.run = AsyncMock(
            return_value=[
                JwtAttackResult(attack="alg-none", vulnerable=True, evidence="forged token"),
            ]
        )
        findings = await module.check_jwt(tmp_path, token, _auth_cfg())
    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert "jwt" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_jwt_check_no_token_returns_empty(tmp_path: Path) -> None:
    module = AuthModule()
    findings = await module.check_jwt(tmp_path, None, _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_otp_check_disabled_without_allow_brute(tmp_path: Path) -> None:
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_otp(
            client, "https://t.example", _auth_cfg(allow_brute=False, otp_endpoint_discovered=True)
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_otp_check_finds_weak_otp_when_allowed(tmp_path: Path) -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if '"0002"' in request.content.decode():
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(401)

    respx.post("https://t.example/verify-otp").mock(side_effect=responder)
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_otp(
            client,
            "https://t.example",
            _auth_cfg(
                allow_brute=True,
                otp_endpoint_discovered=True,
                otp_length=4,
                otp_limit=10,
            ),
        )
    assert len(findings) == 1
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert "otp" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_session_check_flags_token_valid_after_logout(tmp_path: Path) -> None:
    respx.get("https://t.example/me").mock(return_value=httpx.Response(200, json={"id": 1}))
    respx.post("https://t.example/logout").mock(return_value=httpx.Response(200))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_session(
            client, "https://t.example", "bearer-token", _auth_cfg()
        )
    assert len(findings) == 1
    assert "logout" in findings[0].title.lower()
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
@respx.mock
async def test_session_check_no_finding_when_token_revoked(tmp_path: Path) -> None:
    responses = iter([httpx.Response(200, json={"id": 1}), httpx.Response(401)])
    respx.get("https://t.example/me").mock(side_effect=lambda req: next(responses))
    respx.post("https://t.example/logout").mock(return_value=httpx.Response(200))
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_session(
            client, "https://t.example", "bearer-token", _auth_cfg()
        )
    assert findings == []


@pytest.mark.asyncio
async def test_session_check_no_token_returns_empty(tmp_path: Path) -> None:
    module = AuthModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_session(client, "https://t.example", None, _auth_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_jwt_extracted_from_bearer_token_in_run(tmp_path: Path) -> None:
    token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    ctx = _ctx(tmp_path, token_a=token)
    await ctx.prepare()
    respx.route().mock(return_value=httpx.Response(404))
    with patch("pentora.modules.auth.JwtToolWrapper") as Jwt:
        Jwt.return_value.run = AsyncMock(
            return_value=[
                JwtAttackResult(attack="alg-none", vulnerable=True, evidence="forged token"),
            ]
        )
        findings = await AuthModule().run(ctx)
    assert any(f.module == "auth.jwt" for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_run_aggregates_and_persists(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    # Login: 401 (no rate limit), same-length bodies (no enumeration).
    respx.post("https://t.example/login").mock(return_value=httpx.Response(401, text="nope"))
    respx.post("https://t.example/forgot-password").mock(return_value=httpx.Response(404))
    respx.get("https://t.example/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": "s=1; Path=/"})
    )
    respx.route().mock(return_value=httpx.Response(404))

    findings = await AuthModule().run(ctx)
    assert ctx.store is not None
    stored = await ctx.store.all()
    stored_modules = {f.module for f in stored}
    # At least the no-rate-limit and cookie findings should be present and persisted.
    modules = {f.module for f in findings}
    assert any("auth.rate_limit" in m for m in modules)
    assert any("auth.cookie" in m for m in modules)
    assert any("auth.rate_limit" in m for m in stored_modules)
