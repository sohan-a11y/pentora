from pathlib import Path

import httpx
import pytest
import respx

from pentora.config import Config
from pentora.context import ScanContext
from pentora.finding import CVSS, Finding, Severity
from pentora.modules.authz import DEFAULT_AUTHZ_CFG, AuthzModule
from pentora.scope import Scope


def _ctx(
    tmp_path: Path,
    token_a: str | None = "tok-a",
    token_b: str | None = "tok-b",
    profile_cfg: dict | None = None,
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
        token_b=token_b,
    )


def _authz_cfg(**overrides: object) -> dict[str, object]:
    cfg = dict(DEFAULT_AUTHZ_CFG)
    cfg.update(overrides)
    return cfg


def _finding(endpoint: str, **extra: object) -> Finding:
    return Finding(
        module="discovery.endpoint",
        title="t",
        endpoint=endpoint,
        method="GET",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        extra=dict(extra),
    )


@pytest.mark.asyncio
async def test_run_returns_empty_without_both_tokens(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, token_b=None)
    await ctx.prepare()
    findings = await AuthzModule().run(ctx)
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_idor_numeric_neighbor_accessible(tmp_path: Path) -> None:
    # token A can read /users/1 (its own) AND /users/2 (a neighbor) — IDOR.
    respx.get("https://t.example/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1, "ssn": "111-11-1111"})
    )
    respx.get("https://t.example/users/2").mock(
        return_value=httpx.Response(200, json={"id": 2, "ssn": "222-22-2222"})
    )
    respx.route().mock(return_value=httpx.Response(404))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_idor(
            client, "https://t.example/users/1", "tok-a", _authz_cfg()
        )
    assert len(findings) >= 1
    assert findings[0].severity in (Severity.MEDIUM, Severity.HIGH)
    assert "idor" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_idor_neighbor_forbidden_no_finding(tmp_path: Path) -> None:
    respx.get("https://t.example/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1})
    )
    respx.route().mock(return_value=httpx.Response(403))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_idor(
            client, "https://t.example/users/1", "tok-a", _authz_cfg()
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_idor_uuid_swap(tmp_path: Path) -> None:
    a_id = "11111111-1111-1111-1111-111111111111"
    b_id = "22222222-2222-2222-2222-222222222222"
    respx.get(f"https://t.example/profile/{a_id}").mock(
        return_value=httpx.Response(200, json={"id": a_id})
    )
    respx.get(f"https://t.example/profile/{b_id}").mock(
        return_value=httpx.Response(200, json={"id": b_id})
    )
    respx.route().mock(return_value=httpx.Response(404))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_idor(
            client,
            f"https://t.example/profile/{a_id}",
            "tok-a",
            _authz_cfg(uuid_b=b_id),
        )
    assert any("idor" in f.title.lower() for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_bola_diff_flags_leaked_data(tmp_path: Path) -> None:
    body = '{"id": 2, "name": "victim", "email": "victim@example.com"}'
    # token A fetching B's resource returns B's data (similar to B's legit response).
    respx.get("https://t.example/orders/2").mock(return_value=httpx.Response(200, text=body))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_bola(
            client, "https://t.example/orders/2", "tok-a", "tok-b", _authz_cfg()
        )
    assert len(findings) == 1
    assert "bola" in findings[0].title.lower() or "idor" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_bola_distinct_responses_no_finding(tmp_path: Path) -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if "tok-a" in auth:
            return httpx.Response(403, text='{"error": "forbidden, not your order at all"}')
        return httpx.Response(200, text='{"id": 2, "name": "victim", "secret": "zzzzzzzz"}')

    respx.get("https://t.example/orders/2").mock(side_effect=responder)
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_bola(
            client, "https://t.example/orders/2", "tok-a", "tok-b", _authz_cfg()
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_bfla_admin_path_accessible(tmp_path: Path) -> None:
    respx.get("https://t.example/admin/users").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    respx.route().mock(return_value=httpx.Response(403))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_bfla(client, "https://t.example", "tok-a", _authz_cfg())
    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert "bfla" in findings[0].title.lower() or "admin" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_bfla_admin_forbidden_no_finding(tmp_path: Path) -> None:
    respx.route().mock(return_value=httpx.Response(403))
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_bfla(client, "https://t.example", "tok-a", _authz_cfg())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_mass_assignment_reflected_privileged_field(tmp_path: Path) -> None:
    respx.put("https://t.example/me").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/me").mock(
        return_value=httpx.Response(200, json={"id": 1, "role": "admin", "isPremium": True})
    )
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_mass_assignment(
            client, "https://t.example", "tok-a", _authz_cfg()
        )
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "mass" in findings[0].title.lower() or "assignment" in findings[0].title.lower()


@pytest.mark.asyncio
@respx.mock
async def test_mass_assignment_not_reflected_no_finding(tmp_path: Path) -> None:
    respx.put("https://t.example/me").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/me").mock(
        return_value=httpx.Response(200, json={"id": 1, "role": "user"})
    )
    module = AuthzModule()
    async with httpx.AsyncClient() as client:
        findings = await module.check_mass_assignment(
            client, "https://t.example", "tok-a", _authz_cfg()
        )
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_run_aggregates_and_persists(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    await ctx.prepare()
    assert ctx.store is not None
    await ctx.store.add(_finding("https://t.example/users/1"))

    respx.get("https://t.example/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1, "ssn": "111"})
    )
    respx.get("https://t.example/users/2").mock(
        return_value=httpx.Response(200, json={"id": 2, "ssn": "222"})
    )
    respx.put("https://t.example/me").mock(return_value=httpx.Response(403))
    respx.route().mock(return_value=httpx.Response(403))

    findings = await module_run(ctx)
    stored = await ctx.store.all()
    stored_modules = {f.module for f in stored}
    assert any(m.startswith("authz") for m in {f.module for f in findings})
    assert any(m.startswith("authz") for m in stored_modules)


async def module_run(ctx: ScanContext) -> list[Finding]:
    return await AuthzModule().run(ctx)
