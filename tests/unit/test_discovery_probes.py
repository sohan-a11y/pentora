import httpx
import pytest
import respx

from pentora.modules.discovery_probes import (
    DiscoveryHit,
    probe_all,
    probe_env,
    probe_graphql,
    probe_paths,
    probe_swagger,
    probe_vcs,
)


@pytest.mark.asyncio
@respx.mock
async def test_probe_swagger_detects_exposed_spec() -> None:
    respx.get("https://t.example/swagger.json").mock(
        return_value=httpx.Response(200, text='{"swagger": "2.0"}')
    )
    # Everything else 404
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_swagger(client, "https://t.example")
    assert any(h.kind == "swagger" and h.url.endswith("/swagger.json") for h in hits)


@pytest.mark.asyncio
@respx.mock
async def test_probe_env_detects_env_file() -> None:
    respx.get("https://t.example/.env").mock(
        return_value=httpx.Response(200, text="SECRET_KEY=abc123")
    )
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_env(client, "https://t.example")
    assert len(hits) == 1
    assert hits[0] == DiscoveryHit(
        url="https://t.example/.env", kind="env", evidence="HTTP 200"
    )


@pytest.mark.asyncio
@respx.mock
async def test_probe_vcs_detects_git_config() -> None:
    respx.get("https://t.example/.git/config").mock(
        return_value=httpx.Response(200, text="[core]\n")
    )
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_vcs(client, "https://t.example")
    assert any(h.url.endswith("/.git/config") and h.kind == "vcs" for h in hits)


@pytest.mark.asyncio
@respx.mock
async def test_probe_graphql_detects_endpoint() -> None:
    respx.get("https://t.example/graphql").mock(return_value=httpx.Response(400))
    respx.post("https://t.example/graphql").mock(
        return_value=httpx.Response(200, json={"data": {"__schema": {"types": []}}})
    )
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_graphql(client, "https://t.example")
    assert any(h.kind == "graphql" for h in hits)
    introspection = [h for h in hits if "introspection" in h.evidence.lower()]
    assert introspection


@pytest.mark.asyncio
@respx.mock
async def test_probe_paths_treats_404_as_miss() -> None:
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_paths(client, "https://t.example", ["/nope"], "swagger")
    assert hits == []


@pytest.mark.asyncio
@respx.mock
async def test_probe_paths_403_counts_as_hit() -> None:
    respx.get("https://t.example/forbidden").mock(return_value=httpx.Response(403))
    async with httpx.AsyncClient() as client:
        hits = await probe_paths(client, "https://t.example", ["/forbidden"], "vcs")
    assert len(hits) == 1
    assert hits[0].evidence == "HTTP 403"


@pytest.mark.asyncio
@respx.mock
async def test_probe_paths_handles_connection_error() -> None:
    respx.get("https://t.example/boom").mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        hits = await probe_paths(client, "https://t.example", ["/boom"], "env")
    assert hits == []


@pytest.mark.asyncio
@respx.mock
async def test_probe_graphql_post_error_is_ignored() -> None:
    respx.get("https://t.example/graphql").mock(return_value=httpx.Response(404))
    respx.post("https://t.example/graphql").mock(side_effect=httpx.ConnectError("down"))
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_graphql(client, "https://t.example")
    assert hits == []


@pytest.mark.asyncio
@respx.mock
async def test_probe_all_aggregates_every_kind() -> None:
    respx.get("https://t.example/swagger.json").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/.env").mock(return_value=httpx.Response(200))
    respx.get("https://t.example/.git/config").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        hits = await probe_all(client, "https://t.example")
    kinds = {h.kind for h in hits}
    assert {"swagger", "env", "vcs"} <= kinds
