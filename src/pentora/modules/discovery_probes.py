"""Built-in HTTP probes for content discovery (swagger, graphql, backup, vcs, env)."""
from __future__ import annotations

from dataclasses import dataclass

import httpx

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.yaml", "/openapi.json", "/api/docs",
    "/api-docs", "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
BACKUP_PATTERNS = [".bak", ".old", ".swp", "~", ".save", ".orig"]
VCS_PATHS = ["/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/store/00manifest.i"]
ENV_PATHS = ["/.env", "/.env.local", "/.env.production", "/.env.development"]

# Status codes treated as a positive hit (resource exists / is protected but present).
HIT_STATUSES = frozenset({200, 401, 403, 206})

# Minimal GraphQL introspection query used to confirm the schema is exposed.
_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


@dataclass
class DiscoveryHit:
    url: str
    kind: str
    evidence: str


async def probe_paths(
    client: httpx.AsyncClient, base_url: str, paths: list[str], kind: str
) -> list[DiscoveryHit]:
    """GET each path under base_url; a hit is any HIT_STATUSES response."""
    base = base_url.rstrip("/")
    hits: list[DiscoveryHit] = []
    for path in paths:
        url = f"{base}{path}"
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code in HIT_STATUSES:
            hits.append(DiscoveryHit(url=url, kind=kind, evidence=f"HTTP {resp.status_code}"))
    return hits


async def probe_swagger(client: httpx.AsyncClient, base_url: str) -> list[DiscoveryHit]:
    return await probe_paths(client, base_url, SWAGGER_PATHS, "swagger")


async def probe_vcs(client: httpx.AsyncClient, base_url: str) -> list[DiscoveryHit]:
    return await probe_paths(client, base_url, VCS_PATHS, "vcs")


async def probe_env(client: httpx.AsyncClient, base_url: str) -> list[DiscoveryHit]:
    return await probe_paths(client, base_url, ENV_PATHS, "env")


async def probe_graphql(client: httpx.AsyncClient, base_url: str) -> list[DiscoveryHit]:
    """Detect GraphQL endpoints and whether introspection is enabled."""
    base = base_url.rstrip("/")
    hits = await probe_paths(client, base_url, GRAPHQL_PATHS, "graphql")
    for path in GRAPHQL_PATHS:
        url = f"{base}{path}"
        try:
            resp = await client.post(url, json=_INTROSPECTION_QUERY)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and "__schema" in resp.text:
            hits.append(
                DiscoveryHit(url=url, kind="graphql", evidence="GraphQL introspection enabled")
            )
    return hits


async def probe_all(client: httpx.AsyncClient, base_url: str) -> list[DiscoveryHit]:
    """Run every built-in probe against a single base URL."""
    hits: list[DiscoveryHit] = []
    hits.extend(await probe_swagger(client, base_url))
    hits.extend(await probe_graphql(client, base_url))
    hits.extend(await probe_vcs(client, base_url))
    hits.extend(await probe_env(client, base_url))
    return hits
