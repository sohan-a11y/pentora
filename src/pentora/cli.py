"""Click-based CLI entry point for Pentora."""
from __future__ import annotations

from pathlib import Path

import click

from pentora.modules.auth import AuthModule
from pentora.modules.authz import AuthzModule
from pentora.modules.base import PhaseModule
from pentora.modules.cloud import CloudModule
from pentora.modules.cors import CorsModule
from pentora.modules.disclosure import DisclosureModule
from pentora.modules.discovery import DiscoveryModule
from pentora.modules.headers import HeadersModule
from pentora.modules.injection import InjectionModule
from pentora.modules.logic import LogicModule
from pentora.modules.mobile import MobileModule
from pentora.modules.ratelimit import RateLimitModule
from pentora.modules.recon import ReconModule
from pentora.modules.ssrf import SsrfModule
from pentora.modules.takeover import TakeoverModule
from pentora.modules.transport import TransportModule
from pentora.modules.upload import UploadModule
from pentora.version import __version__

# Registry of available phase modules, keyed by phase name (used by `scan` and `list-modules`).
PHASE_MAP: dict[str, type[PhaseModule]] = {
    "recon": ReconModule,
    "discovery": DiscoveryModule,
    "auth": AuthModule,
    "authz": AuthzModule,
    "injection": InjectionModule,
    "upload": UploadModule,
    "ssrf": SsrfModule,
    "logic": LogicModule,
    "disclosure": DisclosureModule,
    "transport": TransportModule,
    "headers": HeadersModule,
    "cors": CorsModule,
    "takeover": TakeoverModule,
    "ratelimit": RateLimitModule,
    "mobile": MobileModule,
    "cloud": CloudModule,
}


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, prog_name="pentora")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Pentora — autonomous web application pentest orchestrator."""


@main.command()
@click.argument("url")
@click.option("--output", "-o", type=click.Path(), default="./pentora-out", help="Output directory")
@click.option("--phases", default="recon", help="Comma-separated phase names (or 'all')")
@click.option("--scope-include", default="", help="Comma-separated in-scope hosts/wildcards")
@click.option("--scope-exclude", default="", help="Comma-separated excluded hosts")
@click.option("--token-a", default=None)
@click.option("--token-b", default=None)
@click.option("--profile", default="generic")
@click.option("--dry-run", is_flag=True, help="Print the plan and exit without scanning")
@click.option(
    "--proxy",
    type=click.Choice(["burp", "zap", "none", "auto"]),
    default="none",
    help="Route traffic through Burp (1337) or ZAP (8090); auto-detects",
)
@click.option("--ai-mode", is_flag=True, help="Enable LLM-powered modules")
@click.option(
    "--llm-provider",
    type=click.Choice(["ollama", "openrouter", "nvidia", "last"]),
    default=None,
    help="LLM provider for AI modules",
)
@click.option("--llm-model", default=None, help="LLM model name")
@click.option("--no-sanitize-llm", is_flag=True, help="Disable PII stripping in LLM prompts")
@click.option("--apk", default=None, type=click.Path(), help="Path to Android APK for mobile analysis")  # noqa: E501
def scan(  # noqa: PLR0913
    url: str,
    output: str,
    phases: str,
    scope_include: str,
    scope_exclude: str,
    token_a: str | None,
    token_b: str | None,
    profile: str,
    dry_run: bool = False,
    proxy: str = "none",
    ai_mode: bool = False,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    no_sanitize_llm: bool = False,
    apk: str | None = None,
) -> None:
    """Run a full pentest scan against URL."""
    import asyncio
    from urllib.parse import urlparse

    from pentora.config import load_config
    from pentora.context import ScanContext
    from pentora.orchestrator import Orchestrator
    from pentora.proxy.base import ProxyClient
    from pentora.reporters.base import Reporter
    from pentora.reporters.finding_folder import FindingFolderReporter
    from pentora.reporters.html import HtmlReporter
    from pentora.reporters.json_reporter import JsonReporter
    from pentora.reporters.markdown import MarkdownReporter
    from pentora.scope import Scope

    if ai_mode and llm_provider is None:
        raise click.UsageError(  # noqa: E501
            "--ai-mode requires --llm-provider (ollama, openrouter, nvidia, last)"
        )

    # Default scope: derive from URL if --scope-include is empty
    if not scope_include:
        host = urlparse(url).hostname or url
        root = ".".join(host.split(".")[-2:])
        include = [root, f"*.{root}"]
    else:
        include = [s.strip() for s in scope_include.split(",") if s.strip()]
    exclude = [s.strip() for s in scope_exclude.split(",") if s.strip()]

    extra: dict[str, object] = {}
    if apk is not None:
        extra["apk_path"] = apk

    cfg = load_config()
    ctx = ScanContext(
        target=url,
        output_dir=Path(output),
        config=cfg,
        scope=Scope(include=include, exclude=exclude),
        profile_name=profile,
        token_a=token_a,
        token_b=token_b,
        extra=extra,
    )

    requested = [p.strip() for p in phases.split(",") if p.strip()]
    if "all" in requested:
        requested = list(PHASE_MAP.keys())

    if dry_run:
        click.echo("=== DRY RUN ===")
        click.echo(f"Target: {url}")
        click.echo(f"Output: {output}")
        click.echo(f"Scope include: {include}")
        click.echo(f"Scope exclude: {exclude}")
        click.echo(f"Phases: {requested}")
        click.echo(f"Profile: {profile}")
        click.echo(f"Proxy: {proxy}")
        click.echo(f"AI mode: {ai_mode}")
        click.echo("Reporters: json, markdown, html, finding_folder")
        return

    modules: list[PhaseModule] = [PHASE_MAP[p]() for p in requested if p in PHASE_MAP]

    # Resolve proxy client (returns BurpClient | ZapClient | None)
    resolved = _resolve_proxy_client(proxy)
    proxy_client: ProxyClient | None = resolved if isinstance(resolved, ProxyClient) else None  # type: ignore[misc]

    reporters: list[Reporter] = [
        JsonReporter(),
        MarkdownReporter(),
        HtmlReporter(),
        FindingFolderReporter(),
    ]
    orc = Orchestrator(modules=modules, reporters=reporters, proxy_client=proxy_client)
    asyncio.run(orc.run(ctx))
    click.echo(f"Scan complete. Reports written to {output}/")


def _resolve_proxy_client(proxy: str) -> object:
    """Resolve --proxy flag to a ProxyClient-compatible object or None."""
    import asyncio

    from pentora.proxy.burp import BurpClient
    from pentora.proxy.zap import ZapClient

    if proxy == "none":
        return None

    if proxy == "burp":
        burp = BurpClient()
        if not asyncio.run(burp.is_alive()):
            click.echo("[warn] Burp REST API not reachable at 1337 — scanning without proxy")
            return None
        return burp

    if proxy == "zap":
        zap = ZapClient()
        if not asyncio.run(zap.is_alive()):
            click.echo("[warn] ZAP not reachable at 8090 — scanning without proxy")
            return None
        return zap

    # auto: probe Burp then ZAP
    burp = BurpClient()
    if asyncio.run(burp.is_alive()):
        return burp
    zap_auto = ZapClient()
    if asyncio.run(zap_auto.is_alive()):
        return zap_auto
    click.echo("[info] No proxy detected (auto) — scanning without proxy")
    return None


@main.command()
def setup() -> None:
    """Install all required tools on Kali."""
    click.echo("[stub] setup")


@main.command()
def doctor() -> None:
    """Diagnose missing tools and misconfigurations."""
    click.echo("[stub] doctor")


@main.command()
def update() -> None:
    """Update nuclei templates, wordlists, fingerprints."""
    click.echo("[stub] update")


@main.command()
@click.argument("findings_db", type=click.Path(exists=True))
def report(findings_db: str) -> None:
    """Regenerate reports from an existing findings DB."""
    click.echo(f"[stub] report {findings_db}")


@main.command("import-results")
@click.argument("source", type=click.Choice(["burp", "zap"]))
@click.argument("path", type=click.Path(exists=True))
def import_results(source: str, path: str) -> None:
    """Import an external scanner's results into Pentora's store."""
    click.echo(f"[stub] import {source} {path}")


@main.command("list-profiles")
def list_profiles() -> None:
    """List available profiles (dating, saas, fintech, ...)."""
    click.echo("[stub] list-profiles")


@main.command("list-modules")
def list_modules() -> None:
    """List available phase modules."""
    for key in PHASE_MAP:
        click.echo(key)
