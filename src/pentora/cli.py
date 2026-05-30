"""Click-based CLI entry point for Pentora."""
from __future__ import annotations

from pathlib import Path

import click

from pentora.version import __version__


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
def scan(
    url: str,
    output: str,
    phases: str,
    scope_include: str,
    scope_exclude: str,
    token_a: str | None,
    token_b: str | None,
    profile: str,
    dry_run: bool = False,
) -> None:
    """Run a full pentest scan against URL."""
    import asyncio
    from urllib.parse import urlparse

    from pentora.config import load_config
    from pentora.context import ScanContext
    from pentora.modules.base import PhaseModule
    from pentora.modules.recon import ReconModule
    from pentora.orchestrator import Orchestrator
    from pentora.reporters.base import Reporter
    from pentora.reporters.finding_folder import FindingFolderReporter
    from pentora.reporters.html import HtmlReporter
    from pentora.reporters.json_reporter import JsonReporter
    from pentora.reporters.markdown import MarkdownReporter
    from pentora.scope import Scope

    # Default scope: derive from URL if --scope-include is empty
    if not scope_include:
        host = urlparse(url).hostname or url
        root = ".".join(host.split(".")[-2:])
        include = [root, f"*.{root}"]
    else:
        include = [s.strip() for s in scope_include.split(",") if s.strip()]
    exclude = [s.strip() for s in scope_exclude.split(",") if s.strip()]

    cfg = load_config()
    ctx = ScanContext(
        target=url,
        output_dir=Path(output),
        config=cfg,
        scope=Scope(include=include, exclude=exclude),
        profile_name=profile,
        token_a=token_a,
        token_b=token_b,
    )

    phase_map: dict[str, type[PhaseModule]] = {"recon": ReconModule}
    requested = [p.strip() for p in phases.split(",") if p.strip()]
    if "all" in requested:
        requested = list(phase_map.keys())

    if dry_run:
        click.echo("=== DRY RUN ===")
        click.echo(f"Target: {url}")
        click.echo(f"Output: {output}")
        click.echo(f"Scope include: {include}")
        click.echo(f"Scope exclude: {exclude}")
        click.echo(f"Phases: {requested}")
        click.echo(f"Profile: {profile}")
        click.echo("Reporters: json, markdown, html, finding_folder")
        return

    modules: list[PhaseModule] = [phase_map[p]() for p in requested if p in phase_map]

    reporters: list[Reporter] = [
        JsonReporter(),
        MarkdownReporter(),
        HtmlReporter(),
        FindingFolderReporter(),
    ]
    orc = Orchestrator(modules=modules, reporters=reporters)
    asyncio.run(orc.run(ctx))
    click.echo(f"Scan complete. Reports written to {output}/")


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
    click.echo("[stub] list-modules")
