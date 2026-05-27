"""Click-based CLI entry point for Pentora."""
from __future__ import annotations

import click

from pentora.version import __version__


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, prog_name="pentora")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Pentora — autonomous web application pentest orchestrator."""


@main.command()
@click.argument("url")
def scan(url: str) -> None:
    """Run a full pentest scan against URL."""
    click.echo(f"[stub] scan {url}")


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
