# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd health command."""

from __future__ import annotations

import asyncio
import logging

import click

from pkg_defender.cli.common import _health_impl
from pkg_defender.cli.main import cli

logger = logging.getLogger(__name__)


@cli.command(name="health")
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["json", "rich"]),
    default="rich",
    help="Output format: 'json' for JSON, 'rich' for formatted output (default: rich). "
    "Examples: pkgd health -o json > output.json",
)
@click.option(
    "-p",
    "--pretty",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (when using --output json)",
)
@click.option(
    "--verbose",
    "-v",
    "verbose",
    is_flag=True,
    default=False,
    help="Show detailed diagnostics: adapter coverage matrix, threat counts, feed status, and timestamp sources.",
)
@click.pass_context
def health(
    ctx: click.Context,
    output_format: str,
    pretty_output: bool,
    verbose: bool,
) -> None:
    """Check system health status.

    Runs diagnostic checks to verify the system is working correctly:
    - Config file existence and accessibility
    - Database existence and connectivity
    - WAL mode enabled for SQLite
    - OSV feed sync status
    - Per-feed configuration status
    - API token validity (GitHub, Socket.dev, X/Twitter)
    - Disk space at data directory
    - File permissions for config and database

    Use --verbose/-v to show additional diagnostics:
    - Adapter coverage matrix (coverage tier, threat counts, cooldown status per ecosystem)
    - Feed implementation status (active, needs API key, or disabled)
    - Timestamp sources (proxied vs verified)

    Returns exit code 0 if all checks pass, exit code 1 if any fail.

    Examples:

    \b
        pkgd health
        pkgd health -o json
        pkgd health --output json --pretty
        pkgd health || echo "Health check failed"
        pkgd health -v
        pkgd health --verbose
        pkgd health --verbose -o json

    EXIT CODES:
        0    All checks passed
        1    One or more checks failed

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml
        ~/.local/share/pkg-defender/threats.db    Database

    \f
    """
    # CI mode auto-enables JSON output
    logger.debug("Health check invoked: format=%s, verbose=%s", output_format, verbose)
    output_format = ctx.obj.get("output_format") or output_format
    return asyncio.run(_health_impl(ctx, output_format, pretty_output, verbose))
