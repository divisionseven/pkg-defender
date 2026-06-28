"""pkgd status command."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import click

from pkg_defender.cli.common import (
    _get_config_from_context,
    create_table,
    format_json,
    get_db_path,
    init_db,
    is_quiet_mode,
    severity_color,
    stdout_console,
)
from pkg_defender.cli.main import cli

logger = logging.getLogger(__name__)


@cli.command(
    name="status",
    epilog="See also: pkgd health, pkgd intel sync, pkgd intel report, pkgd audit",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["json", "rich"]),
    default="rich",
    help="Output format: 'json' for JSON, 'rich' for formatted output (default: rich). "
    "Examples: pkgd status -o json > output.json",
)
@click.option(
    "--pretty",
    "-p",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (only applies with -o json)",
)
@click.option("--json", "json_flag", is_flag=True, help="Output JSON (same as --output json or -o json)")
@click.option("--feeds", "show_feeds", is_flag=True, help="Show feed-by-feed health status")
@click.pass_context
def status(
    ctx: click.Context,
    output_format: str,
    json_flag: bool,
    pretty_output: bool,
    show_feeds: bool,
) -> None:
    """Show defender status: feeds, bypasses, and threats.

    Displays the health of your threat intelligence feeds, any active bypasses
    (packages that were allowed to bypass cooldown or threat checks), and a
    summary count of threats by severity.

    Use --feeds to see detailed per-feed health information including which
    feeds are properly configured and working.

    Examples:

    \b
        pkgd status
        pkgd status --feeds
        pkgd status -o json

    EXIT CODES:
        0    Success (always)

    ENVIRONMENT:
        NO_COLOR    Disable colored output (standard env var)

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml
        ~/.local/share/pkg-defender/threats.db    Threat database

    \f
    """
    if json_flag:
        output_format = "json"
    # CI mode auto-enables JSON output (--json flag takes priority over CI default)
    output_format = ctx.obj.get("output_format") or output_format

    db_path = get_db_path()
    conn = init_db(db_path)

    try:
        config = _get_config_from_context(ctx)

        now_iso = datetime.now(UTC).isoformat()
        bypass_rows = conn.execute(
            "SELECT package_name, version, reason, expires_at "
            "FROM bypasses "
            "WHERE expires_at IS NULL OR expires_at >= ? "
            "ORDER BY id DESC",
            (now_iso,),
        ).fetchall()

        feed_rows = conn.execute("SELECT feed_name, last_sync, status FROM feed_state ORDER BY feed_name").fetchall()

        feed_error_rows = conn.execute("SELECT feed_name, error_message FROM feed_state ORDER BY feed_name").fetchall()

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM threats "
            "GROUP BY severity "
            "ORDER BY CASE severity "
            "  WHEN 'CRITICAL' THEN 1 "
            "  WHEN 'HIGH' THEN 2 "
            "  WHEN 'MEDIUM' THEN 3 "
            "  WHEN 'LOW' THEN 4 "
            "  ELSE 5 END"
        ).fetchall()

        total_threats = sum(row[1] for row in severity_rows)
    finally:
        conn.close()

    feed_error_lookup = {row[0]: row[1] for row in feed_error_rows}

    logger.debug(
        "Status DB: %d bypasses, %d feeds, %d severity groups", len(bypass_rows), len(feed_rows), len(severity_rows)
    )
    logger.debug("Status output format: %s", output_format)

    if output_format == "json":
        bypasses_list = [
            {
                "package_name": r[0],
                "version": r[1],
                "reason": r[2],
                "expires_at": r[3],
            }
            for r in bypass_rows
        ]
        feeds_list = [
            {
                "feed_name": r[0],
                "last_sync": r[1],
                "status": r[2],
            }
            for r in feed_rows
        ]

        sync_state = "never_synced" if len(feed_rows) == 0 else "synced"

        output: dict[str, Any] = {
            "active_bypasses": bypasses_list,
            "feeds": feeds_list,
            "severity_breakdown": {row[0]: row[1] for row in severity_rows},
            "summary": {
                "total_threats": total_threats,
                "active_bypasses": len(bypasses_list),
                "feeds_configured": len(feeds_list),
                "sync_state": sync_state,
            },
        }
        click.echo(format_json(output, pretty_output), nl=False)
        return

    # Suppress dashboard output in quiet mode
    if is_quiet_mode():
        return

    click.echo()
    sev_table = create_table(title="[i]Threat Count by Severity[/i]", show_header=True, header_style="italic")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")

    for row in severity_rows:
        sev_style = severity_color(row[0])
        sev_table.add_row(f"[{sev_style}]{row[0]}[/{sev_style}]", str(row[1]))

    if severity_rows:
        stdout_console.print(sev_table)
    elif len(feed_rows) == 0:
        stdout_console.print(
            "[yellow]No threat data synced yet. Run [bold]pkgd intel sync[/bold] "
            "to fetch threat intelligence from configured feeds.[/]"
        )
    else:
        stdout_console.print("[dim]No threats recorded.[/]")
    stdout_console.print()

    bypass_table = create_table(title="[i]Active Bypasses[/i]", show_header=True, header_style="italic")
    bypass_table.add_column("Package", style="bold")
    bypass_table.add_column("Version")
    bypass_table.add_column("Reason", max_width=40)
    bypass_table.add_column("Expires")

    if bypass_rows:
        for row in bypass_rows:
            pkg, ver, reason, expires_at = row
            if expires_at:
                try:
                    exp = datetime.fromisoformat(expires_at)
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=UTC)
                    remaining = exp - datetime.now(UTC)
                    if remaining.total_seconds() > 0:
                        days = remaining.days
                        hours = int(remaining.seconds // 3600)
                        exp_str = f"{days}d {hours}h" if days > 0 else f"{hours}h"
                    else:
                        exp_str = "expired"
                except (ValueError, TypeError):
                    exp_str = expires_at
            else:
                exp_str = "never"
            bypass_table.add_row(pkg, ver, reason[:40], exp_str)
    else:
        bypass_table.add_row("\u2014", "\u2014", "\u2014", "\u2014")

    stdout_console.print(bypass_table)

    from pkg_defender.intel.aggregator import OSVFeedAdapter
    from pkg_defender.intel.base import FeedSource
    from pkg_defender.intel.ghsa import GHSAFeed
    from pkg_defender.intel.mastodon import MastodonFeed
    from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
    from pkg_defender.intel.ossf_malicious import OSSFMaliciousFeed
    from pkg_defender.intel.reddit import RedditFeed
    from pkg_defender.intel.rss_feed import RSSFeed
    from pkg_defender.intel.socket import SocketFeed
    from pkg_defender.intel.x_twitter import XTwitterFeed

    config = _get_config_from_context(ctx)
    intelligence_feeds: list[FeedSource] = [OSVFeedAdapter()]
    if config.feeds.ghsa_enabled:
        intelligence_feeds.append(GHSAFeed())
    if config.feeds.socket_enabled:
        intelligence_feeds.append(SocketFeed())
    if config.feeds.mastodon_enabled:
        intelligence_feeds.append(MastodonFeed())
    if config.feeds.reddit_enabled:
        intelligence_feeds.append(RedditFeed())
    if config.feeds.rss_enabled:
        intelligence_feeds.append(RSSFeed())
    if config.feeds.x_twitter_enabled:
        intelligence_feeds.append(XTwitterFeed())
    if config.feeds.ossf_malicious_enabled:
        intelligence_feeds.append(OSSFMaliciousFeed())

    audit_sources: list[FeedSource] = []
    if config.feeds.npm_advisory_enabled:
        audit_sources.append(NpmAdvisoryFeed())

    stdout_console.print()

    health_table = create_table(
        title="[i]Intelligence Feed Health[/i]",
        title_justify="center",
        show_header=True,
        header_style="italic",
    )

    feed_state_lookup = {row[0]: row for row in feed_rows}
    health_table.add_column("Feed", style="bold")
    health_table.add_column("Configured")
    health_table.add_column("Last Sync")
    health_table.add_column("Status")
    health_table.add_column("Error", max_width=40)
    health_table.add_column("Exp.", justify="center")

    for feed in intelligence_feeds:
        is_configured = feed.is_configured(config)
        state_row = feed_state_lookup.get(feed.name)

        configured_str = "[green]yes[/]" if is_configured else "[red]no[/]"

        if state_row and state_row[1]:
            try:
                ls = datetime.fromisoformat(state_row[1])
                if ls.tzinfo is None:
                    ls = ls.replace(tzinfo=UTC)
                age = datetime.now(UTC) - ls
                if age.days > 0:
                    last_sync_str = f"{age.days}d ago"
                else:
                    hours = int(age.total_seconds() // 3600)
                    last_sync_str = f"{hours}h ago" if hours > 0 else "<1h ago"
            except (ValueError, TypeError):
                last_sync_str = "[dim]never[/dim]"
        else:
            last_sync_str = "[dim]never[/dim]"

        db_status = state_row[2] if state_row else "not synced"

        if db_status == "idle":
            status_str = "[green]idle[/]"
        elif db_status == "error":
            status_str = "[red]error[/]"
        elif db_status == "syncing":
            status_str = "[yellow]syncing[/]"
        elif db_status == "disabled":
            status_str = "[dim]disabled[/]"
        elif db_status == "not_configured":
            status_str = "[dim]not configured[/]"
        elif db_status == "circuit_open":
            status_str = "[yellow]circuit open[/]"
        else:
            status_str = db_status

        error_str = feed_error_lookup.get(feed.name) or "\u2014"
        exp_str = "[yellow]E[/]" if feed.is_experimental else "\u2014"

        health_table.add_row(
            feed.name,
            configured_str,
            last_sync_str,
            status_str,
            error_str[:40] if error_str != "\u2014" else error_str,
            exp_str,
        )

    stdout_console.print(health_table)

    has_not_configured = any(not feed.is_configured(config) for feed in intelligence_feeds)
    if has_not_configured:
        stdout_console.print()
        stdout_console.print("[dim]Run [cyan]pkgd setup[/cyan] to configure feeds that show 'no'[/]")

    if show_feeds and audit_sources:
        stdout_console.print()
        stdout_console.print("[bold cyan]Audit Sources[/]")

        audit_table = create_table(show_header=True, header_style="italic")
        audit_table.add_column("Source", style="bold")
        audit_table.add_column("Configured")
        audit_table.add_column("Last Sync")
        audit_table.add_column("Notes")

        for source in audit_sources:
            is_configured = source.is_configured(config)
            configured_str = "[green]yes[/]" if is_configured else "[red]no[/]"
            last_sync_str = "N/A"
            notes_str = "runs at audit time" if source.name == "npm_advisory" else "\u2014"
            audit_table.add_row(source.name, configured_str, last_sync_str, notes_str)

        stdout_console.print(audit_table)

    configured_count = sum(1 for feed in intelligence_feeds if feed.is_configured(config))
    audit_sources_count = sum(1 for source in audit_sources if source.is_configured(config))
    total_sources = configured_count + audit_sources_count
    logger.debug(
        "Feed health: %d/%d feeds configured, %d audit sources",
        configured_count,
        len(intelligence_feeds),
        audit_sources_count,
    )

    stdout_console.print()
    stdout_console.print(
        f"  [bold]{total_threats}[/] total threats  |  "
        f"[bold]{len(bypass_rows)}[/] active bypasses  |  "
        f"[bold]{total_sources}[/] sources configured"
    )
