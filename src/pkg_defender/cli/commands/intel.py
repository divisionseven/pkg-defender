# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd intel group and subcommands."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import click
from rich.columns import Columns
from rich.panel import Panel

from pkg_defender.cli._constants import SHOW_SOURCE_URLS
from pkg_defender.cli._exit_codes import EXIT_REGISTRY_UNREACHABLE as _EXIT_REGISTRY_UNREACHABLE
from pkg_defender.cli._manager_constants import MANAGER_NAMES, resolve_ecosystem
from pkg_defender.cli._progress import (
    feed_sync_progress,
    format_feed_message,
    handle_feed_complete,
    handle_feed_error,
    should_show_progress,
)
from pkg_defender.cli.common import (
    _check_and_warn_staleness,
    _format_versions,
    _get_config_from_context,
    console,
    create_table,
    format_json,
    get_db_path,
    init_db,
    is_quiet_mode,
    severity_color,
    stdout_console,
)
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli
from pkg_defender.db.schema import query_threats_by_source
from pkg_defender.registry.brew import brew_get_installed_version

logger = logging.getLogger(__name__)


@cli.group(cls=ManagerGroup, name="intel", epilog="See also: pkgd status, pkgd health, pkgd daemon")
@click.pass_context
def intel_group(ctx: click.Context) -> None:
    """Intelligence feed commands."""
    if ctx.invoked_subcommand is None:
        if "--help" not in sys.argv and "-h" not in sys.argv:
            click.echo(ctx.get_help())
            ctx.exit(0)
        return


@intel_group.command(
    name="sync",
    epilog="See also: pkgd status, pkgd health, pkgd daemon, pkgd intel search, pkgd intel report",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["json", "rich"]),
    default="rich",
    help="Output format: 'json' for JSON, 'rich' for formatted output (default: rich). "
    "Examples: pkgd intel sync -o json > output.json",
)
@click.option(
    "--pretty",
    "-p",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (only applies with -o json)",
)
@click.option("--json", "json_flag", is_flag=True, help="Output JSON (same as --output json or -o json)")
@click.option(
    "--exclude-feed",
    "exclude_feeds",
    multiple=True,
    help="Exclude a feed from this sync. May be specified multiple times. Example: --exclude-feed ossf_malicious",
)
@click.pass_context
def intel_sync(
    ctx: click.Context,
    output_format: str,
    json_flag: bool,
    pretty_output: bool,
    exclude_feeds: tuple[str, ...] = (),
) -> None:
    """Sync threat intelligence feeds.

    Downloads the latest threat data from all configured intelligence sources:
    - OSV (Open Source Vulnerabilities)
    - GitHub Advisory Database (GHSA)
    - Socket.dev
    - npm Advisory Database
    - Mastodon
    - Reddit
    - RSS feeds
    - Twitter/X

    This populates the local threat database used by 'pkgd install' and 'pkgd audit'
    to check packages against known vulnerabilities and malicious packages.

    Run this periodically (e.g., daily or weekly) to keep threat data current.
    The 'pkgd daemon' can automate this process.

    Examples:

    \b
        pkgd intel sync
        pkgd intel sync --json

    EXIT CODES:
        0    Sync completed (some feeds may have errors)
        5    Registry/network unreachable

    ENVIRONMENT:
        PKGD_CONFIG_PATH           Config file location
        NO_COLOR                   Disable colored output

    FILES:
        ~/.local/share/pkg-defender/threats.db    Threat database

    \f
    """
    if json_flag:
        output_format = "json"

    # CI mode auto-enables JSON output
    output_format = ctx.obj.get("output_format") or output_format

    from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter
    from pkg_defender.intel.base import FeedSource
    from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter
    from pkg_defender.intel.ghsa import GHSAFeed
    from pkg_defender.intel.mastodon import MastodonFeed
    from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
    from pkg_defender.intel.ossf_malicious import OSSFMaliciousFeed
    from pkg_defender.intel.reddit import RedditFeed
    from pkg_defender.intel.rss_feed import RSSFeed
    from pkg_defender.intel.socket import SocketFeed
    from pkg_defender.intel.x_twitter import XTwitterFeed

    config = _get_config_from_context(ctx)
    db_path = get_db_path()

    click.echo()
    if should_show_progress():
        console.print("Syncing threat feeds...")
    else:
        click.echo("Syncing threat feeds...", err=True)

    feeds: list[FeedSource] = [OSVFeedAdapter()]
    if shutil.which("brew") is not None:
        feeds.append(HomebrewFeedAdapter())
    if config.feeds.ghsa_enabled:
        feeds.append(GHSAFeed())
    if config.feeds.socket_enabled:
        feeds.append(SocketFeed())
    if config.feeds.npm_advisory_enabled:
        feeds.append(NpmAdvisoryFeed())
    if config.feeds.mastodon_enabled:
        feeds.append(MastodonFeed())
    if config.feeds.reddit_enabled:
        feeds.append(RedditFeed())
    if config.feeds.rss_enabled:
        feeds.append(RSSFeed())
    if config.feeds.x_twitter_enabled:
        feeds.append(XTwitterFeed())
    if config.feeds.ossf_malicious_enabled:
        feeds.append(OSSFMaliciousFeed())

    # Runtime feed exclusion (independent of config — allows one-off skip)
    if exclude_feeds:
        excluded_set = set(exclude_feeds)
        feeds = [f for f in feeds if f.name not in excluded_set]
        logger.debug("Intel sync: %d feeds after applying --exclude-feed %s", len(feeds), exclude_feeds)

    logger.debug("Intel sync: %d feeds configured", len(feeds))

    aggregator = FeedAggregator(
        feeds,
        db_path,
        config=config,
        retention_days=config.database.retention_days,
    )
    sync_start = datetime.now(UTC)

    try:
        with feed_sync_progress(len(feeds)) as progress:
            task: Any = 0  # placeholder, only used when progress is not None
            if progress is not None:
                task = progress.add_task("Syncing all feeds concurrently...", total=len(feeds))

            def _on_feed_complete(feed_name: str, record_count: int) -> None:
                handle_feed_complete(progress, task, feed_name, record_count)

            def _on_feed_error(feed_name: str, error: Exception) -> None:
                handle_feed_error(progress, task, feed_name, error)

            results = asyncio.run(
                asyncio.wait_for(
                    aggregator.sync_all(
                        progress_callback=_on_feed_complete,
                        error_callback=_on_feed_error,
                    ),
                    timeout=config.feeds.feed_sync_timeout if config.feeds.feed_sync_timeout > 0 else None,
                )
            )
    except TimeoutError:
        console.print(
            f"[bold red]\u2717 Error:[/bold red] Feed sync timed out after "
            f"{config.feeds.feed_sync_timeout} seconds. "
            "Check your network connection and run 'pkgd intel sync' again."
        )
        raise SystemExit(_EXIT_REGISTRY_UNREACHABLE) from None
    except Exception as exc:
        console.print(
            f"[bold red]\u2717 Error:[/bold red] Feed sync failed: {exc}. "
            "Check your network connection and run 'pkgd intel sync' again."
        )
        raise SystemExit(_EXIT_REGISTRY_UNREACHABLE) from exc

    sync_summary = aggregator.get_sync_summary()
    feed_metadata = aggregator.get_feed_metadata()

    feed_results: list[dict[str, Any]] = []
    total = 0
    for feed in feeds:
        count = results.get(feed.name, 0)
        total += count
        feed_info = sync_summary.get(feed.name, {})
        feed_status = feed_info.get("status", "unknown")
        error_msg = feed_info.get("error_message")

        feed_result: dict[str, Any] = {
            "feed": feed.name,
            "threats_synced": count,
            "status": feed_status,
        }
        if error_msg:
            feed_result["error"] = error_msg
        feed_results.append(feed_result)
    logger.debug("Sync results: %d total threats from %d feeds", total, len(feeds))

    if output_format == "json":
        output: dict[str, Any] = {
            "total_threats_synced": total,
            "feeds": feed_results,
        }
        click.echo(format_json(output, pretty_output), nl=False)
        return

    # Suppress sync summary in quiet mode — informational, not query results
    if is_quiet_mode():
        return

    # ── Homebrew Vulnerability Alert ──
    homebrew_count = results.get("homebrew", 0)
    if homebrew_count > 0:
        conn = sqlite3.connect(db_path)
        try:
            homebrew_records = query_threats_by_source(
                conn,
                ecosystem="homebrew",
                source="homebrew_osv",
                ingested_since=sync_start.isoformat(),
            )
        finally:
            conn.close()

        if homebrew_records:
            alert_lines: list[str] = []
            for rec in homebrew_records:
                version = asyncio.run(brew_get_installed_version(rec["package_name"])) or ""
                version_str = f" ({version})" if version else ""
                cvss = f" \u2014 CVSS {rec['cvss_score']}" if rec.get("cvss_score") else ""
                lines = [f"  Package: {rec['package_name']}{version_str}"]
                lines.append(f"  Severity: {rec['severity']}{cvss}")
                if rec.get("summary"):
                    lines.append(f"  Summary: {rec['summary']}")
                if rec.get("detail_url"):
                    lines.append(f"  URL: {rec['detail_url']}")
                alert_lines.append("\n".join(lines))
            alert_text = "\n\n".join(alert_lines)
            pkg_label = "Packages" if len(homebrew_records) != 1 else "Package"
            console.print()
            console.print(
                Panel(
                    alert_text,
                    title="\u26a0 BREW",
                    border_style="red",
                    subtitle=f"{len(homebrew_records)} Vulnerable {pkg_label} Found",
                )
            )
            console.print()

    has_issues = any(fr.get("status") in ("error", "not_configured", "not configured") for fr in feed_results)
    warnings: list[str] = []

    for feed_result in feed_results:
        feed_name = feed_result["feed"]
        count = feed_result["threats_synced"]
        feed_status = feed_result["status"]
        error_msg = feed_result.get("error")

        metadata = feed_metadata.get(feed_name, {})

        if feed_status == "error":
            msg = error_msg or "unknown error"
            if len(msg) > 60:
                msg = msg[:57] + "..."
            console.print(f"  [red]{feed_name}[/red]: error \u2014 {msg}")
        elif feed_status in ("not_configured", "not configured"):
            console.print(f"  [dim]{feed_name}[/dim]: [yellow]not configured[/yellow]")
        elif count > 0:
            msg = format_feed_message(feed_name, count)
            source_url = metadata.get("source_url")
            if SHOW_SOURCE_URLS and source_url:
                console.print(f"  [green]{msg}[/] ([link={source_url}]{source_url}[/link])")
            else:
                console.print(f"  [green]{msg}[/]")
        else:
            msg = format_feed_message(feed_name, count)
            console.print(f"  [dim]{msg}[/dim]")

        # Collect per-feed warnings for deferred display
        warning = metadata.get("warning")
        if warning:
            warnings.append(warning)

    # Print all collected warnings after feed results, before Total line
    for warning in warnings:
        console.print(f"    [yellow]\u26a0 {warning}[/yellow]")

    console.print(f"\n[green]Total: {total} threats synced[/green]")

    db_path = get_db_path()
    if db_path.exists():
        size_mb = db_path.stat().st_size / (1024 * 1024)
        free_bytes = shutil.disk_usage(db_path).free
        free_gb = free_bytes / (1024 * 1024 * 1024)

        size_str = f"{size_mb / 1024:.1f} GB" if size_mb >= 1024 else f"{size_mb:.1f} MB"

        warning = ""
        if free_gb < 5:
            warning = "\u26a0 "
        free_str = f"{free_gb:.0f} GB" if free_gb >= 100 else f"{free_gb:.1f} GB"

        console.print(f"[dim]Database size: {size_str} | {warning}Free space on disk: {free_str}[/dim]")

    failed = aggregator.get_failed_feeds()
    if failed:
        console.print("[bold red]\u26a0 Feed failures:[/bold red]")
        for feed_name, error_msg in failed.items():
            console.print(f"  [red]{feed_name}: {error_msg}[/red]")
        console.print()

    # Check for RSS warnings (e.g., 0 entries after filtering)
    has_rss_warnings = any(
        feed_metadata.get(feed_name, {}).get("warning") for feed_name in (fr["feed"] for fr in feed_results)
    )

    if has_issues or has_rss_warnings:
        console.print()
        console.print("[bold]\U0001f4a1 Helpful Tips:[/bold]")
        if has_rss_warnings:
            console.print(
                "RSS returned 0 entries \u2014 check [cyan]feeds.rss_keywords[/cyan] "
                "and [cyan]feeds.rss_urls[/cyan] in config"
            )
        console.print("Run [cyan]pkgd status --feeds[/cyan] for detailed feed status")
        console.print("Run [cyan]pkgd health[/cyan] for system diagnostics")


@intel_group.command(name="search")
@click.argument("query")
@click.option(
    "--manager",
    "-m",
    default=None,
    type=click.Choice(list(MANAGER_NAMES)),
    help="Package manager to filter by (e.g., npm, pip, cargo).",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["json", "rich"]),
    default="rich",
    help="Output format: 'json' for JSON, 'rich' for formatted output (default: rich). "
    "Examples: pkgd intel search axios -o json > output.json",
)
@click.option(
    "--pretty",
    "-p",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (only applies with -o json)",
)
@click.option("--json", "json_flag", is_flag=True, help="Output JSON (same as --output json or -o json)")
@click.option(
    "--exclude-severity",
    "exclude_severity",
    help="Severity levels to exclude (comma-separated: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN). Default: UNKNOWN",
)
@click.pass_context
def intel_search(
    ctx: click.Context,
    query: str,
    manager: str | None,
    output_format: str,
    json_flag: bool,
    pretty_output: bool,
    exclude_severity: str | None,
) -> None:
    """Search the local threat database.

    Searches for packages or vulnerabilities matching the query.

    Examples:

    \b
        pkgd intel search axios
        pkgd intel search log4j --manager pip
        pkgd intel search "remote code execution" -o json
        pkgd intel search axios --exclude-severity UNKNOWN

    EXIT CODES:
        0    Success (results or no results)
        2    Invalid arguments

    ENVIRONMENT:
        PKGD_CONFIG_PATH           Config file location
        NO_COLOR                   Disable colored output

    FILES:
        ~/.local/share/pkg-defender/threats.db    Threat database

    SEE ALSO:
        pkgd intel sync, pkgd intel report, pkgd audit

    \f
    """
    if json_flag:
        output_format = "json"

    # CI mode auto-enables JSON output
    output_format = ctx.obj.get("output_format") or output_format

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

    if exclude_severity is not None:
        provided = {s.strip().upper() for s in exclude_severity.split(",") if s.strip()}
        invalid = provided - valid_severities
        if invalid:
            raise click.BadParameter(
                f"Invalid severity values: {', '.join(sorted(invalid))}. "
                f"Valid options: {', '.join(sorted(valid_severities))}"
            )

    db_path = get_db_path()
    conn = init_db(db_path)

    try:
        config = _get_config_from_context(ctx)
        _check_and_warn_staleness(conn, config=config)

        if exclude_severity is not None:
            exclude_severities = [s.strip().upper() for s in exclude_severity.split(",") if s.strip()]
        else:
            exclude_severities = config.output.search_exclude_severity

        pattern = f"%{query}%"

        if exclude_severities:
            placeholders = ", ".join(["?"] * len(exclude_severities))
            severity_filter = f"AND severity NOT IN ({placeholders})"
        else:
            severity_filter = ""

        ecosystem_filter: str | None = None
        if manager is not None:
            ecosystem_filter = resolve_ecosystem(manager)

        if ecosystem_filter:
            rows = conn.execute(
                f"SELECT id, ecosystem, package_name, severity, summary, source, first_seen "
                f"FROM threats "
                f"WHERE package_name LIKE ? AND ecosystem = ? {severity_filter} "
                "ORDER BY CASE severity "
                "    WHEN 'CRITICAL' THEN 1 "
                "    WHEN 'HIGH' THEN 2 "
                "    WHEN 'MEDIUM' THEN 3 "
                "    WHEN 'LOW' THEN 4 "
                "    WHEN 'UNKNOWN' THEN 5 "
                "END, first_seen DESC",
                (pattern, ecosystem_filter, *exclude_severities) if exclude_severities else (pattern, ecosystem_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT id, ecosystem, package_name, severity, summary, source, first_seen "
                f"FROM threats "
                f"WHERE package_name LIKE ? {severity_filter} "
                "ORDER BY CASE severity "
                "    WHEN 'CRITICAL' THEN 1 "
                "    WHEN 'HIGH' THEN 2 "
                "    WHEN 'MEDIUM' THEN 3 "
                "    WHEN 'LOW' THEN 4 "
                "    WHEN 'UNKNOWN' THEN 5 "
                "END, first_seen DESC",
                (pattern, *exclude_severities) if exclude_severities else (pattern,),
            ).fetchall()

        logger.debug(
            "Search '%s': %d results (manager=%s, exclude=%s)",
            query,
            len(rows),
            manager,
            exclude_severity,
        )

        if output_format == "json":
            results = [
                {
                    "id": r[0],
                    "ecosystem": r[1],
                    "package_name": r[2],
                    "severity": r[3],
                    "summary": r[4],
                    "source": r[5],
                    "first_seen": r[6],
                }
                for r in rows
            ]
            click.echo(format_json(results, pretty_output), nl=False)
            return

        if not rows:
            click.echo()
            stdout_console.print(f"No threats found matching '{query}'")
            return

        click.echo()
        table = create_table(
            title=f"[i]Threats matching '{query}'[/i]",
            show_header=True,
            header_style="italic",
        )
        table.add_column("ID", style="bold")
        table.add_column("Ecosystem")
        table.add_column("Package")
        table.add_column("Severity")
        table.add_column("Source")
        table.add_column("First Seen")

        for row in rows:
            sev_style = severity_color(row[3])
            table.add_row(
                row[0],
                row[1],
                row[2] or "\u2014",
                f"[{sev_style}]{row[3]}[/{sev_style}]",
                row[5],
                row[6][:10] if row[6] else "\u2014",
            )

        stdout_console.print(table)
    finally:
        conn.close()


@intel_group.command(name="report")
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["json", "rich"]),
    default="rich",
    help="Output format: 'json' for JSON, 'rich' for formatted output (default: rich). "
    "Examples: pkgd intel report -o json > output.json",
)
@click.option(
    "--pretty",
    "-p",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (only applies with -o json)",
)
@click.option("--json", "json_flag", is_flag=True, help="Output JSON (same as --output json or -o json)")
@click.option(
    "--manager",
    "-m",
    default=None,
    type=click.Choice(list(MANAGER_NAMES)),
    help="Package manager to filter by (e.g., npm, pip, cargo).",
)
@click.option(
    "--exclude-severity",
    "exclude_severity",
    help="Severity levels to exclude (comma-separated: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN). Default: UNKNOWN",
)
@click.pass_context
def intel_report(
    ctx: click.Context,
    output_format: str,
    json_flag: bool,
    pretty_output: bool,
    manager: str | None,
    exclude_severity: str | None,
) -> None:
    """Display threat report: recent threats and landscape

    Shows recent threats (last 7 days), record counts by severity and source,
    ecosystem breakdown, and the most targeted packages.

    Examples:

    \b
        pkgd intel report
        pkgd intel report -o json
        pkgd intel report --manager npm

    EXIT CODES:
        0    Success
        2    Invalid arguments

    ENVIRONMENT:
        PKGD_CONFIG_PATH           Config file location
        NO_COLOR                   Disable colored output

    FILES:
        ~/.local/share/pkg-defender/threats.db    Threat database

    SEE ALSO:
        pkgd intel sync, pkgd intel search, pkgd status

    \f
    """
    if json_flag:
        output_format = "json"

    # CI mode auto-enables JSON output
    output_format = ctx.obj.get("output_format") or output_format

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

    if exclude_severity is not None:
        provided = {s.strip().upper() for s in exclude_severity.split(",") if s.strip()}
        invalid = provided - valid_severities
        if invalid:
            raise click.BadParameter(
                f"Invalid severity values: {', '.join(sorted(invalid))}. "
                f"Valid options: {', '.join(sorted(valid_severities))}"
            )

    config = _get_config_from_context(ctx)

    if exclude_severity is not None:
        exclude_severities = [s.strip().upper() for s in exclude_severity.split(",") if s.strip()]
    else:
        exclude_severities = config.output.intel_exclude_severity

    db_path = get_db_path()
    conn = init_db(db_path)

    try:
        # Skip stale-DB warning in JSON mode — Rich Panel output would contaminate stdout
        if output_format != "json":
            _check_and_warn_staleness(conn, config=config)

        ecosystem_filter: str | None = None
        if manager is not None:
            ecosystem_filter = resolve_ecosystem(manager)

        ecosystem = ecosystem_filter

        where_clauses: list[str] = []
        params: list[str] = []
        if ecosystem_filter:
            where_clauses.append("ecosystem = ?")
            params.append(ecosystem_filter)

        if exclude_severities:
            placeholders = ", ".join(["?"] * len(exclude_severities))
            where_clauses.append(f"severity NOT IN ({placeholders})")
            params.extend(exclude_severities)

        where_clause = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params_tuple = tuple(params)

        thirty_days_ago = (datetime.now(UTC) - timedelta(days=30)).isoformat()

        total_row = conn.execute(f"SELECT COUNT(*) FROM threats {where_clause}", params_tuple).fetchone()
        total_records = total_row[0] if total_row else 0

        severity_rows = conn.execute(
            f"SELECT severity, COUNT(*) as count FROM threats {where_clause} "
            "GROUP BY severity "
            "ORDER BY CASE severity "
            "  WHEN 'CRITICAL' THEN 1 "
            "  WHEN 'HIGH' THEN 2 "
            "  WHEN 'MEDIUM' THEN 3 "
            "  WHEN 'LOW' THEN 4 "
            "  ELSE 5 END",
            params_tuple,
        ).fetchall()

        source_rows = conn.execute(
            f"SELECT source, COUNT(*) as count FROM threats {where_clause} GROUP BY source ORDER BY count DESC",
            params_tuple,
        ).fetchall()

        all_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        included_severities = [s for s in all_severities if s not in exclude_severities]

        if included_severities:
            severity_cols = []
            for sev in included_severities:
                severity_cols.append(f"SUM(CASE WHEN severity = '{sev}' THEN 1 ELSE 0 END) AS {sev}")

            severity_columns_sql = ", ".join(severity_cols)

            # Build dated clause for ecosystem breakdown (30-day filter)
            eco_clauses = list(where_clauses)
            eco_clauses.append("first_seen >= ?")
            eco_params = list(params) + [thirty_days_ago]
            eco_where = f"WHERE {' AND '.join(eco_clauses)}" if eco_clauses else ""

            ecosystem_rows = conn.execute(
                f"SELECT ecosystem, {severity_columns_sql}, COUNT(*) as total_count "
                f"FROM threats {eco_where} GROUP BY ecosystem ORDER BY total_count DESC",
                tuple(eco_params),
            ).fetchall()
        else:
            ecosystem_rows = []

        top_pkg_clauses: list[str] = []
        top_pkg_params: list[str] = []
        if ecosystem:
            top_pkg_clauses.append("ecosystem = ?")
            top_pkg_params.append(ecosystem)
        if exclude_severities:
            placeholders = ", ".join(["?"] * len(exclude_severities))
            top_pkg_clauses.append(f"severity NOT IN ({placeholders})")
            top_pkg_params.extend(exclude_severities)
        top_pkg_clauses.append("first_seen >= ?")
        top_pkg_params.append(thirty_days_ago)

        if top_pkg_clauses:
            top_pkg_where = "WHERE package_name IS NOT NULL AND " + " AND ".join(top_pkg_clauses)
        else:
            top_pkg_where = "WHERE package_name IS NOT NULL"

        top_pkg_rows = conn.execute(
            f"SELECT package_name, ecosystem, COUNT(*) as count, MAX(severity) as worst_severity "
            f"FROM threats {top_pkg_where} "
            "GROUP BY package_name, ecosystem "
            "ORDER BY count DESC, CASE MAX(severity) "
            "  WHEN 'CRITICAL' THEN 1 "
            "  WHEN 'HIGH' THEN 2 "
            "  WHEN 'MEDIUM' THEN 3 "
            "  WHEN 'LOW' THEN 4 "
            "  ELSE 5 END LIMIT 10",
            tuple(top_pkg_params),
        ).fetchall()

        seven_days_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()
        recent_clauses: list[str] = ["first_seen >= ?"]
        recent_params: list[str] = [seven_days_ago]
        if ecosystem:
            recent_clauses.append("ecosystem = ?")
            recent_params.append(ecosystem)
        if exclude_severities:
            placeholders = ", ".join(["?"] * len(exclude_severities))
            recent_clauses.append(f"severity NOT IN ({placeholders})")
            recent_params.extend(exclude_severities)

        recent_where = " AND ".join(recent_clauses)

        threat_rows = conn.execute(
            f"SELECT package_name, severity, source, first_seen, "
            f"affected_versions, affected_ranges "
            f"FROM threats WHERE {recent_where} "
            "ORDER BY CASE severity "
            "  WHEN 'CRITICAL' THEN 1 "
            "  WHEN 'HIGH' THEN 2 "
            "  WHEN 'MEDIUM' THEN 3 "
            "  WHEN 'LOW' THEN 4 "
            "  ELSE 5 END, first_seen DESC",
            tuple(recent_params),
        ).fetchall()
    finally:
        conn.close()

    if output_format == "json":
        recent_threats_list = [
            {
                "package_name": r[0],
                "severity": r[1],
                "source": r[2],
                "first_seen": r[3],
                "affected_versions": json.loads(r[4]) if r[4] else [],
                "affected_ranges": json.loads(r[5]) if r[5] else [],
            }
            for r in threat_rows
        ]

        ecosystem_dict: dict[str, dict[str, int]] = {}
        for row in ecosystem_rows:
            ecosystem_name = row[0]
            ecosystem_data: dict[str, int] = {}
            for i, sev in enumerate(included_severities):
                ecosystem_data[sev.lower()] = row[i + 1]
            ecosystem_data["total"] = row[-1]
            ecosystem_dict[ecosystem_name] = ecosystem_data

        output: dict[str, Any] = {
            "recent_threats": recent_threats_list,
            "threat_overview": {
                "severity": {row[0].lower(): row[1] for row in severity_rows},
                "source": {row[0]: row[1] for row in source_rows},
            },
            "threat_landscape": {
                "ecosystem": ecosystem_dict,
                "top_packages": [
                    {
                        "package_name": row[0],
                        "ecosystem": row[1],
                        "count": row[2],
                        "worst_severity": row[3],
                    }
                    for row in top_pkg_rows
                ],
            },
        }
        click.echo(format_json(output, pretty_output), nl=False)
        return

    click.echo()
    title_suffix = f"(Ecosystem: {ecosystem})"
    stdout_console.print("[bold]### THREAT INTELLIGENCE REPORT ###[/bold]")
    if ecosystem:
        stdout_console.print(f"{title_suffix}\n")

    if exclude_severities:
        excluded_str = ", ".join(sorted(exclude_severities))
        stdout_console.print(f"[dim][white]*Excluding Severity Level(s): {excluded_str}[/white][/dim]\n\n")

    stdout_console.print("[i][bold]== Recent Threats (Last 7 Days) ==[/bold][/i]")

    threat_table = create_table(
        show_header=True,
        header_style="bold",
    )
    threat_table.add_column("Package", style="bold", max_width=50)
    threat_table.add_column("Severity")
    threat_table.add_column("Source")
    threat_table.add_column("Age")
    threat_table.add_column("Versions", style="dim", max_width=38)

    for row in threat_rows:
        pkg, sev, src, first_seen_str, affected_versions_json, affected_ranges_json = row
        try:
            fs = datetime.fromisoformat(first_seen_str)
            if fs.tzinfo is None:
                fs = fs.replace(tzinfo=UTC)
            age_td = datetime.now(UTC) - fs
            if age_td.days > 0:
                age_str = f"{age_td.days}d ago"
            else:
                hours = int(age_td.total_seconds() // 3600)
                age_str = f"{hours}h ago" if hours > 0 else "<1h ago"
        except (ValueError, TypeError):
            age_str = "?"

        version_str = _format_versions(affected_versions_json, affected_ranges_json)

        sev_style = severity_color(sev)
        threat_table.add_row(
            pkg or "\u2014",
            f"[{sev_style}]{sev}[/{sev_style}]",
            src,
            age_str,
            version_str,
        )

    if threat_rows:
        stdout_console.print(threat_table)
    else:
        stdout_console.print("[dim]No threats in the last 7 days.[/]")

    stdout_console.print()

    stdout_console.print("[i][bold]== Threat Overview ==[/bold][/i]")

    sev_table = create_table(show_header=True, header_style="bold")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")

    for row in severity_rows:
        sev_style = severity_color(row[0])
        sev_table.add_row(
            f"[{sev_style}]{row[0]}[/{sev_style}]",
            str(row[1]),
        )
    sev_table.add_section()
    sev_table.add_row("[dim][i]Total[/i][/dim]", f"[dim][i]{total_records}[/i][/dim]")

    src_table = create_table(show_header=True, header_style="bold")
    src_table.add_column("Source", style="bold")
    src_table.add_column("Count", justify="right")

    for row in source_rows:
        src_table.add_row(row[0], str(row[1]))

    if severity_rows and source_rows:
        stdout_console.print(Columns([sev_table, src_table], equal=True, expand=False))
    elif severity_rows:
        stdout_console.print(sev_table)
    else:
        stdout_console.print("[dim]No threat records found.[/]")

    stdout_console.print()

    stdout_console.print("[i][bold]== Threat Landscape ==[/bold][/i]")

    eco_table = create_table(show_header=True, header_style="bold")
    eco_table.add_column("Top Targeted Ecosystems (Last 30 Days)", style="bold")
    for sev in included_severities:
        eco_table.add_column(sev, justify="right")
    eco_table.add_column("Total", justify="right")

    for row in ecosystem_rows:
        ecosystem_name = row[0]
        total_count = row[-1]
        row_data = [ecosystem_name]
        for i, sev in enumerate(included_severities):
            count = row[i + 1]
            if sev == "CRITICAL":
                row_data.append(f"[bold][red]{count}[/red][/bold]")
            elif sev == "HIGH":
                row_data.append(f"[red]{count}[/red]")
            elif sev == "MEDIUM":
                row_data.append(f"[yellow]{count}[/yellow]")
            elif sev == "LOW":
                row_data.append(f"[blue]{count}[/blue]")
            else:
                row_data.append(str(count))
        row_data.append(str(total_count))
        eco_table.add_row(*row_data)

    pkg_table = create_table(show_header=True, header_style="bold")
    pkg_table.add_column("Top Targeted Packages (Last 30 Days)", style="bold")
    pkg_table.add_column("Ecosystem")
    pkg_table.add_column("Threats", justify="right")
    pkg_table.add_column("Worst Severity", justify="center")

    for row in top_pkg_rows:
        sev_style = severity_color(row[3])
        pkg_table.add_row(
            row[0] or "\u2014",
            row[1],
            str(row[2]),
            f"[{sev_style}]{row[3]}[/{sev_style}]",
        )

    if ecosystem_rows and top_pkg_rows:
        stdout_console.print(Columns([eco_table, pkg_table], equal=True, expand=False))
    elif ecosystem_rows:
        stdout_console.print(eco_table)
    elif top_pkg_rows:
        stdout_console.print(pkg_table)
    if not ecosystem_rows and not top_pkg_rows:
        stdout_console.print("[dim]No ecosystem or package data available.[/]")

    stdout_console.print()
