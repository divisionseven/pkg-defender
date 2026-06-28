"""pkgd audit-logs group and subcommands."""

from __future__ import annotations

from datetime import datetime

import click

from pkg_defender.cli.common import console, create_table, get_connection, get_db_path, stdout_console
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli

from .._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR


@cli.group(cls=ManagerGroup, name="audit-logs")
def audit_logs_group() -> None:
    """Query and manage audit event logs."""
    pass


@audit_logs_group.command(name="query")
@click.option("--ecosystem", help="Filter by ecosystem")
@click.option("--package", "-p", "package_name", help="Filter by package name")
@click.option(
    "--verdict",
    type=click.Choice(["PASS", "PARTIAL_PASS", "FAIL", "BLOCKED", "WARN", "ERROR"]),
    help="Filter by verdict",
)
@click.option(
    "--source",
    type=click.Choice(["shell_hook", "cli", "api", "cron", "test"]),
    help="Filter by source",
)
@click.option(
    "--since",
    help="Filter events after ISO8601 datetime",
)
@click.option(
    "--until",
    help="Filter events before ISO8601 datetime",
)
@click.option(
    "--limit",
    "-l",
    default=100,
    type=int,
    help="Maximum events to return",
)
def audit_logs_query(
    ecosystem: str | None,
    package_name: str | None,
    verdict: str | None,
    source: str | None,
    since: str | None,
    until: str | None,
    limit: int,
) -> None:
    """Query audit event logs.

    Displays audit events matching the specified filters.
    Use --limit to control the number of results.

    Examples:

    \b
        pkgd audit-logs query
        pkgd audit-logs query --ecosystem npm
        pkgd audit-logs query --verdict FAIL
        pkgd audit-logs query --since 2026-01-01
        pkgd audit-logs query -l 50

    EXIT CODES:
        0    Success
        1    Error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    from pkg_defender.db import get_audit_events

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            console.print(f"[red]Error:[/] Invalid --since format: {since}")
            console.print("Use ISO8601 format (e.g., 2026-01-01T00:00:00)")
            raise SystemExit(_EXIT_GENERAL_ERROR) from None

    until_dt = None
    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
        except ValueError:
            console.print(f"[red]Error:[/] Invalid --until format: {until}")
            console.print("Use ISO8601 format (e.g., 2026-01-01T00:00:00)")
            raise SystemExit(_EXIT_GENERAL_ERROR) from None

    db_path = get_db_path()
    if not db_path or not db_path.exists():
        console.print("[red]Error:[/] Database not found. Run 'pkgd setup' first.")
        raise SystemExit(_EXIT_GENERAL_ERROR)

    conn = get_connection(db_path)
    events = get_audit_events(
        conn,
        ecosystem=ecosystem,
        package_name=package_name,
        verdict=verdict,
        source=source,
        since=since_dt,
        until=until_dt,
        limit=limit,
    )
    conn.close()

    if not events:
        console.print("No audit events found matching the specified filters.")
        return

    table = create_table(show_header=True, header_style="bold magenta")
    table.add_column("Timestamp")
    table.add_column("Ecosystem")
    table.add_column("Package")
    table.add_column("Verdict")
    table.add_column("Exit")
    table.add_column("Source")
    table.add_column("Runtime (ms)")

    for event in events:
        table.add_row(
            event.get("timestamp", "")[:19],
            event.get("ecosystem", ""),
            event.get("package_name", "")[:30],
            event.get("verdict", ""),
            str(event.get("exit_code", "")),
            event.get("source", ""),
            str(event.get("runtime_ms", "")),
        )

    stdout_console.print(table)
    console.print(f"\n[dim]Total events: {len(events)}[/dim]")


@audit_logs_group.command(name="stats")
@click.option(
    "--since",
    help="Filter events after ISO8601 datetime",
)
@click.option(
    "--until",
    help="Filter events before ISO8601 datetime",
)
def audit_logs_stats(since: str | None, until: str | None) -> None:
    """Show aggregate audit statistics.

    Displays summary statistics for audit events including
    counts by verdict, ecosystem, and source.

    Examples:

    \b
        pkgd audit-logs stats
        pkgd audit-logs stats --since 2026-01-01

    EXIT CODES:
        0    Success
        1    Error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    from pkg_defender.db import get_audit_event_stats

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            console.print(f"[red]Error:[/] Invalid --since format: {since}")
            console.print("Use ISO8601 format (e.g., 2026-01-01T00:00:00)")
            raise SystemExit(_EXIT_GENERAL_ERROR) from None

    until_dt = None
    if until:
        try:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
        except ValueError:
            console.print(f"[red]Error:[/] Invalid --until format: {until}")
            console.print("Use ISO8601 format (e.g., 2026-01-01T00:00:00)")
            raise SystemExit(_EXIT_GENERAL_ERROR) from None

    db_path = get_db_path()
    if not db_path or not db_path.exists():
        console.print("[red]Error:[/] Database not found. Run 'pkgd setup' first.")
        raise SystemExit(_EXIT_GENERAL_ERROR)

    conn = get_connection(db_path)
    stats = get_audit_event_stats(conn, since=since_dt, until=until_dt)
    conn.close()

    if stats["total"] == 0:
        console.print("No audit events found.")
        return

    stdout_console.print(f"\n[bold]Total Audit Events:[/bold] {stats['total']}\n")

    stdout_console.print("[bold]By Verdict:[/bold]")
    for verdict, count in sorted(stats["by_verdict"].items()):
        stdout_console.print(f"  {verdict}: {count}")
    stdout_console.print()

    stdout_console.print("[bold]By Ecosystem:[/bold]")
    for eco, count in sorted(stats["by_ecosystem"].items()):
        stdout_console.print(f"  {eco}: {count}")
    stdout_console.print()

    stdout_console.print("[bold]By Source:[/bold]")
    for source, count in sorted(stats["by_source"].items()):
        stdout_console.print(f"  {source}: {count}")
