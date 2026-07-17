# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd daemon group and subcommands."""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import click

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli.common import console, create_table, is_quiet_mode
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli


@cli.group(cls=ManagerGroup, name="daemon", epilog="See also: pkgd intel sync, pkgd health")
@click.pass_context
def daemon_group(ctx: click.Context) -> None:
    """Background daemon commands."""
    if ctx.invoked_subcommand is None:
        if "--help" not in sys.argv and "-h" not in sys.argv:
            click.echo(ctx.get_help())
            ctx.exit(0)
        return


@daemon_group.command(name="run")
def daemon_run() -> None:
    """Run the daemon in the foreground (used by service managers).

    Runs the background sync daemon in the foreground. Typically used
    by systemd, launchd, or other service managers.

    EXIT CODES:
        0    Daemon cycle completed (if not daemonized)
        1    Error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    from pkg_defender.daemon.runner import run_daemon

    run_daemon()


def _write_pid_file(data_dir: Path, pid: int) -> None:
    """Write daemon PID to ``data_dir / daemon.pid``.

    Args:
        data_dir: Daemon data directory.
        pid: Process ID of the daemon.
    """
    pid_path = data_dir / "daemon.pid"
    pid_path.write_text(str(pid))


def _start_daemon() -> None:
    """Core start logic — start the daemon as a background process.

    This is a private helper; prefer ``daemon_start`` for CLI invocation
    or ``daemon_restart`` for restart workflow.
    """
    from pkg_defender.config.settings import get_data_dir
    from pkg_defender.daemon.runner import is_daemon_running

    data_dir = get_data_dir()
    if is_daemon_running(data_dir):
        if not is_quiet_mode():
            click.echo()
            console.print("[yellow]Daemon is already running.[/]")
        return

    proc = subprocess.Popen(
        [sys.executable, "-c", "from pkg_defender.cli.main import run_cli; run_cli(['daemon', 'run'])"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Wait briefly to confirm daemon didn't crash immediately
    for _ in range(20):  # 20 × 100ms = 2 seconds
        time.sleep(0.1)
        if proc.poll() is not None:
            break
    else:
        # Process survived the settle window — confirm success
        _write_pid_file(data_dir, proc.pid)
        if not is_quiet_mode():
            click.echo()
            console.print("[green]Daemon started in background.[/]")
        return

    # Process exited during settle window — report failure
    console.print(f"[red]Daemon failed to start (exit code {proc.returncode}).[/]")
    raise SystemExit(_EXIT_GENERAL_ERROR)


@daemon_group.command(name="start")
def daemon_start() -> None:
    """Start the daemon as a background process.

    Starts the background sync daemon. The daemon will periodically
    sync threat feeds based on configuration.

    Examples:

    \b
        pkgd daemon start
        # Daemon runs in background

    EXIT CODES:
        0    Daemon started or already running

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    _start_daemon()


def _stop_daemon(data_dir: Path, quiet: bool) -> None:
    """Core stop logic — stop the running daemon by sending SIGTERM.

    Args:
        data_dir: Daemon data directory.
        quiet: If True, suppress output messages.

    This is a private helper; prefer ``daemon_stop`` for CLI invocation
    or ``daemon_restart`` for restart workflow.
    """
    from pkg_defender.daemon.runner import HEARTBEAT_FILENAME, PID_FILENAME, release_lock

    pid_path = data_dir / PID_FILENAME
    heartbeat_path = data_dir / HEARTBEAT_FILENAME

    if not pid_path.exists() and not heartbeat_path.exists():
        if not quiet:
            click.echo("Daemon does not appear to be running.", err=True)
        return

    if pid_path.exists():
        # Read PID
        try:
            pid = int(pid_path.read_text().strip())
        except (ValueError, OSError):
            # Corrupt PID file — just clean up
            pid_path.unlink(missing_ok=True)
            heartbeat_path.unlink(missing_ok=True)
            if not quiet:
                click.echo("Removed stale state (corrupt PID file).", err=True)
            release_lock()
            return

        # Check if process exists
        try:
            os.kill(pid, 0)
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                # Stale PID — process already gone
                pid_path.unlink(missing_ok=True)
                heartbeat_path.unlink(missing_ok=True)
                if not quiet:
                    click.echo("Daemon was already stopped (stale PID).", err=True)
                release_lock()
                return
            raise

        # Send SIGTERM
        os.kill(pid, signal.SIGTERM)
        if not quiet:
            click.echo(f"Sending SIGTERM to daemon (PID {pid})...", err=True)

        # Wait up to 5 seconds for graceful shutdown
        for _ in range(5):
            time.sleep(1)
            try:
                os.kill(pid, 0)
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    break
        else:
            # Process still alive — force kill (POSIX only; Windows has no SIGKILL)
            if sys.platform != "win32":
                if not quiet:
                    click.echo("Daemon did not stop gracefully, sending SIGKILL...", err=True)
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.5)
            elif not quiet:
                click.echo("Daemon did not stop gracefully on Windows.", err=True)

        # Clean up (defense-in-depth — daemon should have removed these)
        pid_path.unlink(missing_ok=True)
        heartbeat_path.unlink(missing_ok=True)

    elif heartbeat_path.exists():
        # Legacy: no PID file but heartbeat exists (daemon run mode)
        heartbeat_path.unlink(missing_ok=True)
        if not quiet:
            click.echo("Heartbeat removed. The daemon will stop at the end of its current cycle.", err=True)

    release_lock()
    if not quiet:
        click.echo("Daemon stopped.", err=True)


@daemon_group.command(name="stop")
def daemon_stop() -> None:
    """Stop the running daemon by sending SIGTERM.

    Reads the PID file, sends SIGTERM, waits up to 5 seconds for graceful
    shutdown, then falls back to SIGKILL. Cleans up PID file and heartbeat.

    Examples:

    \b
        pkgd daemon stop

    EXIT CODES:
        0    Stop command sent

    ENVIRONMENT:
        NO_COLOR                   Disable colored output

    \f
    """
    from pkg_defender.config.settings import get_data_dir

    _stop_daemon(data_dir=get_data_dir(), quiet=is_quiet_mode())


@daemon_group.command(name="restart")
def daemon_restart() -> None:
    """Restart the daemon.

    Stops the running daemon (if any) and starts a new background
    daemon process.

    Examples:

    \b
        pkgd daemon restart

    EXIT CODES:
        0    Daemon restarted

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    from pkg_defender.config.settings import get_data_dir

    data_dir = get_data_dir()
    quiet = is_quiet_mode()

    _stop_daemon(data_dir=data_dir, quiet=quiet)
    _start_daemon()

    if not quiet:
        click.echo()
        console.print("[green]Daemon restarted.[/]")


@daemon_group.command(name="status")
def daemon_status() -> None:
    """Show daemon status from heartbeat.

    Shows whether the daemon is running and the last sync time.

    Examples:

    \b
        pkgd daemon status
        pkgd daemon status || echo "Daemon not running"

    EXIT CODES:
        0    Daemon is running
        1    Daemon is not running

    ENVIRONMENT:
        NO_COLOR                   Disable colored output

    \f
    """
    from pkg_defender.config.settings import get_data_dir
    from pkg_defender.daemon.runner import read_heartbeat

    data_dir = get_data_dir()
    heartbeat = read_heartbeat(data_dir)

    if heartbeat is None:
        if not is_quiet_mode():
            click.echo()
            console.print("[red]Daemon is not running (no fresh heartbeat).[/]")
            console.print("[red]Start it with 'pkgd daemon start'.[/]")
        raise SystemExit(_EXIT_GENERAL_ERROR)

    status = heartbeat.get("status", "unknown")
    last_sync = heartbeat.get("last_sync", "never")
    error = heartbeat.get("error")
    feeds = heartbeat.get("feeds", {})

    if not is_quiet_mode():
        color = "green" if status == "ok" else "red"
        console.print(f"Status:  [{color}]{status}[/]")
        console.print(f"Last sync: {last_sync}")

    if error:
        click.echo(f"Error: {error}", err=True)

    if feeds and not is_quiet_mode():
        table = create_table(title="[i]Feed Sync Results[/i]", show_header=True, header_style="italic")
        table.add_column("Feed", style="bold")
        table.add_column("Records")
        for feed_name, count in feeds.items():
            table.add_row(feed_name, str(count))
        console.print(table)


@daemon_group.command(name="install")
@click.option(
    "--platform",
    default=None,
    type=click.Choice(["macos", "linux", "windows"]),
    help="Target platform (auto-detected if omitted)",
)
def daemon_install(platform: str | None) -> None:
    """Install the daemon as a system service.

    Installs the daemon as a system service (systemd, launchd, etc.)
    for automatic startup on boot.

    Examples:

    \b
        pkgd daemon install
        pkgd daemon install --platform linux

    EXIT CODES:
        0    Service installed
        1    General error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    \f
    """
    from pkg_defender.daemon.service import install_service

    try:
        path = install_service(platform_name=platform)
        if not is_quiet_mode():
            click.echo()
            console.print(f"[green]Service installed:[/] {path}")
    except (ValueError, FileNotFoundError) as exc:
        click.echo(
            f"Error installing daemon service: {exc}. Run 'pkgd daemon install --help' for platform requirements.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR) from exc


@daemon_group.command(name="uninstall")
def daemon_uninstall() -> None:
    """Uninstall the daemon system service.

    Removes the daemon system service installation.

    Examples:

    \b
        pkgd daemon uninstall

    EXIT CODES:
        0    Service uninstalled
        1    General error

    ENVIRONMENT:
        NO_COLOR                   Disable colored output

    \f
    """
    from pkg_defender.daemon.service import uninstall_service

    try:
        uninstall_service()
        if not is_quiet_mode():
            click.echo()
            console.print("[green]Service uninstalled.[/]")
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(_EXIT_GENERAL_ERROR) from exc
