# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd reset command."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

import click

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli.common import console, get_db_path, get_default_config_path
from pkg_defender.cli.main import cli


@cli.command(
    name="reset",
    epilog=(
        "\nDeleted data includes:\n"
        "  - Threat database and WAL/SHM/journal files (~/.local/share/pkg-defender/threats.db*)\n"
        "  - Log files (pkgd.log*, daemon_stdout.log, daemon_stderr.log)\n"
        "  - Daemon state (daemon.pid, daemon_heartbeat.json, daemon.lock)\n"
        "  - Configuration file:\n"
        "      Linux ~/.config/pkg-defender/pkgd.toml\n"
        "      macOS ~/Library/Application Support/pkg-defender/pkgd.toml\n"
        "  - Feed synchronization state\n\n"
        "Run `pkgd setup` to restore after reset.\n"
    ),
)
@click.option(
    "--teardown",
    "-t",
    is_flag=True,
    help="Remove database and config file (full teardown)",
)
@click.pass_context
def reset(ctx: click.Context, teardown: bool = False) -> None:
    """Reset all pkg-defender data (threat DB, feed state).

    WARNING: This will permanently delete all threat data!

    Permanently deletes the threat database and config file,
    resetting pkgd to a fresh state.

    Examples:

    \b
        pkgd reset
        # Deletes database only (config preserved)
    \b
        pkgd reset --teardown
        # Full teardown: database + config
    \b
        pkgd reset --yes
        # Skips confirmation prompt

    EXIT CODES:
        0    Data reset successfully
        1    General error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location
        PKGD_DATABASE_WAL_MODE

    FILES DELETED:
        ~/.local/share/pkg-defender/threats.db    Threat database
        ~/.local/share/pkg-defender/threats.db-*  WAL/SHM/journal files
        ~/.local/share/pkg-defender/pkgd.log*     Log files
        ~/.local/share/pkg-defender/daemon_*      Daemon state files
        (pkgd.toml only deleted with --teardown flag)

    \f
    """
    auto_confirm = ctx.obj.get("auto_confirm", False) if ctx.obj else False

    if not auto_confirm and not click.confirm("\033[91mThis will permanently delete all threat data. Continue?\033[0m"):
        click.echo("Aborted.", err=True)
        raise SystemExit(_EXIT_GENERAL_ERROR)

    if teardown:
        from pkg_defender.config.settings import get_data_dir

        if env_config_path := os.environ.get("PKGD_CONFIG_PATH"):
            config_path = Path(env_config_path)
        else:
            config_path = get_default_config_path()

        data_dir = get_data_dir()

        console.print("[bold red]\u26a0  Full Teardown Warning[/]\n")
        console.print("[red]This will:")
        console.print("[red]  1. Uninstall the daemon service (if running)[/]")
        console.print("[red]  2. Delete all data directory files (database, WAL, logs, daemon state)[/]")
        console.print("[red]  3. Delete the config file[/]")
        console.print()
        if not click.confirm("Continue with full teardown?"):
            console.print("[dim]Teardown cancelled.[/dim]")
            return

        removed: list[str] = []

        # --- 1. Uninstall daemon service FIRST (must precede state file deletion) ---
        daemon_uninstalled = False
        try:
            import platform as _platform

            from pkg_defender.daemon.service import LAUNCHD_LABEL, SYSTEMD_SERVICE_NAME, uninstall_service

            is_installed = False
            plat = _platform.system().lower()

            if plat == "darwin":
                plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
                is_installed = plist_path.exists()
            elif plat == "linux":
                unit_dir = Path.home() / ".config" / "systemd" / "user"
                unit_path = unit_dir / f"{SYSTEMD_SERVICE_NAME}.service"
                is_installed = unit_path.exists()
            elif plat == "windows":
                xml_path = data_dir / f"{SYSTEMD_SERVICE_NAME}-task.xml"
                is_installed = xml_path.exists()

            if is_installed:
                console.print("  Uninstalling daemon service...")
                uninstall_service()
                daemon_uninstalled = True
                console.print("    Daemon service uninstalled.")
        except Exception as exc:
            console.print(f"    Warning: Could not uninstall daemon: {exc}")
        console.print()

        # --- 2. SQLite WAL/SHM/Journal files (must be deleted before or alongside DB) ---
        for suffix in ("-wal", "-shm", "-journal"):
            wal_path = data_dir / f"threats.db{suffix}"
            if wal_path.exists():
                try:
                    try:
                        subprocess.run(["trash", str(wal_path)], check=True, timeout=5)
                    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        wal_path.unlink()
                    removed.append(str(wal_path))
                except OSError as exc:
                    click.echo(f"Warning: Could not delete {wal_path}: {exc}", err=True)

        # --- 3. Main database ---
        db_path = get_db_path()
        if db_path.exists():
            try:
                try:
                    subprocess.run(["trash", str(db_path)], check=True, timeout=5)
                except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    db_path.unlink()
                removed.append(str(db_path))
            except OSError as exc:
                click.echo(f"Warning: Could not delete {db_path}: {exc}", err=True)

        # --- Shut down logging to release RotatingFileHandler locks ---
        # On Windows, RotatingFileHandler holds an exclusive file lock on
        # pkgd.log. logging.shutdown() closes and flushes all handlers,
        # releasing the lock so unlink() succeeds.
        logging.shutdown()

        # --- 4. Log files ---
        for log_name in [
            "pkgd.log",
            "pkgd.log.1",
            "pkgd.log.2",
            "pkgd.log.3",
            "pkgd.log.4",
            "pkgd.log.5",
            "daemon_stdout.log",
            "daemon_stderr.log",
        ]:
            log_path = data_dir / log_name
            if log_path.exists():
                try:
                    log_path.unlink()
                    removed.append(str(log_path))
                except OSError as exc:
                    click.echo(f"Warning: Could not delete {log_path}: {exc}", err=True)

        # --- 5. Daemon state files (safe now — service already uninstalled) ---
        for state_name in ["daemon.pid", "daemon_heartbeat.json", "daemon.lock"]:
            state_path = data_dir / state_name
            if state_path.exists():
                try:
                    state_path.unlink()
                    removed.append(str(state_path))
                except OSError as exc:
                    click.echo(f"Warning: Could not delete {state_path}: {exc}", err=True)

        # --- 6. Config file (may be outside data_dir) ---
        if config_path.exists():
            try:
                config_path.unlink()
                removed.append(str(config_path))
            except OSError as exc:
                click.echo(f"Warning: Could not delete {config_path}: {exc}", err=True)

        # --- 7. Remove empty data directory ---
        try:
            if data_dir.exists() and not any(data_dir.iterdir()):
                data_dir.rmdir()
                removed.append(str(data_dir))
        except OSError:
            pass  # Non-empty or permissions — leave as-is

        # --- 8. Report ---
        console.print("[bold green]\u2713 Teardown Complete[/]")
        if removed:
            console.print("[green]Deleted:[/]")
            for item in removed:
                console.print(f"  {item}")
        if daemon_uninstalled:
            console.print("[green]Daemon service uninstalled.[/]")

        console.print()
        console.print("[dim]Your pkg-defender installation has been reset.[/]")
        return

    db_path = get_db_path()
    removed = []

    if db_path.exists():
        try:
            try:
                subprocess.run(["trash", str(db_path)], check=True, timeout=5)
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                db_path.unlink()
            removed.append(str(db_path))
        except OSError as exc:
            click.echo(f"Warning: Could not delete {db_path}: {exc}", err=True)

    if removed:
        click.echo()
        console.print("[green]Deleted:[/]")
        for item in removed:
            console.print(f"  {item}")
    else:
        click.echo()
        console.print("No data to reset.")
