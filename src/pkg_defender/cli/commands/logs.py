# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd logs group and subcommands."""

from __future__ import annotations

import os
import time
from collections import deque

import click

from pkg_defender.cli.common import get_data_dir
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli

from .._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR


@cli.group(cls=ManagerGroup, name="logs")
def logs_group() -> None:
    """View and manage pkg-defender logs."""
    pass


@logs_group.command(name="view")
@click.option(
    "-n",
    "--lines",
    default=100,
    type=int,
    help="Number of lines to show (default: 100)",
)
@click.option(
    "-f",
    "--full",
    is_flag=True,
    help="Show full log file (not just recent entries)",
)
def logs_view(lines: int, full: bool) -> None:
    """View recent log entries.

    Displays the most recent log entries from the pkg-defender log file.
    Use --full to display the entire log file.

    Examples:

    \b
        pkgd logs view
        pkgd logs view -n 50
        pkgd logs view --full

    EXIT CODES:
        0    Success
        1    Error (log file not found or unreadable)

    FILES:
        ~/.local/share/pkg-defender/pkgd.log    Log file

    \f
    """
    data_dir = get_data_dir()
    log_file = data_dir / "pkgd.log"

    if not log_file.exists():
        click.echo(
            f"Error: Log file not found: {log_file}. "
            "Logs are created when pkgd runs. Run a command like 'pkgd status' to generate logs.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR)

    try:
        if full:
            with open(log_file, encoding="utf-8") as f:
                content = f.read()
        else:
            with open(log_file, encoding="utf-8") as f:
                content = "".join(deque(f, maxlen=lines))

        click.echo(content)
    except OSError as e:
        click.echo(
            f"Error reading log file: {e}. Check file permissions.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR) from e


@logs_group.command(name="follow")
@click.option(
    "-n",
    "--lines",
    default=10,
    type=int,
    help="Number of initial lines to show (default: 10)",
)
def logs_follow(lines: int) -> None:
    """Follow new log entries as they are written (tail -f style).

    Continuously displays new log entries as they are written to the log file.
    Press Ctrl+C to stop.

    Examples:

    \b
        pkgd logs follow
        pkgd logs follow -n 20

    EXIT CODES:
        0    Success (Ctrl+C to exit)
        1    Error (log file not found or unreadable)

    FILES:
        ~/.local/share/pkg-defender/pkgd.log    Log file

    \f
    """
    data_dir = get_data_dir()
    log_file = data_dir / "pkgd.log"

    if not log_file.exists():
        click.echo(
            f"Error: Log file not found: {log_file}. "
            "Logs are created when pkgd runs. Run a command like 'pkgd status' to generate logs.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR)

    try:
        with open(log_file, encoding="utf-8") as f:
            initial = "".join(deque(f, maxlen=lines))
            if initial:
                click.echo(initial.rstrip())
            file_position = f.tell()
    except OSError as e:
        click.echo(
            f"Error reading log file: {e}. Check file permissions.",
            err=True,
        )
        raise SystemExit(_EXIT_GENERAL_ERROR) from e

    try:
        with open(log_file, encoding="utf-8") as f:
            while True:
                try:
                    new_stat = os.fstat(f.fileno())
                    current_size = new_stat.st_size
                except OSError:
                    break

                if current_size > file_position:
                    f.seek(file_position)
                    for line in f:
                        click.echo(line.rstrip())
                    file_position = f.tell()
                elif current_size < file_position:
                    file_position = 0
                    f.seek(0)

                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
