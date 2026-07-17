# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd completion group and subcommands."""

from __future__ import annotations

import os

import click

from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli


@cli.group(cls=ManagerGroup, name="completion", epilog="See also: pkgd completion generate")
def completion_group() -> None:
    """Shell tab completion commands."""


@completion_group.command(name="generate")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish", "powershell", "nushell"]))
@click.option(
    "--executable",
    "-e",
    default="pkgd",
    help="Name of the executable (default: pkgd)",
)
def completion_generate(shell: str, executable: str) -> None:
    """Generate shell completion script.

    Outputs the shell completion script for the specified shell.
    Redirect output to a file or pipe to shell to install.

    Examples:

    \b
        pkgd completion generate bash > /etc/bash_completion.d/pkgd
        pkgd completion generate zsh > ~/.zsh/completions/_pkgd
        pkgd completion generate fish | source
        pkgd completion generate powershell > ~/Documents/PowerShell/pkgd_completion.ps1
        pkgd completion generate nushell > ~/.config/nushell/completions/pkgd.nu

    EXIT CODES:
        0    Script generated successfully

    SEE ALSO:
        pkgd hooks verify

    \f
    """
    prog_name_upper = executable.upper().replace("-", "_")
    complete_env = f"_{prog_name_upper}_COMPLETE"

    os.environ[complete_env] = f"{shell}_source"

    from pkg_defender.cli import cli

    ctx = click.Context(cli)
    try:
        cli.main(prog_name=executable, standalone_mode=False, args=[], ctx=ctx)
    except SystemExit as e:
        if e.code is not None and e.code != 0:
            raise
