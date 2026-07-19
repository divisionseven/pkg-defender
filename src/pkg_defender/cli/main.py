# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point — Click commands for pkgd audit, intel, config, health, reset."""

from __future__ import annotations

import collections.abc
import logging
import os
import re
import sys
import types
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import click
from click.exceptions import NoArgsIsHelpError

from pkg_defender import __version__
from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli._exit_codes import EXIT_SIGINT as _EXIT_SIGINT
from pkg_defender.cli._exit_codes import EXIT_SUCCESS as _EXIT_SUCCESS
from pkg_defender.cli.banners import get_terminal_width, should_use_color
from pkg_defender.cli.common import (  # noqa: F401
    _detect_ecosystem_from_cwd,
    _detect_manager_from_cwd,
    _get_config_from_context,
    console,
    is_running_in_ci,
)
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.config import get_db_path, load_config  # noqa: F401
from pkg_defender.config.settings import get_default_config_path  # noqa: F401
from pkg_defender.logging_filter import SecretRedactingFilter

# Supported shells for setup/diagnostics
SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell", "nushell")


def setup_logging(verbosity: int, data_dir: Path) -> None:
    """Configure Python logging based on verbosity level.

    Uses explicit handler levels instead of ``basicConfig()`` to prevent
    log messages from internal modules leaking to the terminal. The console
    handler defaults to ERROR and only shows INFO+ with ``-v`` or DEBUG+
    with ``-vv``. The file handler always logs at DEBUG.

    Args:
        verbosity: 0 = default (ERROR to console), 1 = -v (INFO), 2 = -vv (DEBUG)
        data_dir: Path to store log files
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove existing handlers (including defaults from basicConfig)
    root_logger.handlers.clear()

    # Determine console level
    if verbosity >= 2:
        console_level = logging.DEBUG
    elif verbosity == 1:
        console_level = logging.INFO
    else:
        console_level = logging.ERROR

    # Console handler — user-facing messages only
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root_logger.addHandler(console_handler)

    # File handler — always DEBUG
    log_file = data_dir / "pkgd.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root_logger.addHandler(file_handler)

    redaction_filter = SecretRedactingFilter()
    root_logger.addFilter(redaction_filter)


def _get_first_line(docstring: str | None) -> str:
    """Extract only the first line of a docstring for short help display."""
    if not docstring:
        return ""
    first_line = docstring.split("\n")[0].strip()
    return first_line


class GroupedHelpFormatter(click.HelpFormatter):
    """Custom formatter matching standard CLI help style.

    - "Common Commands" at TOP (3-4 commands, NO aliases)
    - "Commands" below (ALL commands, WITH aliases inline)
    - Commands with aliases first, then commands without aliases
    - Options at BOTTOM
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._colmargin = 1

    def write_commands(self, ctx: click.Context, commands: dict[str, click.Command]) -> None:
        """Write commands in THREE sections: Common, Management, Commands."""
        if not commands:
            return

        common_commands = [
            "setup",
            "status",
            "audit",
            "bypass",
            "health",
            "reset",
        ]

        management_groups = ["config", "intel", "daemon", "setup"]

        common_rows: list[tuple[str, str]] = []
        management_rows: list[tuple[str, str]] = []
        standalone_rows: list[tuple[str, str]] = []

        def get_base_name(name: str | tuple[str, ...]) -> str:
            if isinstance(name, tuple):
                return name[0]
            return name

        def get_parent_group(name: str | tuple[str, ...]) -> str | None:
            if isinstance(name, str) and " " in name:
                return name.split(" ")[0]
            return None

        for name, cmd in commands.items():
            if cmd.hidden:
                continue

            full_help = cmd.help or cmd.short_help or ""
            help_text = _get_first_line(full_help)

            if isinstance(name, tuple):
                primary = name[0]
                aliases = name[1:]
                display_name = f"-{aliases[0]}, {primary}" if aliases else primary
            else:
                display_name = name

            base_name = get_base_name(name)
            parent_group = get_parent_group(name)

            if isinstance(cmd, click.Group) and cmd.list_commands(ctx):
                if base_name in management_groups:
                    management_rows.append((name, help_text))
            elif parent_group and parent_group in management_groups:
                standalone_rows.append((display_name, help_text))
            elif base_name in common_commands:
                common_rows.append((display_name, help_text))
            else:
                standalone_rows.append((display_name, help_text))

        common_rows.sort(key=lambda x: common_commands.index(x[0]) if x[0] in common_commands else 999)

        if not common_rows and not management_rows and not standalone_rows:
            return

        is_main_cli = len(commands) > 10

        if is_main_cli and common_rows:
            self.write_heading("Common Commands")
            self.write_dl(common_rows)
            self.write_text("")

        if is_main_cli and management_rows:
            self.write_heading("Management Commands")
            self.write_dl(management_rows)
            self.write_text("")

        if standalone_rows:
            self.write_heading("Commands")
            name_width = max(len(name) for name, _ in standalone_rows)
            name_width = min(name_width, 25)
            assert self.width is not None
            limit = self.width - name_width - 6
            if limit < 10:
                limit = 20
            self.write_dl(standalone_rows)
            self.write_text("")

    def write_options(self, ctx: click.Context, option_rows: list[tuple[str, str]]) -> None:
        """Write Global Options section at the END (after commands)."""
        if not option_rows:
            return

        self.write_heading("Global Options")

        opt_width = max(len(row[0]) for row in option_rows)
        opt_width = min(opt_width, 20)
        assert self.width is not None
        limit = self.width - opt_width - 6
        if limit < 10:
            limit = 20

        self.write_dl(option_rows)


def _show_version_callback(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    """Callback to show version and exit."""
    if value:
        click.echo(f"pkgd version {__version__}")
        ctx.exit(0)


@click.group(cls=ManagerGroup, invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-V",
    "--version",
    is_flag=True,
    callback=_show_version_callback,
    expose_value=False,
    is_eager=True,
    help="Show version information",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output")
@click.option(
    "--config",
    "-c",
    "config_file",
    type=click.Path(),
    default=None,
    help="Path to config file",
)
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option(
    "--ascii",
    is_flag=True,
    help="Force ASCII-only output (for Windows/CI environments)",
)
@click.option("--yes", "-y", "auto_confirm", is_flag=True, help="Skip confirmation prompts")
@click.option(
    "--force",
    "-f",
    "force_mode",
    is_flag=True,
    help="Skip confirmation prompts and force operations",
)
@click.option(
    "--debug",
    "-d",
    "debug_mode",
    is_flag=True,
    help="Show full tracebacks for unexpected errors",
)
@click.option(
    "--verbose",
    "-v",
    "verbose_count",
    count=True,
    help="Increase verbosity: -v (INFO), -vv (DEBUG)",
)
@click.option(
    "--no-verbose",
    is_flag=True,
    help="Disable verbose output (overrides PKGD_OUTPUT_VERBOSE env var)",
)
@click.option(
    "--dry-run",
    "-n",
    "dry_run_mode",
    is_flag=True,
    envvar="PKGD_DRY_RUN",
    help="Show what would be done without making changes",
)
@click.option(
    "--ci",
    "--non-interactive",
    "ci_mode",
    is_flag=True,
    help="Run in non-interactive CI mode (skip prompts, use env vars)",
)
@click.option(
    "--explain",
    "explain_mode",
    is_flag=True,
    help="Show detailed explanation of why packages were blocked",
)
@click.option(
    "--json",
    "json_flag",
    is_flag=True,
    help="Output result as JSON. For clearing commands (pass), JSON goes to "
    "stderr (use 2>result.json to capture). Use --dry-run --json for "
    "pipeable output.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    quiet: bool,
    config_file: str | None,
    no_color: bool,
    ascii: bool,
    auto_confirm: bool,
    force_mode: bool,
    debug_mode: bool,
    verbose_count: int,
    no_verbose: bool,
    dry_run_mode: bool,
    ci_mode: bool,
    explain_mode: bool,
    json_flag: bool = False,
) -> None:
    """pkg-defender \u2014 Supply chain attack defense CLI."""
    if ctx.invoked_subcommand is None:
        import sys

        if "--help" not in sys.argv and "-h" not in sys.argv:
            formatter = ctx.make_formatter()
            cli.format_help(ctx, formatter)
            ctx.exit(0)
        return

    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    ctx.obj["config_file"] = config_file
    ctx.obj["no_color"] = no_color
    ctx.obj["auto_confirm"] = auto_confirm or force_mode
    ctx.obj["force"] = force_mode
    ctx.obj["debug"] = debug_mode
    ctx.obj["verbose"] = verbose_count
    ctx.obj["dry_run"] = dry_run_mode
    ctx.obj["explain"] = explain_mode
    ctx.obj["json"] = json_flag
    ctx.obj["ascii"] = ascii
    if json_flag:
        ctx.obj["output_format"] = "json"

    if ci_mode or os.environ.get("PKGD_CI", "").lower() in ("1", "true", "yes"):
        ctx.obj["ci"] = True
        # CI mode auto-enables JSON output for machine-parseable results
        ctx.obj["output_format"] = "json"
    else:
        ctx.obj["ci"] = False

    from pkg_defender.cli._ci_detect import is_ci_environment

    if not ctx.obj["ci"]:
        ctx.obj["ci_auto_detected"] = is_ci_environment()
    else:
        ctx.obj["ci_auto_detected"] = False

    if no_color:
        from pkg_defender.cli._progress import set_progress_no_color
        from pkg_defender.cli.common import set_console_no_color
        from pkg_defender.display import set_no_color

        set_console_no_color()
        set_no_color()
        set_progress_no_color()

    if ascii:
        from pkg_defender.display import set_ascii_mode

        set_ascii_mode(True)

    if quiet:
        from pkg_defender.display import set_quiet_mode

        set_quiet_mode(True)

    from pkg_defender.display import set_verbose_mode

    if no_verbose:
        ctx.obj["verbose"] = 0
        set_verbose_mode(False)
    elif verbose_count >= 1:
        ctx.obj["verbose"] = verbose_count
        set_verbose_mode(True)
    else:
        config = load_config()
        ctx.obj["verbose"] = 1 if config.output.verbose else 0
        set_verbose_mode(config.output.verbose)

        # Wire config.output.color as baseline when no explicit override
        if not no_color and os.environ.get("NO_COLOR") is None:  # noqa: SIM102
            if not config.output.color:
                from pkg_defender.cli._progress import set_progress_no_color
                from pkg_defender.cli.common import set_console_no_color
                from pkg_defender.display import set_no_color

                set_console_no_color()
                set_no_color()
                set_progress_no_color()

    if debug_mode:
        os.environ["PKGD_DEBUG"] = "1"

    from pkg_defender.config.settings import get_data_dir
    from pkg_defender.display import is_verbose_mode

    data_dir = get_data_dir()
    effective_verbosity = verbose_count if verbose_count > 0 else (1 if is_verbose_mode() else 0)
    setup_logging(
        verbosity=effective_verbosity,
        data_dir=data_dir,
    )

    if verbose_count >= 1 or debug_mode:
        from pkg_defender.cli._dependency_check import check_outdated_tools

        outdated = check_outdated_tools()
        if outdated and not quiet:
            console.print("[yellow]Warning: Outdated tools detected:[/yellow]")
            for tool_info in outdated:
                console.print(f"  {tool_info['tool']}: {tool_info['installed']} (minimum: {tool_info['minimum']})")


def _format_epilog_preserve_newlines(self: click.Group, ctx: click.Context, formatter: click.HelpFormatter) -> None:
    """Format epilog without using cleandoc which collapses newlines in bullet lists."""
    if self.epilog:
        with formatter.indentation():
            epilog_text = self.epilog.rstrip("\n")
            lines = epilog_text.split("\n")
            for i, line in enumerate(lines):
                formatter.write(line)
                if i < len(lines) - 1:
                    formatter.write("\n")


def _expand_subcommands(
    commands: dict[str, click.Command] | collections.abc.MutableMapping[str, click.Command],
    ctx: click.Context,
) -> dict[str, click.Command]:
    """Expand Click groups to include their subcommands in the commands dict."""
    expanded: dict[str, click.Command] = {}
    for name, cmd in commands.items():
        expanded[name] = cmd
        if isinstance(cmd, click.Group):
            for subname in cmd.list_commands(ctx):
                subcmd = cmd.get_command(ctx, subname)
                if subcmd and not subcmd.hidden:
                    expanded[f"{name} {subname}"] = subcmd
    return expanded


def _custom_format_help(self: click.Group, ctx: click.Context, formatter: click.HelpFormatter) -> None:
    """Custom format_help that uses GroupedHelpFormatter."""
    from pkg_defender.cli.banners import get_banner

    show_help = "--help" in sys.argv or "-h" in sys.argv
    is_main_cli = self.name == "pkgd" or len(self.commands) > 10
    banner = get_banner()
    if banner and not show_help and is_main_cli:
        config = _get_config_from_context(ctx)
        if config.output.show_ascii_banner:
            click.echo(banner.rstrip(), color=should_use_color())

    if not isinstance(formatter, GroupedHelpFormatter):
        width = get_terminal_width() - 2
        custom_formatter = GroupedHelpFormatter(width=width)

        custom_formatter.write_text("")

        custom_formatter.write_usage(
            ctx.command_path,
            "[OPTIONS] COMMAND [ARGS...]",
            prefix="Usage (native):  ",
        )
        custom_formatter.write_usage(
            ctx.command_path,
            "[OPTIONS] MANAGER SUBCOMMAND [PACKAGE...] [MANAGER_OPTIONS...]",
            prefix="Usage (wrapper): ",
        )
        custom_formatter.write_text("")

        if is_main_cli:
            custom_formatter.write_text("PKG-Defender \u2014 The supply chain attack defense CLI")
            custom_formatter.write_text("Check packages for threats BEFORE they reach your machine or CI.")
            custom_formatter.write_text("")
        else:
            if self.help:
                custom_formatter.write_text(self.help)
                custom_formatter.write_text("")

        expanded_commands = _expand_subcommands(self.commands, ctx)

        custom_formatter.write_commands(ctx, expanded_commands)

        option_rows: list[tuple[str, str]] = []
        for param in self.get_params(ctx):
            help_record = param.get_help_record(ctx)
            if help_record is not None:
                option_rows.append(help_record)
        custom_formatter.write_options(ctx, option_rows)

        custom_formatter.write_text("")
        custom_formatter.write_text("Run 'pkgd COMMAND --help' for more information on a specific command.")

        _format_epilog_preserve_newlines(self, ctx, custom_formatter)

        output = "\n" + custom_formatter.getvalue()
        click.echo(output, color=should_use_color())
    else:
        formatter.write_text("")

        formatter.write_usage(
            ctx.command_path,
            "[OPTIONS] COMMAND [ARGS...]",
            prefix="Usage (native):  ",
        )
        formatter.write_usage(
            ctx.command_path,
            "[OPTIONS] MANAGER SUBCOMMAND [PACKAGE...] [MANAGER_OPTIONS...]",
            prefix="Usage (wrapper): ",
        )
        formatter.write_text("")

        is_main_cli = self.name == "pkgd" or len(self.commands) > 10

        if is_main_cli:
            formatter.write_text(
                "Supply chain attack defense CLI \u2014 check packages for threats BEFORE installation."
            )
            formatter.write_text("")
        elif self.help:
            formatter.write_text(self.help)
            formatter.write_text("")

        expanded_commands = _expand_subcommands(self.commands, ctx)

        formatter.write_commands(ctx, expanded_commands)

        option_rows = []
        for param in self.get_params(ctx):
            help_record = param.get_help_record(ctx)
            if help_record is not None:
                option_rows.append(help_record)
        formatter.write_options(ctx, option_rows)

        formatter.write_text("")
        formatter.write_text("Run 'pkgd COMMAND --help' for more information on a specific command.")

        if self.epilog:
            _format_epilog_preserve_newlines(self, ctx, formatter)

        output = "\n" + formatter.getvalue()
        click.echo(output, color=should_use_color())


object.__setattr__(cli, "format_help", types.MethodType(_custom_format_help, cli))

# ---------------------------------------------------------------------------
# Instance-level format_help/format_epilog patches (not class-level)
# ---------------------------------------------------------------------------
_original_command_format_help = click.Command.format_help


def _command_format_help_with_leading_newline(
    self: click.Command, ctx: click.Context, formatter: click.HelpFormatter
) -> None:
    """Wrapper to add ONE leading newline to individual command help output."""
    width = get_terminal_width() - 2
    custom_formatter = GroupedHelpFormatter(width=width)
    custom_formatter.write_text("")
    _original_command_format_help(self, ctx, custom_formatter)
    output = custom_formatter.getvalue()
    click.echo(output, color=should_use_color())


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _command_format_epilog_preserve_newlines(
    self: click.Command, ctx: click.Context, formatter: click.HelpFormatter
) -> None:
    """Format epilog without using cleandoc which collapses newlines in bullet lists.

    Strips ANSI escape sequences when color output is disabled, ensuring
    raw ANSI codes or click.style() output in epilogs respects --no-color and NO_COLOR.
    """
    if self.epilog:
        with formatter.indentation():
            epilog_text = self.epilog.rstrip("\n")
            if not should_use_color():
                epilog_text = _strip_ansi(epilog_text)
            lines = epilog_text.split("\n")
            for i, line in enumerate(lines):
                formatter.write(line)
                if i < len(lines) - 1:
                    formatter.write("\n")


# ---------------------------------------------------------------------------
# Apply instance-level format_help/format_epilog to all commands
# (replaces class-level patches on click.Command to limit blast radius)
# ---------------------------------------------------------------------------


def _patch_command_instance(cmd: click.Command) -> None:
    """Apply format_help and format_epilog patches to a single command instance."""
    object.__setattr__(cmd, "format_help", types.MethodType(_command_format_help_with_leading_newline, cmd))
    object.__setattr__(cmd, "format_epilog", types.MethodType(_command_format_epilog_preserve_newlines, cmd))


def _patch_all_commands(group: click.Group) -> None:
    """Recursively apply instance-level patches to a group and all sub-commands.

    This limits format_help/format_epilog patches to only pkgd's own commands,
    rather than mutating click.Command globally.
    """
    for cmd in group.commands.values():
        if isinstance(cmd, click.Group):
            _patch_all_commands(cmd)
        _patch_command_instance(cmd)


# ---------------------------------------------------------------------------
# CLI Registration: Import command modules (triggers @cli.command() decorators)
# ---------------------------------------------------------------------------

import pkg_defender.cli.commands.audit  # noqa: F401, E402
import pkg_defender.cli.commands.audit_logs  # noqa: F401, E402
import pkg_defender.cli.commands.bypass  # noqa: F401, E402
import pkg_defender.cli.commands.completion  # noqa: F401, E402
import pkg_defender.cli.commands.config  # noqa: F401, E402
import pkg_defender.cli.commands.daemon  # noqa: F401, E402
import pkg_defender.cli.commands.db  # noqa: F401, E402
import pkg_defender.cli.commands.health  # noqa: F401, E402
import pkg_defender.cli.commands.hooks  # noqa: F401, E402
import pkg_defender.cli.commands.intel  # noqa: F401, E402
import pkg_defender.cli.commands.logs  # noqa: F401, E402
import pkg_defender.cli.commands.reset  # noqa: F401, E402
import pkg_defender.cli.commands.setup  # noqa: F401, E402
import pkg_defender.cli.commands.status  # noqa: F401, E402

_patch_all_commands(cli)


def _handle_exception(e: Exception, debug: bool = False) -> int:
    """Handle unexpected exceptions with appropriate output.

    Args:
        e: The exception to handle.
        debug: If True, show full traceback. Otherwise, show user-friendly message.

    Returns:
        The exit code to return.
    """
    if debug:
        import traceback

        click.echo(traceback.format_exc(), err=True)
    else:
        click.echo(f"Error: {e}", err=True)
        click.echo(
            "Run 'pkgd --debug' to see full error details.",
            err=True,
        )
    return _EXIT_GENERAL_ERROR


def _handle_sigint(signum: int, frame: Any) -> None:
    """Signal handler for SIGINT (Ctrl+C)."""
    import sys as _sys

    _sys.exit(_EXIT_SIGINT)


def run_cli(
    args: list[str] | None = None,
    standalone: bool = True,
) -> int:
    """Programmatic CLI entry point.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:]).
        standalone: If True, exit with the return code. If False, return the code.

    Returns:
        Exit code (only when standalone=False).
    """
    debug = os.environ.get("PKGD_DEBUG") == "1"

    import signal as _signal

    _signal.signal(_signal.SIGINT, _handle_sigint)

    try:
        exit_code: int = cli.main(args, standalone_mode=False)

        if exit_code is None:
            exit_code = _EXIT_SUCCESS
    except NoArgsIsHelpError:
        exit_code = _EXIT_SUCCESS
    except click.UsageError as e:
        e.show()
        exit_code = e.exit_code
    except Exception as e:
        exit_code = _handle_exception(e, debug)

    if standalone:
        import sys

        sys.exit(exit_code)

    return exit_code


if __name__ == "__main__":
    run_cli()
