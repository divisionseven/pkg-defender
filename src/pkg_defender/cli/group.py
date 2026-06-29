"""Custom Click group that routes unknown subcommand names to package manager dispatcher."""

from __future__ import annotations

import click


class ManagerGroup(click.Group):
    """
    Custom Click Group that catches unknown subcommands and checks
    if they are known package manager names before raising an error.

    This enables the unified wrapper pattern:
        pkgd pip install requests
        pkgd npm install express
        pkgd brew install tree
    """

    def list_commands(self, ctx: click.Context) -> list[str]:
        """List commands sorted alphabetically."""
        return sorted(self.commands.keys(), key=str)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """
        Get command by name with fuzzy matching and manager routing.

        Priority:
        1. Native pkgd subcommands (audit, intel, status, etc.) — handled by parent
        2. Known package managers (pip, npm, brew, etc.) — route to dispatcher
        3. Fuzzy match for unknown commands — suggests close matches via difflib
        4. Unknown — return None (Click raises UsageError naturally)

        Note: This method incorporates the fuzzy matching logic previously
        implemented as a class-level monkey-patch on ``click.Group.get_command``.
        No monkey-patch is needed — the logic lives directly in this override.
        """
        # 1. Direct match
        if cmd_name in self.commands:
            return self.commands[cmd_name]

        # 2. Manager name check (lazy import avoids circular dependency)
        from pkg_defender.registry import get_adapter_class_for_manager

        if get_adapter_class_for_manager(cmd_name) is not None:
            return make_manager_passthrough_command(cmd_name)

        # 3. Fuzzy match for unknown commands
        resilient = getattr(ctx, "resilient_parsing", False)
        if ctx and not resilient:
            import difflib

            matches = difflib.get_close_matches(cmd_name, list(self.commands.keys()), n=1, cutoff=0.6)
            if matches:
                ctx.fail(f"No such command '{cmd_name}'. Did you mean '{matches[0]}'?")
            else:
                ctx.fail(f"No such command '{cmd_name}'. Run 'pkgd --help' to see available commands.")

        return None

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """
        Required override: prevents Click from consuming manager args
        during its own resolution phase.

        When a known manager name is detected as the first argument,
        we return it as the command name and pass the remaining args.
        """
        cmd_name = args[0] if args else None
        if cmd_name:
            from pkg_defender.registry import get_adapter_class_for_manager

            if get_adapter_class_for_manager(cmd_name) is not None:
                cmd = self.get_command(ctx, cmd_name)
                assert cmd is not None
                return cmd_name, cmd, args[1:]
        return super().resolve_command(ctx, args)


def make_manager_passthrough_command(manager_name: str) -> click.Command:
    """
    Dynamically creates a Click Command for a manager that collects
    all remaining args as raw unprocessed strings and hands them off
    to the ManagerDispatcher.

    Key settings:
    - ignore_unknown_options=True: manager flags like --index-url don't cause Click errors
    - allow_extra_args=True: collects everything into manager_args
    - allow_interspersed_args=False: does not reorder flags and positional args
    - type=click.UNPROCESSED: args collected as raw strings, no Click transformation
    """

    @click.command(
        name=manager_name,
        context_settings={
            "ignore_unknown_options": True,
            "allow_extra_args": True,
            "allow_interspersed_args": False,  # Critical: don't reorder flags
        },
        epilog=(
            "\b\n"
            "PKGD-specific options (also accepted before the manager name, "
            "e.g. `pkgd --dry-run pip install`):\n"
            "  --cooldown HOURS     Override the cooldown window (minimum package age in hours).\n"
            "  --dry-run, -n        Show what would happen without making changes.\n"
            "  --json               Output result as JSON.\n"
            "  --verbose, -v        Increase verbosity.\n"
            "  --ci, --non-interactive\n"
            "                       Run in non-interactive CI mode.\n"
            "  --explain            Show detailed explanation for blocked packages.\n"
            "  --force, -f          Skip confirmation prompts."
        ),
    )
    @click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)
    @click.option(
        "--fail-on-threat",
        is_flag=True,
        default=None,
        help="Exit with code 1 when threats are detected (default: enabled by config)",
    )
    @click.option(
        "--allow-once",
        is_flag=False,
        flag_value="24h",
        default=None,
        metavar="DURATION",
        help="Allow this single install, bypassing cooldown for a limited time (default: 24h, e.g. --allow-once=6h).",
    )
    @click.option(
        "--bypass-cooldown",
        is_flag=True,
        default=None,
        help="Bypass cooldown check for this install (threat checks still run).",
    )
    @click.option(
        "--bypass-threat",
        is_flag=True,
        default=None,
        help="Bypass threat check for this install (cooldown still enforced).",
    )
    @click.pass_context
    def _manager_cmd(
        ctx: click.Context,
        manager_args: tuple[str, ...],
        fail_on_threat: bool | None,
        allow_once: str | None,
        bypass_cooldown: bool | None,
        bypass_threat: bool | None,
    ) -> None:
        """Dynamic command that routes to the appropriate manager dispatcher."""
        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.config import load_config

        # Store fail_on_threat in context for dispatcher to use
        config = load_config()
        if fail_on_threat is None:
            # Use config default if flag not specified
            fail_on_threat = config.fail_on_threat_enabled
        ctx.obj = ctx.obj or {}
        ctx.obj["fail_on_threat"] = fail_on_threat
        ctx.obj["allow_once"] = allow_once
        ctx.obj["bypass_cooldown"] = bypass_cooldown
        ctx.obj["bypass_threat"] = bypass_threat

        dispatcher = ManagerDispatcher(manager_name)
        dispatcher.run(list(manager_args), ctx)

    return _manager_cmd
