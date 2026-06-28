"""CLI interface."""

from pkg_defender.cli._ci_detect import get_ci_provider, is_ci_environment
from pkg_defender.cli.dispatcher import ManagerDispatcher
from pkg_defender.cli.exec import (
    exec_cleared_command,
    handle_blocked_command,
    handle_cleared_command,
)
from pkg_defender.cli.group import ManagerGroup, make_manager_passthrough_command
from pkg_defender.cli.main import cli, run_cli

__all__ = [
    "cli",
    "run_cli",
    "is_ci_environment",
    "get_ci_provider",
    "ManagerGroup",
    "make_manager_passthrough_command",
    "ManagerDispatcher",
    "exec_cleared_command",
    "handle_cleared_command",
    "handle_blocked_command",
]
