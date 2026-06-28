"""Completion script installation utilities.

This module provides functions for installing completion scripts for various
shell types (bash, zsh, fish, powershell, nushell).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Supported shell types
SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell", "nushell")


def install_completion(shell: str, dry_run: bool = False) -> None:
    """Install completion script for the specified shell.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).
        dry_run: If True, show what would be done without modifying files.

    Raises:
        ValueError: If the shell is not supported.

    Note:
        Click's completion generation only supports bash, zsh, and fish.
        For powershell and nushell, this will log a warning and skip installation.

    Examples:
        >>> install_completion("bash")
        >>> install_completion("zsh", dry_run=True)
    """
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"Unsupported shell: {shell}. Supported shells: {SUPPORTED_SHELLS}")

    completion_path = get_shell_config_path(shell)

    if dry_run:
        logger.info(f"Would install completion script to {completion_path}")
        return

    completion_script = _generate_completion_script(shell)

    if not completion_script:
        # Click doesn't support completion generation for this shell
        logger.warning(
            f"Skipping completion installation for '{shell}' - "
            f"not supported by Click's completion generator. "
            f"Use 'pkgd completion generate {shell}' to manually generate completions."
        )
        return

    completion_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        completion_path.write_text(completion_script)
        logger.info(f"Installed completion script to {completion_path}")
    except PermissionError as e:
        raise RuntimeError(f"Permission denied: Cannot write to {completion_path}. Please check permissions.") from e
    except OSError as e:
        raise RuntimeError(f"Cannot write to {completion_path}: {e}") from e


def get_shell_config_path(shell: str) -> Path:
    """Get the completion script installation path for a given shell.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).

    Returns:
        The path where the completion script should be installed.

    Raises:
        ValueError: If the shell is not supported.
    """
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"Unsupported shell: {shell}. Supported shells: {SUPPORTED_SHELLS}")

    home = Path.home()

    shell_paths: dict[str, Path] = {
        "bash": home / ".local" / "share" / "bash-completion" / "completions" / "pkgd",
        "zsh": home / ".zsh" / "completions" / "_pkgd",
        "fish": home / ".config" / "fish" / "completions" / "pkgd.fish",
        "powershell": home / ".config" / "powershell" / "pkgd_completion.ps1",
        "nushell": home / ".config" / "nushell" / "completions" / "pkgd.nu",
    }

    return shell_paths[shell]


def _generate_completion_script(shell: str) -> str | None:
    """Generate completion script for the specified shell.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).

    Returns:
        The completion script content, or None if generation fails.

    Note:
        Click's completion generation only supports bash, zsh, and fish.
        For powershell and nushell, this will return None.
    """
    # Click only supports bash, zsh, and fish for completion generation
    click_supported_shells = {"bash", "zsh", "fish"}

    if shell not in click_supported_shells:
        logger.warning(
            f"Completion generation for '{shell}' is not yet supported by Click. "
            f"Supported shells for automatic completion: {', '.join(sorted(click_supported_shells))}"
        )
        return None

    # Set environment variable to trigger Click's completion generation
    prog_name_upper = "PKGD"
    complete_env = f"_{prog_name_upper}_COMPLETE"
    os.environ[complete_env] = f"{shell}_source"

    # Import and invoke the CLI to trigger Click's internal completion script output
    try:
        import click

        from pkg_defender.cli import cli

        ctx = click.Context(cli)

        # Capture stdout to get the completion script
        from io import StringIO

        old_stdout = sys.stdout
        sys.stdout = StringIO()

        try:
            # Click 8.x automatic: calls sys.exit with script if env var is set
            cli.main(prog_name="pkgd", standalone_mode=False, args=[], ctx=ctx)
        except SystemExit as e:
            if e.code is not None and e.code != 0:
                logger.warning(f"Completion generation exited with code {e.code}")
        finally:
            completion_script = sys.stdout.getvalue()
            sys.stdout = old_stdout

        return completion_script if completion_script.strip() else None

    except Exception as e:
        logger.error(f"Failed to generate completion script for {shell}: {e}")
        return None
