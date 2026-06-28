"""Shell detection utilities.

This module provides functions for detecting the user's shell from environment
variables and determining shell-specific configuration paths.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Supported shell types
SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell", "nushell")

# Shell name mapping for normalization
_SHELL_NAME_MAP: dict[str, str] = {
    "bash": "bash",
    "/bin/bash": "bash",
    "/usr/bin/bash": "bash",
    "/usr/local/bin/bash": "bash",
    "zsh": "zsh",
    "/bin/zsh": "zsh",
    "/usr/bin/zsh": "zsh",
    "/usr/local/bin/zsh": "zsh",
    "fish": "fish",
    "/usr/bin/fish": "fish",
    "/usr/local/bin/fish": "fish",
    "powershell": "powershell",
    "pwsh": "powershell",
    "/usr/bin/pwsh": "powershell",
    "/usr/local/bin/pwsh": "powershell",
    "/opt/homebrew/bin/pwsh": "powershell",
    "nushell": "nushell",
    "nu": "nushell",
    "/usr/bin/nu": "nushell",
    "/usr/local/bin/nu": "nushell",
}


def detect_shell() -> str:
    """Detect the user's shell from the SHELL environment variable.

    Returns:
        The detected shell name (one of SUPPORTED_SHELLS), or 'bash' as fallback.

    Examples:
        >>> os.environ["SHELL"] = "/bin/zsh"
        >>> detect_shell()
        'zsh'
        >>> os.environ["SHELL"] = "/bin/bash"
        >>> detect_shell()
        'bash'
    """
    shell_path = os.environ.get("SHELL")

    if not shell_path:
        logger.warning("No SHELL environment variable detected, defaulting to bash")
        return "bash"

    # Normalize shell path to shell name
    shell_name = _SHELL_NAME_MAP.get(shell_path)

    if shell_name:
        return shell_name

    # Extract shell name from path if not in map
    shell_name = Path(shell_path).name

    # Try to normalize common shell names
    if shell_name == "pwsh":
        shell_name = "powershell"
    elif shell_name == "nu":
        shell_name = "nushell"

    # Check if normalized shell is supported
    if shell_name in SUPPORTED_SHELLS:
        return shell_name

    # Fallback to bash with warning
    logger.warning(
        f"Shell '{shell_path}' is not supported, defaulting to bash. "
        f"Supported shells: {', '.join(sorted(SUPPORTED_SHELLS))}"
    )
    return "bash"


def get_shell_config_path(shell: str) -> Path:
    """Get the completion script installation path for a given shell.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).

    Returns:
        The path where the completion script should be installed.

    Raises:
        ValueError: If the shell is not supported.

    Examples:
        >>> get_shell_config_path("bash")
        Path('~/.local/share/bash-completion/completions/pkgd')
        >>> get_shell_config_path("zsh")
        Path('~/.zsh/completions/_pkgd')
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


def get_shell_executable(shell: str) -> str:
    """Get the executable path for a given shell.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).

    Returns:
        The shell executable name or path.

    Examples:
        >>> get_shell_executable("bash")
        'bash'
        >>> get_shell_executable("powershell")
        'pwsh'
    """
    shell_executables: dict[str, str] = {
        "bash": "bash",
        "zsh": "zsh",
        "fish": "fish",
        "powershell": "pwsh",
        "nushell": "nu",
    }

    return shell_executables.get(shell, shell)


def is_shell_installed(shell: str) -> bool:
    """Check if a shell is installed and available on the system.

    Args:
        shell: The shell name (one of SUPPORTED_SHELLS).

    Returns:
        True if the shell is installed, False otherwise.

    Examples:
        >>> is_shell_installed("bash")
        True
        >>> is_shell_installed("nonexistent")
        False
    """
    executable = get_shell_executable(shell)

    return shutil.which(executable) is not None
