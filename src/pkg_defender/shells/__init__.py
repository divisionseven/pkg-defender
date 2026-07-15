# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Shell detection and completion installation utilities.

This module provides utilities for detecting the user's shell and installing
completion scripts for various shell types (bash, zsh, fish, powershell, nushell).
"""

from pkg_defender.shells.detect import (
    detect_shell,
    get_shell_config_path,
    get_shell_executable,
    is_shell_installed,
)
from pkg_defender.shells.install import install_completion

__all__ = [
    "detect_shell",
    "get_shell_config_path",
    "get_shell_executable",
    "is_shell_installed",
    "install_completion",
]
