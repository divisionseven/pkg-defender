"""Dependency version checking utilities."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys

# Minimum versions for key tools
MIN_VERSIONS: dict[str, str] = {
    "pip": "21.0",
    "npm": "8.0",
    "python": "3.11",
}


def get_tool_version(tool: str) -> str | None:
    """Get installed version of a tool.

    Args:
        tool: Tool name (pip, npm, python, etc.)

    Returns:
        Version string or None if not found.
    """
    if tool == "python":
        return f"{sys.version_info.major}.{sys.version_info.minor}"

    tool_path = shutil.which(tool)
    if not tool_path:
        return None

    for flag in ["--version", "-v", "-V", "version"]:
        try:
            result = subprocess.run(
                [tool_path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout + result.stderr
                return _parse_version(output)
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            continue
        except OSError:
            continue
        except ValueError:
            continue
    return None


def _parse_version(output: str) -> str | None:
    """Parse version string from command output."""
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
    return match.group(1) if match else None


def check_outdated_tools() -> list[dict[str, str]]:
    """Check for outdated tools.

    Returns:
        List of dicts with 'tool', 'installed', 'minimum' keys.
    """
    warnings: list[dict[str, str]] = []
    for tool, minimum in MIN_VERSIONS.items():
        installed = get_tool_version(tool)
        if installed and _version_lt(installed, minimum):
            warnings.append(
                {
                    "tool": tool,
                    "installed": installed,
                    "minimum": minimum,
                }
            )
    return warnings


def _version_lt(v1: str, v2: str) -> bool:
    """Return True if *v1* is less than *v2*.

    Delegates to :func:`pkg_defender.version.compare_versions`.
    """
    from pkg_defender.version import compare_versions

    return compare_versions(v1, v2) < 0
