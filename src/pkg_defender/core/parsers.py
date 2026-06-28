"""Lock file parsers for various package manager formats."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# Lock file detection order (highest priority first).
LOCK_FILE_NAMES: list[str] = [
    "package-lock.json",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
]

# Maps lock file basenames to their ecosystem identifier.
_ECOSYSTEM_MAP: dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "poetry.lock": "pypi",
    "Pipfile.lock": "pypi",
    "requirements.txt": "pypi",
    "uv.lock": "pypi",
}

# Directories to skip during recursive lock file discovery.
_SKIP_DIRS: set[str] = {
    ".venv",
    "venv",
    ".env",
    "env",
    "node_modules",
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".tox",
    "build",
    "dist",
    ".eggs",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


def find_lock_files(project_path: Path) -> list[Path]:
    """Recursively find all recognised lock files under *project_path*.

    Walks the directory tree, skipping common virtual environment, cache,
    and VCS directories. Returns paths sorted by directory depth then
    by ``LOCK_FILE_NAMES`` priority (npm lock files first).

    Args:
        project_path: Root directory to search.

    Returns:
        List of ``Path`` objects for every recognised lock file found.
        Empty list if none found.
    """
    project_path = Path(project_path).resolve()  # Normalise to absolute
    found: list[Path] = []
    lock_names_set: set[str] = set(LOCK_FILE_NAMES)

    for root, dirs, files in os.walk(project_path, topdown=True):
        # Prune skipped directories in-place (modifies dirs in-place for os.walk)
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        for fname in files:
            if fname in lock_names_set:
                found.append(Path(root) / fname)

    # Sort: by directory depth (shallow first), then by priority in LOCK_FILE_NAMES
    found.sort(
        key=lambda p: (
            len(p.relative_to(project_path).parents),
            LOCK_FILE_NAMES.index(p.name) if p.name in LOCK_FILE_NAMES else 99,
        )
    )
    return found


def detect_lock_file(project_path: Path) -> Path | None:
    """Return the first recognised lock file found in *project_path*.

    Checks for files in priority order defined by :data:`LOCK_FILE_NAMES`.

    Args:
        project_path: Directory to scan for lock files.

    Returns:
        Path to the first lock file found, or ``None`` if no recognised
        lock file exists.
    """
    for name in LOCK_FILE_NAMES:
        candidate = project_path / name
        if candidate.is_file():
            return candidate
    return None


def parse_lock_file(lock_path: Path) -> list[dict[str, str]]:
    """Detect format from filename and dispatch to the appropriate parser.

    Args:
        lock_path: Path to a lock file.

    Returns:
        List of dicts with keys ``package``, ``version``, ``ecosystem``.
    """
    filename = lock_path.name

    if filename == "package-lock.json":
        return parse_package_lock(lock_path)
    if filename == "poetry.lock":
        return parse_poetry_lock(lock_path)
    if filename == "requirements.txt":
        return parse_requirements_txt(lock_path)
    if filename == "Pipfile.lock":
        return parse_pipfile_lock(lock_path)
    if filename == "yarn.lock":
        return parse_yarn_lock(lock_path)
    if filename == "pnpm-lock.yaml":
        return parse_pnpm_lock(lock_path)
    if filename == "uv.lock":
        return parse_uv_lock(lock_path)

    # Unsupported format — return empty list rather than raising.
    return []


def parse_package_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``package-lock.json`` (v2 and v3 formats).

    v3 (and v2 with ``packages``): flat dict keyed by
    ``node_modules/<package>``.  v2 without ``packages``: nested
    ``dependencies`` dict.

    Args:
        path: Path to ``package-lock.json``.

    Returns:
        List of ``{"package", "version", "ecosystem": "npm"}`` dicts.
    """
    with open(path, encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    results: list[dict[str, str]] = []

    if "packages" in data:
        # v3 (and v2 that also has packages): flat structure
        for key, info in data["packages"].items():
            name = key.removeprefix("node_modules/")
            if not name or not isinstance(info, dict):
                continue
            version = info.get("version")
            if version:
                results.append({"package": name, "version": version, "ecosystem": "npm"})
    elif "dependencies" in data:
        # v2 fallback: nested dependencies
        _collect_npm_dependencies(data["dependencies"], results)

    return results


def _collect_npm_dependencies(
    deps: dict[str, Any],
    results: list[dict[str, str]],
) -> None:
    """Recursively collect npm packages from a nested ``dependencies`` dict."""
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version:
            results.append({"package": name, "version": version, "ecosystem": "npm"})
        # Walk nested dependencies (v2 lockfile format)
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _collect_npm_dependencies(nested, results)


def parse_poetry_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``poetry.lock`` (TOML format) using ``tomllib``.

    Each ``[[package]]`` section has ``name`` and ``version`` fields.

    Args:
        path: Path to ``poetry.lock``.

    Returns:
        List of ``{"package", "version", "ecosystem": "pypi"}`` dicts.
    """
    import tomllib

    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    results: list[dict[str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            results.append({"package": name, "version": version, "ecosystem": "pypi"})
    return results


# Pattern matching an exact pin: ``package==version``
# Handles extras like ``pkg[extra]==1.0`` and environment markers like ``; python_version < "3.10"``
_REQUIREMENTS_EXACT_RE = re.compile(
    r"^"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"  # optional extras
    r"=="
    r"(?P<version>[^\s;]+)"  # version (stop at space or semicolon)
    r"(?:\s*;.*)?"  # optional environment marker
    r"$"
)


def parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    """Parse ``requirements.txt`` line-by-line.

    Extracts **exact** version pins only (``package==version``).
    Skips comments, blank lines, ``-r`` includes, options (``--index-url``
    etc.), and range specifiers (``>=``, ``~=``, etc.).

    Args:
        path: Path to ``requirements.txt``.

    Returns:
        List of ``{"package", "version", "ecosystem": "pypi"}`` dicts.
    """
    results: list[dict[str, str]] = []

    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("-"):
                continue

            match = _REQUIREMENTS_EXACT_RE.match(line)
            if match:
                results.append(
                    {
                        "package": match.group("name").lower(),
                        "version": match.group("version"),
                        "ecosystem": "pypi",
                    }
                )

    return results


def parse_pipfile_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``Pipfile.lock`` (JSON format).

    Extracts packages from both ``default`` and ``develop`` sections.
    Each entry maps a package name to ``{"version": "==X.Y.Z"}``.
    The ``==`` (or other operator) prefix is stripped from the version.

    Args:
        path: Path to ``Pipfile.lock``.

    Returns:
        List of ``{"package", "version", "ecosystem": "pypi"}`` dicts.
    """
    with open(path, encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    results: list[dict[str, str]] = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            if not isinstance(info, dict):
                continue
            version_raw = info.get("version")
            if version_raw:
                results.append(
                    {
                        "package": name,
                        "version": version_raw.lstrip("="),
                        "ecosystem": "pypi",
                    }
                )
    return results


# Regex matching a yarn.lock dependency header line.
# Captures the package name (including scoped @scope/pkg) before the first @version.
# Handles both quoted and unquoted headers:
#   lodash@^4.17.21:          (unquoted, non-scoped)
#   "lodash@^4.17.21":        (quoted, non-scoped — yarn v2+)
#   "@babel/core@^7.20.0":    (quoted, scoped)
_YARN_HEADER_RE = re.compile(r'^"?(@?[^@"]+?)(?:@[^,:\"]+)(?:\s*,\s*@[^,:\"]+)*"?:\s*$')

# Regex matching an indented version line inside a yarn.lock entry.
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')


def parse_yarn_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``yarn.lock`` (custom text format) using regex.

    yarn.lock uses a custom text format where non-indented lines ending
    with ``:`` are dependency headers and indented ``version "X.Y.Z"``
    lines give the resolved version.

    Handles both yarn v1 and v2 lock file formats and scoped packages
    like ``@babel/core``.

    Args:
        path: Path to ``yarn.lock``.

    Returns:
        List of ``{"package", "version", "ecosystem": "npm"}`` dicts.
    """
    results: list[dict[str, str]] = []
    current_name: str | None = None

    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            # Check for a dependency header (non-indented, ends with :)
            header_match = _YARN_HEADER_RE.match(line)
            if header_match:
                current_name = header_match.group(1)
                continue

            # Check for a version line (indented)
            if current_name is not None:
                version_match = _YARN_VERSION_RE.match(line)
                if version_match:
                    results.append(
                        {
                            "package": current_name,
                            "version": version_match.group(1),
                            "ecosystem": "npm",
                        }
                    )
                    current_name = None

    return results


def parse_pnpm_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``pnpm-lock.yaml`` (YAML format) using PyYAML.

    The top-level ``packages`` dict has keys of the form
    ``/<name>@<version>`` (with a leading slash).  Scoped packages use
    ``/@scope/name@version``.

    Requires ``pyyaml>=6.0``.

    Args:
        path: Path to ``pnpm-lock.yaml``.

    Returns:
        List of ``{"package", "version", "ecosystem": "npm"}`` dicts.
    """
    from yaml import safe_load

    with open(path, encoding="utf-8") as fh:
        data = safe_load(fh)

    results: list[dict[str, str]] = []
    packages: dict[str, Any] = data.get("packages", {}) if isinstance(data, dict) else {}

    for key in packages:
        if not isinstance(key, str) or not key.startswith("/"):
            continue

        # Strip leading "/"
        raw = key[1:]

        # Handle scoped packages: @scope/name@version
        if raw.startswith("@"):
            # Scoped: find the second @ which separates name from version
            at_idx = raw.find("@", 1)
            if at_idx == -1:
                continue
            name = raw[:at_idx]
            version = raw[at_idx + 1 :]
        else:
            # Normal: split on last @
            at_idx = raw.rfind("@")
            if at_idx == -1:
                continue
            name = raw[:at_idx]
            version = raw[at_idx + 1 :]

        if name and version:
            results.append({"package": name, "version": version, "ecosystem": "npm"})

    return results


def parse_uv_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``uv.lock`` (TOML format) using ``tomllib``.

    Uses the same ``[[package]]`` array structure as ``poetry.lock``.
    Each entry has ``name`` and ``version`` fields.

    Args:
        path: Path to ``uv.lock``.

    Returns:
        List of ``{"package", "version", "ecosystem": "pypi"}`` dicts.
    """
    import tomllib

    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    results: list[dict[str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            results.append({"package": name, "version": version, "ecosystem": "pypi"})
    return results
