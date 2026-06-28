"""Manager constants — detection and ecosystem mappings.

This module provides:
- Detection constants (hardcoded — describe how to detect package manager
  installation, not dangerous commands)
- Manager name list and ecosystem mappings (previously from YAML)
- Helper functions for manager/ecosystem resolution
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# =============================================================================
# Manager Names (hardcoded — previously from YAML command dictionary)
# =============================================================================

MANAGER_NAMES: tuple[str, ...] = (
    "apt",
    "brew",
    "bundler",
    "bun",
    "cargo",
    "composer",
    "conda",
    "dnf",
    "gem",
    "npm",
    "pip",
    "pip3",
    "pipenv",
    "pipx",
    "pnpm",
    "poetry",
    "uv",
    "yarn",
    "yum",
)

# Manager → ecosystem mappings. Each manager maps to its correct package
# repository ecosystem (e.g., "pip" → "pypi", "brew" → "homebrew").
# ECOSYSTEM_TO_MANAGER is auto-derived from MANAGER_TO_ECOSYSTEM.
MANAGER_TO_ECOSYSTEM: dict[str, str] = {
    "pip": "pypi",
    "pip3": "pypi",
    "pipenv": "pypi",
    "pipx": "pypi",
    "poetry": "pypi",
    "uv": "pypi",
    "brew": "homebrew",
    "gem": "rubygems",
    "bundler": "rubygems",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    # One-to-one (manager name matches ecosystem name):
    "apt": "apt",
    "cargo": "cargo",
    "composer": "composer",
    "conda": "conda",
    "dnf": "dnf",
    "npm": "npm",
    "yum": "yum",
}

# Ecosystem → preferred manager (auto-derived first-wins preserves
# MANAGER_NAMES preference order: pip before uv, gem before bundler, etc.)
ECOSYSTEM_TO_MANAGER: dict[str, str] = {}
for _m, _e in MANAGER_TO_ECOSYSTEM.items():
    if _e not in ECOSYSTEM_TO_MANAGER:
        ECOSYSTEM_TO_MANAGER[_e] = _m

# =============================================================================
# Detection Constants (hardcoded — not from YAML)
# =============================================================================

# Package manager detection commands — used during `pkgd setup`.
# These are hardcoded because they describe how to detect if the manager
# is installed on the system, not the dangerous commands to intercept.
MANAGER_DETECTION_COMMANDS: dict[str, list[str]] = {
    "apt": ["apt", "--version"],
    "cargo": ["cargo", "--version"],
    "conda": ["conda", "--version"],
    "dnf": ["dnf", "--version"],
    "gem": ["gem", "--version"],
    "npm": ["npm", "--version"],
    "pip": ["pip", "--version"],
    "brew": ["brew", "--version"],
    "yum": ["yum", "--version"],
    "poetry": ["poetry", "--version"],
    "pipenv": ["pipenv", "--version"],
    "bun": ["bun", "--version"],
    "composer": ["composer", "--version"],
    "bundler": ["bundler", "--version"],
}

# Marker files for auto-detection of manager from CWD.
# These are hardcoded because they are file system paths, not dangerous commands.
MANAGER_MARKER_FILES: dict[str, list[str]] = {
    "npm": ["package.json"],
    "yarn": ["package.json", "yarn.lock"],
    "pnpm": ["package.json", "pnpm-lock.yaml"],
    "pip": ["pyproject.toml", "requirements.txt", "setup.py"],
    "uv": ["pyproject.toml", "uv.lock"],
    "pipx": ["pyproject.toml"],
    "cargo": ["Cargo.toml"],
    "gem": ["Gemfile"],
    "brew": ["Brewfile", "Formula"],
    "apt": ["/etc/apt/sources.list"],
    "yum": ["/etc/yum.repos.d/"],
    "dnf": ["/etc/dnf.repos.d/"],
    "conda": ["environment.yml", "environment.yaml", "conda-lock.json"],
    "poetry": ["pyproject.toml", "poetry.lock"],
    "pipenv": ["Pipfile", "Pipfile.lock"],
    "bun": ["package.json"],
    "composer": ["composer.json"],
    "bundler": ["Gemfile", "Gemfile.lock"],
}

# Managers with no reliable CWD marker — detect via system file instead.
_MANAGER_SYSTEM_CHECK: dict[str, str] = {
    "apt": "/etc/apt",
}

# =============================================================================
# Helper functions
# =============================================================================


def resolve_ecosystem(manager: str) -> str:
    """Resolve a manager name to its ecosystem identifier.

    Uses the MANAGER_TO_ECOSYSTEM mapping which maps each package manager
    to its correct package repository ecosystem (e.g., "pip" → "pypi",
    "brew" → "homebrew", "gem" → "rubygems").

    Args:
        manager: Package manager name (e.g., "pip", "gem").

    Returns:
        Ecosystem identifier (e.g., "pypi", "homebrew", "rubygems").

    Raises:
        ValueError: If manager is not recognized.
    """
    if manager not in MANAGER_TO_ECOSYSTEM:
        raise ValueError(f"Unknown package manager {manager!r}; supported: {list(MANAGER_NAMES)}")
    return MANAGER_TO_ECOSYSTEM[manager]


def get_manager(ecosystem: str) -> str:
    """Convert ecosystem to manager name.

    Searches through MANAGER_TO_ECOSYSTEM to find managers that handle
    the given ecosystem. Returns the preferred manager:
    - pypi -> uv (modern/fast)
    - npm -> yarn (modern/fast)
    - homebrew -> brew
    - rubygems -> gem

    Args:
        ecosystem: Package ecosystem identifier (e.g., "pypi", "homebrew", "conda").

    Returns:
        Manager name (e.g., "uv", "brew", "conda").

    Raises:
        ValueError: If ecosystem is not recognized.
    """
    # Direct lookup in ECOSYSTEM_TO_MANAGER
    if ecosystem in ECOSYSTEM_TO_MANAGER:
        manager = ECOSYSTEM_TO_MANAGER[ecosystem]
        # Skip self-referential mappings (homebrew -> homebrew is wrong)
        if manager != ecosystem:
            return manager

    # Search through MANAGER_TO_ECOSYSTEM for matching ecosystems
    # Priority order gives us the preferred managers
    _preferred_managers: dict[str, str] = {
        "pip": "uv",  # uv is the modern/fast Python manager
        "npm": "yarn",  # yarn is preferred over npm
        "homebrew": "brew",
        "rubygems": "gem",
    }

    if ecosystem in _preferred_managers:
        return _preferred_managers[ecosystem]

    # Fallback: search for any manager with this ecosystem
    for manager, eco in MANAGER_TO_ECOSYSTEM.items():
        if eco == ecosystem:
            return manager

    raise ValueError(f"Unknown ecosystem: {ecosystem}")


def _detect_manager_from_cwd() -> str:
    """Detect package manager from files in the current directory.

    This is the primary detection method, used when pkgd is invoked from a
    project directory. It looks for marker files (e.g., package-lock.json for npm,
    requirements.txt for pip) to identify the package manager.

    Returns:
        Package manager name (e.g., "npm", "pip", "cargo").
    """
    cwd = Path.cwd()
    for manager, markers in MANAGER_MARKER_FILES.items():
        for marker in markers:
            if (cwd / marker).exists():
                return manager
    # System-level detection: if /etc/apt exists, we're on Debian/Ubuntu
    if Path("/etc/apt").exists():
        return "apt"
    return "npm"  # safe fallback


async def _detect_manager_from_system_packages(package_name: str) -> str | None:
    """Detect which package manager has a package installed.

    Iterates through all package managers and calls their get_installed_version()
    function to determine which manager has the package installed.

    Args:
        package_name: Name of the package to search for.

    Returns:
        Manager name (e.g., "npm", "pip", "brew") if found, None otherwise.
    """
    # List of managers to check and their get_installed_version functions.
    # Order matters: more common managers checked first for faster detection.
    managers_to_check = [
        ("npm", "pkg_defender.registry.npm", "npm_get_installed_version"),
        ("pip", "pkg_defender.registry.pypi", "pip_get_installed_version"),
        ("pipx", "pkg_defender.registry.pypi", "pipx_get_installed_version"),
        ("cargo", "pkg_defender.registry.cargo", "cargo_get_installed_version"),
        ("rubygems", "pkg_defender.registry.rubygems", "rubygems_get_installed_version"),
        ("brew", "pkg_defender.registry.brew", "brew_get_installed_version"),
        ("apt", "pkg_defender.registry.apt", "apt_get_installed_version"),
        ("yum", "pkg_defender.registry.yum", "yum_get_installed_version"),
        ("dnf", "pkg_defender.registry.dnf", "dnf_get_installed_version"),
        ("conda", "pkg_defender.registry.conda", "conda_get_installed_version"),
        ("uv", "pkg_defender.registry.uv", "uv_get_installed_version"),
        ("yarn", "pkg_defender.registry.yarn", "yarn_get_installed_version"),
        ("pnpm", "pkg_defender.registry.pnpm", "pnpm_get_installed_version"),
        ("poetry", "pkg_defender.registry.poetry", "poetry_get_installed_version"),
        ("pipenv", "pkg_defender.registry.pipenv", "pipenv_get_installed_version"),
        ("bun", "pkg_defender.registry.bun", "bun_get_installed_version"),
        ("bundler", "pkg_defender.registry.bundler", "bundler_get_installed_version"),
        ("composer", "pkg_defender.registry.composer", "composer_get_installed_version"),
    ]

    for manager_name, module_name, func_name in managers_to_check:
        try:
            # Dynamic import avoids loading all modules at startup.
            import importlib

            module = importlib.import_module(module_name)
            get_installed_version = getattr(module, func_name, None)
            if get_installed_version is None:
                continue

            # Check if the package is installed by this manager.
            result = await get_installed_version(package_name)
            if result is not None:
                return manager_name
        except Exception:
            logger.debug("manager detection: version lookup failed for %s", manager_name)
            # Skip managers that error — they're likely not available on this system.
            continue

    return None


__all__ = [
    "ECOSYSTEM_TO_MANAGER",
    "MANAGER_DETECTION_COMMANDS",
    "MANAGER_MARKER_FILES",
    "MANAGER_NAMES",
    "MANAGER_TO_ECOSYSTEM",
    "_detect_manager_from_cwd",
    "_detect_manager_from_system_packages",
    "get_manager",
    "resolve_ecosystem",
]
