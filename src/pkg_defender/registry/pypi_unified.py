"""Unified PyPI adapter — combines PyPIAdapter registry lookups with PipAdapter command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.flags import PIP_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_python_package
from pkg_defender.registry.pypi import PyPIAdapter


class PyPIUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for pip — PyPI registry lookups + pip command parsing.

    Combines:
    - Registry methods from PyPIAdapter (get_publish_time, get_all_versions,
      get_latest_version, get_installed_version)
    - Manager methods from PipAdapter (parse, build_exec_args,
      COMMAND_INTENT_MAP)

    Uses composition over inheritance: a PyPIAdapter instance is created
    internally and all registry methods delegate to it, avoiding code
    duplication of the complex multi-source fallback chain in
    get_publish_time.
    """

    manager_name: str = "pip"
    ecosystem: str = "pypi"
    coverage_tier: CoverageTier = CoverageTier.FULL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "download": CommandIntent.INSTALL,
        "wheel": CommandIntent.INSTALL,  # pip wheel builds wheel, pulls deps
        "sync": CommandIntent.SYNC,  # pip-tools sync
    }

    VALUE_FLAGS: frozenset[str] = PIP_VALUE_FLAGS

    registry_base_url: str = "https://pypi.org"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by PyPI ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to PyPIAdapter ---

    def __init__(self) -> None:
        """Initialize with PyPIAdapter delegate for registry calls."""
        super().__init__()
        self._pypi_delegate = PyPIAdapter()

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to PyPIAdapter.get_publish_time.

        Args:
            package: PyPI package name.
            version: Exact version string (PEP 440).
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._pypi_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to PyPIAdapter.get_all_versions.

        Args:
            package: PyPI package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        return await self._pypi_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to PyPIAdapter.get_latest_version.

        Args:
            package: PyPI package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await self._pypi_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to PyPIAdapter.get_installed_version (pip show).

        Args:
            package: PyPI package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._pypi_delegate.get_installed_version(package)

    # --- Manager command parsing (from PipAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse pip command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw pip command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        # 1. Strip pkgd flags
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args:
            return self._safe_passthrough(manager_args, pkgd_flags)

        # 2. Extract subcommand
        subcommand = clean_args[0]
        remaining = clean_args[1:]

        # 3. Classify
        intent = self.classify_intent(subcommand)

        if intent == CommandIntent.SAFE_PASSTHROUGH:
            return self._safe_passthrough(manager_args, pkgd_flags, subcommand, remaining)

        # 4. Tokenize
        tokens = self.tokenize_args(remaining)

        # 5. Extract packages and flags
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # 6. Handle -r / --requirement flags
        file_targets: list[str] = []
        requires_file_audit = False
        for token in tokens:
            if isinstance(token, tuple) and token[0] in {
                "-r",
                "--requirement",
            }:
                file_targets.append(token[1])
                requires_file_audit = True

        # 7. Parse packages
        packages = [parse_python_package(s, ecosystem=self.ecosystem) for s in package_strings]

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=file_targets,
            raw_args=manager_args,
            requires_file_audit=requires_file_audit,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct pip command args for exec.

        Args:
            parsed: The parsed command to reconstruct.

        Returns:
            List of command-line arguments for exec.
        """
        args = [self.manager_name]
        args.extend(parsed.manager_subcommand.split())
        args.extend(parsed.manager_flags)
        for pkg in parsed.packages:
            args.append(pkg.raw)
        for f in parsed.file_targets:
            args.extend(["-r", f])
        return args


# ---------------------------------------------------------------------------
# Standalone convenience functions — preserved for backward compatibility
# ---------------------------------------------------------------------------


async def pypi_unified_get_publish_time(
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
) -> tuple[datetime | None, str]:
    """Return the UTC publish time for *package* at *version* via PyPI.

    Args:
        package: PyPI package name.
        version: Exact version string (PEP 440).
        session: Optional aiohttp session for connection pooling.

    Returns:
        Tuple of (publish_time, source).
    """
    adapter = PyPIUnifiedAdapter()
    return await adapter.get_publish_time(package, version, session)


async def pypi_unified_get_latest_version(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> str | None:
    """Return the latest stable version of *package* via PyPI.

    Args:
        package: PyPI package name.
        session: Optional aiohttp session for connection pooling.

    Returns:
        Latest version string, or None if not found.
    """
    adapter = PyPIUnifiedAdapter()
    return await adapter.get_latest_version(package, session)
