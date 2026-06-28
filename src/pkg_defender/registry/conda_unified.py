"""Unified Conda adapter — conda-forge registry lookups + conda command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.conda import CondaAdapter
from pkg_defender.registry.flags import CONDA_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_conda_package


class CondaUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for conda — conda-forge registry lookups + conda command parsing.

    Combines:
    - Registry methods from CondaAdapter (delegated via class composition)
    - Manager methods from CondaAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)

    Note: Conda now provides per-version publish timestamps via the Anaconda API.
    The capability ``VERIFIED_PUBLISH_TIMESTAMPS`` reflects this improvement.
    """

    manager_name: str = "conda"
    ecosystem: str = "conda"
    coverage_tier: CoverageTier = CoverageTier.FULL

    def __init__(self) -> None:
        """Initialise with a CondaAdapter delegate for registry operations."""
        super().__init__()
        self._conda_delegate = CondaAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "update": CommandIntent.UPDATE,
        "upgrade": CommandIntent.UPDATE,
        "create": CommandIntent.INSTALL,
        "env": CommandIntent.SAFE_PASSTHROUGH,
    }

    VALUE_FLAGS: frozenset[str] = CONDA_VALUE_FLAGS

    registry_base_url: str = "conda-forge"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by Conda ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to CondaAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to CondaAdapter.

        Note: Conda now provides per-version publish timestamps via the
        Anaconda API — this returns (datetime, "registry_api") when the
        API is available, or falls through to the shared TimestampResolver.

        Args:
            package: Conda package name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (datetime or None, source string).
        """
        return await self._conda_delegate.get_publish_time(package, version, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to CondaAdapter.

        Args:
            package: Conda package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo with publish_time populated from the
            Anaconda API where available.
        """
        return await self._conda_delegate.get_all_versions(package)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to CondaAdapter.

        Args:
            package: Conda package name.
            session: Optional aiohttp session (unused for conda).

        Returns:
            Latest version string, or None if not found.
        """
        return await self._conda_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to CondaAdapter.

        Args:
            package: Conda package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._conda_delegate.get_installed_version(package)

    # --- Manager command parsing (from CondaAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse conda command arguments into a structured ParsedCommand.

        Handles special cases:
        - ``conda env create`` and ``conda env update`` treated as INSTALL
        - ``conda create`` treated as INSTALL

        Args:
            manager_args: Raw conda command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args:
            return self._safe_passthrough(manager_args, pkgd_flags)

        # Handle "conda env create" / "conda env update"
        if len(clean_args) >= 2 and clean_args[0] == "env":
            subcommand = " ".join(clean_args[:2])
            remaining = clean_args[2:]
            intent = CommandIntent.INSTALL
        else:
            subcommand = clean_args[0]
            remaining = clean_args[1:]
            intent = self.classify_intent(subcommand)

        if intent == CommandIntent.SAFE_PASSTHROUGH:
            return self._safe_passthrough(manager_args, pkgd_flags, subcommand, remaining)

        tokens = self.tokenize_args(remaining)
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        packages = [parse_conda_package(s, ecosystem=self.ecosystem) for s in package_strings]

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=manager_args,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct conda command args for exec.

        Uses parsed.manager_subcommand.split() to handle compound
        subcommands like "env create".

        Args:
            parsed: The parsed command to reconstruct.

        Returns:
            List of command-line arguments for exec.
        """
        args = [self.manager_name] + parsed.manager_subcommand.split()
        args.extend(parsed.manager_flags)
        for pkg in parsed.packages:
            args.append(pkg.raw)
        return args
