"""Unified APT adapter — Debian registry lookups + apt command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.apt import APTAdapter
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.flags import APT_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_apt_package


class AptUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for apt — Debian registry lookups + apt command parsing.

    Combines:
    - Registry methods from APTAdapter (delegated via class composition)
    - Manager methods from APTAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)

    Note: apt is always a system-wide (global) install. All commands have
    is_global=True.
    """

    manager_name: str = "apt"
    ecosystem: str = "apt"
    coverage_tier: CoverageTier = CoverageTier.AUDIT

    def __init__(self) -> None:
        """Initialise with an APTAdapter delegate for registry operations."""
        super().__init__()
        self._apt_delegate = APTAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "update": CommandIntent.SYNC,
        "upgrade": CommandIntent.UPDATE,
        "full-upgrade": CommandIntent.UPDATE,
        "dist-upgrade": CommandIntent.UPDATE,
        "remove": CommandIntent.REMOVE,
        "autoremove": CommandIntent.REMOVE,
        "purge": CommandIntent.REMOVE,
    }

    VALUE_FLAGS: frozenset[str] = APT_VALUE_FLAGS

    registry_base_url: str = "local://apt"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by APT ecosystem.

        Note: Narrower than APTAdapter capabilities — threat-intel
        support is deferred until v1.1 per the AUDIT-tier constraint.
        """
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
        ]

    # --- Registry method delegation to APTAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to APTAdapter.

        Uses snapshot.debian.org with fallback chain.

        Args:
            package: Package name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._apt_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to APTAdapter.

        Args:
            package: Package name.
            session: Optional aiohttp session (unused for apt).

        Returns:
            List of VersionInfo sorted by version descending.
        """
        return await self._apt_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to APTAdapter.

        Args:
            package: Package name.
            session: Optional aiohttp session (unused for apt).

        Returns:
            Latest version string, or None if not found.
        """
        return await self._apt_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to APTAdapter.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._apt_delegate.get_installed_version(package)

    # --- Manager command parsing (from APTAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse apt command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw apt command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args:
            return self._safe_passthrough(manager_args, pkgd_flags)

        subcommand = clean_args[0]
        remaining = clean_args[1:]
        intent = self.classify_intent(subcommand)

        if intent == CommandIntent.SAFE_PASSTHROUGH:
            return self._safe_passthrough(manager_args, pkgd_flags, subcommand, remaining)

        tokens = self.tokenize_args(remaining)
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # apt update is a sync operation (refreshes package index)
        if subcommand == "update":
            intent = CommandIntent.SYNC

        packages = [parse_apt_package(s, ecosystem=self.ecosystem) for s in package_strings]

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=manager_args,
            is_global=True,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct apt command args for exec.

        Args:
            parsed: The parsed command to reconstruct.

        Returns:
            List of command-line arguments for exec.
        """
        args = [self.manager_name, parsed.manager_subcommand]
        args.extend(parsed.manager_flags)
        for pkg in parsed.packages:
            args.append(pkg.raw)
        return args
