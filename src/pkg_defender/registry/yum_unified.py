"""Unified YUM adapter — YUM registry lookups + yum command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.flags import DNF_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_dnf_package
from pkg_defender.registry.yum import YUMAdapter


class YumUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for yum — YUM registry lookups + yum command parsing.

    Combines:
    - Registry methods from YUMAdapter (delegated via class composition)
    - Manager methods

    Note: yum uses DNF-style command line and name-version parsing but has
    its own registry backend. yum is always system-wide (is_global=True).

    There is no dedicated YUM manager adapter in managers/ — yum uses DnfAdapter
    via MANAGER_ALIASES["yum"] = "dnf". This unified adapter provides the
    first native yum adapter with its own identity.
    """

    manager_name: str = "yum"
    ecosystem: str = "yum"
    coverage_tier: CoverageTier = CoverageTier.AUDIT

    def __init__(self) -> None:
        """Initialise with a YUMAdapter delegate for registry operations."""
        super().__init__()
        self._yum_delegate = YUMAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "update": CommandIntent.UPDATE,
        "upgrade": CommandIntent.UPDATE,
        "localinstall": CommandIntent.INSTALL,
        "localupdate": CommandIntent.UPDATE,
        "group": CommandIntent.INSTALL,
        "remove": CommandIntent.REMOVE,
        "autoremove": CommandIntent.REMOVE,
    }

    VALUE_FLAGS: frozenset[str] = DNF_VALUE_FLAGS

    registry_base_url: str = "local://yum"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by YUM ecosystem.

        Per BC-4: ``PROXIED`` is the honest tier — repodata ``<time file>``
        is a proxy (not a cryptographically-attested publish time).
        ``THREAT_INTEL_SUPPORT`` is excluded per the AUDIT-tier rule
        enforced by ``test_coverage_tiers.py:181-185``.
        """
        return [
            EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS,
        ]

    # --- Registry method delegation to YUMAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to YUMAdapter (Bodhi → Koji → repodata cascade).

        Args:
            package: Package name.
            version: Exact version string (e.g., "8.19.0-1.fc40").
            session: Optional aiohttp session.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._yum_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to YUMAdapter.

        Args:
            package: Package name.
            session: Optional aiohttp session (unused for yum).

        Returns:
            List of VersionInfo sorted by version descending.
        """
        return await self._yum_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to YUMAdapter.

        Args:
            package: Package name.
            session: Optional aiohttp session (unused for yum).

        Returns:
            Latest version string, or None if not found.
        """
        return await self._yum_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to YUMAdapter (rpm -q).

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._yum_delegate.get_installed_version(package)

    # --- Manager command parsing ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse yum command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw yum command arguments.

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

        packages = [parse_dnf_package(s, ecosystem=self.ecosystem) for s in package_strings]

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
        """Reconstruct yum command args for exec.

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
