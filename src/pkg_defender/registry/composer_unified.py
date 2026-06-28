"""Unified Composer adapter — Packagist registry lookups + composer command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.composer import ComposerAdapter
from pkg_defender.registry.flags import COMPOSER_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_composer_package


class ComposerUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for composer — Packagist registry lookups + composer command parsing.

    Combines:
    - Registry methods from ComposerAdapter (delegated via class composition)
    - Manager methods from ComposerAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)
    """

    manager_name: str = "composer"
    ecosystem: str = "composer"
    coverage_tier: CoverageTier = CoverageTier.FULL

    def __init__(self) -> None:
        """Initialise with a ComposerAdapter delegate for registry operations."""
        super().__init__()
        self._composer_delegate = ComposerAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "require": CommandIntent.INSTALL,
        "install": CommandIntent.SYNC,
        "update": CommandIntent.UPDATE,
        "remove": CommandIntent.REMOVE,
        "create-project": CommandIntent.INSTALL,
        "global": CommandIntent.INSTALL,
    }

    VALUE_FLAGS: frozenset[str] = COMPOSER_VALUE_FLAGS

    registry_base_url: str = "https://packagist.org"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by Composer ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to ComposerAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to ComposerAdapter.

        Args:
            package: Composer package name (vendor/package).
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._composer_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to ComposerAdapter.

        Args:
            package: Composer package name (vendor/package).
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        return await self._composer_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to ComposerAdapter.

        Args:
            package: Composer package name (vendor/package).
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await self._composer_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to ComposerAdapter.

        Args:
            package: Composer package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._composer_delegate.get_installed_version(package)

    # --- Manager command parsing (from ComposerAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse composer command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw composer command arguments.

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

        # composer install with no packages = SYNC from composer.json
        if not package_strings and subcommand == "install":
            intent = CommandIntent.SYNC

        packages = [parse_composer_package(s, ecosystem=self.ecosystem) for s in package_strings]

        # Detect --dev flag for dev dependency classification
        is_dev = "--dev" in manager_flags

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=manager_args,
            is_dev_dependency=is_dev,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct composer command args for exec.

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
