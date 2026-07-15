# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Brew adapter — Homebrew registry lookups + brew command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.brew import BrewAdapter
from pkg_defender.registry.flags import BREW_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_brew_package


class BrewUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for brew — Homebrew registry lookups + brew command parsing.

    Combines:
    - Registry methods from BrewAdapter (delegated via class composition)
    - Manager methods from BrewAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)

    Note: brew is always a system-wide (global) install. All commands have
    is_global=True.

    The Homebrew API now uses PROXIED_PUBLISH_TIMESTAMPS — per-version timestamps
    are resolved via the shared TimestampResolver (GitHub Releases → GitHub Tags/Commits →
    Libraries.io) when available.
    """

    manager_name: str = "brew"
    ecosystem: str = "homebrew"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    def __init__(self) -> None:
        """Initialise with a BrewAdapter delegate for registry operations."""
        super().__init__()
        self._brew_delegate = BrewAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "upgrade": CommandIntent.UPDATE,
        "reinstall": CommandIntent.INSTALL,
        "bundle": CommandIntent.INSTALL,
        "tap": CommandIntent.SAFE_PASSTHROUGH,
    }

    VALUE_FLAGS: frozenset[str] = BREW_VALUE_FLAGS

    registry_base_url: str = "https://formulae.brew.sh"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by Homebrew ecosystem."""
        return [
            EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to BrewAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to BrewAdapter.

        Args:
            package: Homebrew formula name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._brew_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to BrewAdapter.

        Args:
            package: Homebrew formula name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        return await self._brew_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to BrewAdapter.

        Args:
            package: Homebrew formula name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await self._brew_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to BrewAdapter.

        Args:
            package: Homebrew formula name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._brew_delegate.get_installed_version(package)

    # --- Manager command parsing (from BrewAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse brew command arguments into a structured ParsedCommand.

        Handles special cases:
        - ``brew upgrade`` with no packages → SYNC (upgrades all)
        - Always is_global=True

        Args:
            manager_args: Raw brew command arguments.

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

        # brew upgrade with no args = upgrade all — SYNC
        if not package_strings and subcommand == "upgrade":
            intent = CommandIntent.SYNC

        packages = [parse_brew_package(s, ecosystem=self.ecosystem) for s in package_strings]

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
        """Reconstruct brew command args for exec.

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
