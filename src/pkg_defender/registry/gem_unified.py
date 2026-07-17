# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified gem adapter — RubyGems registry lookups + gem command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.flags import GEM_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_gem_package
from pkg_defender.registry.rubygems import RubyGemsAdapter


class GemUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for gem — RubyGems registry lookups + gem command parsing.

    Combines:
    - Registry methods from RubyGemsAdapter (delegated via class composition)
    - Manager methods from GemAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)
    """

    manager_name: str = "gem"
    ecosystem: str = "rubygems"
    coverage_tier: CoverageTier = CoverageTier.FULL

    def __init__(self) -> None:
        """Initialise with a RubyGemsAdapter delegate for registry operations."""
        super().__init__()
        self._rubygems_delegate = RubyGemsAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "update": CommandIntent.UPDATE,
        "fetch": CommandIntent.INSTALL,  # Downloads gem file
        "query": CommandIntent.SAFE_PASSTHROUGH,  # list, search, which, contents
        "build": CommandIntent.SAFE_PASSTHROUGH,
        "push": CommandIntent.SAFE_PASSTHROUGH,
        "owner": CommandIntent.SAFE_PASSTHROUGH,
    }

    VALUE_FLAGS: frozenset[str] = GEM_VALUE_FLAGS

    registry_base_url: str = "https://rubygems.org"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by RubyGems ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to RubyGemsAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to RubyGemsAdapter.

        Args:
            package: RubyGems gem name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._rubygems_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to RubyGemsAdapter.

        Args:
            package: RubyGems gem name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        return await self._rubygems_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to RubyGemsAdapter.

        Args:
            package: RubyGems gem name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await self._rubygems_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to RubyGemsAdapter.

        Args:
            package: RubyGems gem name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._rubygems_delegate.get_installed_version(package)

    # --- Manager command parsing (from GemAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse gem command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw gem command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args:
            return self._safe_passthrough(manager_args, pkgd_flags)

        # 2. Extract subcommand
        subcommand = clean_args[0]
        remaining = clean_args[1:]

        intent = self.classify_intent(subcommand)

        if intent == CommandIntent.SAFE_PASSTHROUGH:
            return self._safe_passthrough(manager_args, pkgd_flags, subcommand, remaining)

        # 4. Tokenize
        tokens = self.tokenize_args(remaining)

        # 5. Extract packages and flags
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # 6. Parse packages
        packages = [parse_gem_package(s, ecosystem=self.ecosystem) for s in package_strings]

        # 7. gem install with --local is non-global
        is_global = "--local" not in manager_flags

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=manager_args,
            is_global=is_global,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct gem command args for exec.

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
