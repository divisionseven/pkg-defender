# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Cargo adapter — crates.io registry lookups + cargo command parsing."""

from __future__ import annotations

from datetime import datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.cargo import CargoAdapter
from pkg_defender.registry.flags import CARGO_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_cargo_package


class CargoUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for cargo — crates.io registry lookups + cargo command parsing.

    Combines:
    - Registry methods from CargoAdapter (delegated via class composition)
    - Manager methods from CargoAdapter (parse, build_exec_args, COMMAND_INTENT_MAP)
    """

    manager_name: str = "cargo"
    ecosystem: str = "cargo"
    coverage_tier: CoverageTier = CoverageTier.FULL

    def __init__(self) -> None:
        """Initialise with a CargoAdapter delegate for registry operations."""
        super().__init__()
        self._cargo_delegate = CargoAdapter()

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "install": CommandIntent.INSTALL,
        "update": CommandIntent.UPDATE,
        "fetch": CommandIntent.SYNC,
        "build": CommandIntent.SAFE_PASSTHROUGH,
        "run": CommandIntent.EXECUTE,
    }

    VALUE_FLAGS: frozenset[str] = CARGO_VALUE_FLAGS

    registry_base_url: str = "https://crates.io"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by Cargo ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to CargoAdapter ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to CargoAdapter.

        Args:
            package: Cargo crate name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await self._cargo_delegate.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Delegate to CargoAdapter.

        Args:
            package: Cargo crate name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        return await self._cargo_delegate.get_all_versions(package, session)

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to CargoAdapter.

        Args:
            package: Cargo crate name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await self._cargo_delegate.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to CargoAdapter.

        Args:
            package: Cargo crate name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await self._cargo_delegate.get_installed_version(package)

    # --- Manager command parsing (from CargoAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse cargo command arguments into a structured ParsedCommand.

        Args:
            manager_args: Raw cargo command arguments.

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

        # cargo fetch is a sync operation (downloads deps)
        if subcommand == "fetch":
            intent = CommandIntent.SYNC

        packages = [parse_cargo_package(s, ecosystem=self.ecosystem) for s in package_strings]

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
        """Reconstruct cargo command args for exec.

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
