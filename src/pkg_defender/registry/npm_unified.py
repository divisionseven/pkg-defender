"""Unified npm adapter — npm registry lookups + npm command parsing."""

from __future__ import annotations

from datetime import UTC, datetime

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry import npm as npm_module
from pkg_defender.registry.base import CoverageTier, EcosystemCapability, UnifiedRegistryAdapter
from pkg_defender.registry.flags import NPM_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_npm_package


class NpmUnifiedAdapter(UnifiedRegistryAdapter):
    """Unified adapter for npm — npm registry lookups + npm command parsing.

    Combines:
    - Registry methods from npm.py module functions (get_publish_time,
      get_all_versions, get_latest_version, get_installed_version)
    - Manager methods from NpmAdapter (parse, build_exec_args,
      COMMAND_INTENT_MAP)

    Unlike PyPIUnifiedAdapter which uses composition with PyPIAdapter,
    this adapter calls npm module functions directly because npm.py
    exposes module-level functions rather than a class.
    """

    manager_name: str = "npm"
    ecosystem: str = "npm"
    coverage_tier: CoverageTier = CoverageTier.FULL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "i": CommandIntent.INSTALL,  # shorthand
        "add": CommandIntent.INSTALL,  # npm add is like install
        "update": CommandIntent.UPDATE,
        "up": CommandIntent.UPDATE,  # shorthand
        "remove": CommandIntent.REMOVE,
        "rm": CommandIntent.REMOVE,  # shorthand
        "uninstall": CommandIntent.REMOVE,
        "un": CommandIntent.REMOVE,  # shorthand
    }

    VALUE_FLAGS: frozenset[str] = NPM_VALUE_FLAGS

    registry_base_url: str = "https://registry.npmjs.org"

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return capabilities supported by npm ecosystem."""
        return [
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ]

    # --- Registry method delegation to npm module functions ---

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Delegate to npm module's get_publish_time with multi-source fallback.

        Args:
            package: npm package name (scoped or plain).
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source).
        """
        return await npm_module.get_publish_time(package, version, session, is_latest=is_latest)

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Fetch all versions from npm and wrap in VersionInfo objects.

        npm_module.get_all_versions() returns list[str]. This method
        wraps each string in a VersionInfo with publish_time from the
        timestamps dict.

        Args:
            package: npm package name (scoped or plain).
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        # Get version timestamps in a single call
        time_dict = await npm_module.get_all_version_timestamps(package, session)
        if not time_dict:
            return []

        results: list[VersionInfo] = []
        for ver, publish_time in time_dict.items():
            results.append(
                VersionInfo(
                    ecosystem="npm",
                    package_name=package,
                    version=ver,
                    publish_time=publish_time,
                )
            )

        results.sort(key=lambda v: v.publish_time or datetime.min.replace(tzinfo=UTC), reverse=True)
        return results

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Delegate to npm module's get_latest_version.

        Args:
            package: npm package name (scoped or plain).
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        return await npm_module.get_latest_version(package, session)

    async def get_installed_version(self, package: str) -> str | None:
        """Delegate to npm module's npm_get_installed_version (npm list).

        Args:
            package: npm package name (scoped or plain).

        Returns:
            Installed version string, or None if not installed.
        """
        return await npm_module.npm_get_installed_version(package)

    # --- Manager command parsing (from NpmAdapter) ---

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse npm command arguments into a structured ParsedCommand.

        Handles npm-specific patterns:
        - Shorthands: i→install, rm→remove, un→uninstall, up→update
        - ``npm install`` with no packages → SYNC intent
        - ``--global`` / ``-g`` flag → is_global=True
        - ``--save-dev`` / ``-D`` flag → is_dev_dependency=True

        Args:
            manager_args: Raw npm command arguments.

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

        # 4. npm install with no packages is a sync operation (from package.json)
        if subcommand == "install" and not remaining:
            intent = CommandIntent.SYNC

        # 5. Tokenize
        tokens = self.tokenize_args(remaining)

        # 6. Extract packages and flags
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # 7. Handle -g/--global flag
        is_global = False
        for token in tokens:
            if isinstance(token, tuple):
                flag, _ = token
                if flag in ("-g", "--global"):
                    is_global = True
                    break
            elif isinstance(token, str) and token in ("-g", "--global"):
                is_global = True
                break
        if "--global" in manager_flags or "-g" in manager_flags:
            is_global = True

        # 8. Handle --save-dev / -D flag
        is_dev_dependency = False
        if "--save-dev" in manager_flags or "-D" in manager_flags:
            is_dev_dependency = True
            # Remove from manager_flags as it's not passed to npm
            manager_flags = [f for f in manager_flags if f not in ("--save-dev", "-D")]

        # 9. Parse packages
        packages = [parse_npm_package(s, ecosystem=self.ecosystem) for s in package_strings]

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=manager_args,
            requires_file_audit=False,
            is_global=is_global,
            is_dev_dependency=is_dev_dependency,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct npm command args for exec.

        Args:
            parsed: The parsed command to reconstruct.

        Returns:
            List of command-line arguments for exec.
        """
        args = [self.manager_name, parsed.manager_subcommand]

        # Add back --save-dev flag if it was present
        if parsed.is_dev_dependency:
            args.append("--save-dev")

        args.extend(parsed.manager_flags)
        for pkg in parsed.packages:
            args.append(pkg.raw)
        return args
