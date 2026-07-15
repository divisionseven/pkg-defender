# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Yarn adapter — npm registry lookups + yarn command parsing."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import YARN_VALUE_FLAGS
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.parsing import parse_npm_package


class YarnUnifiedAdapter(NpmUnifiedAdapter):
    """Unified adapter for yarn — npm registry lookups + yarn command parsing.

    Yarn uses the npm registry for package metadata. This adapter
    extends NpmUnifiedAdapter with yarn-specific command parsing,
    including workspaces support.
    """

    manager_name: str = "yarn"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "upgrade": CommandIntent.UPDATE,
        "up": CommandIntent.UPDATE,  # Yarn Berry
        "set": CommandIntent.INSTALL,  # yarn set version X
        "install": CommandIntent.SYNC,  # yarn install = from yarn.lock
        "remove": CommandIntent.REMOVE,
        "dlx": CommandIntent.EXECUTE,  # yarn dlx — like npx
        "link": CommandIntent.SAFE_PASSTHROUGH,  # yarn link
    }

    VALUE_FLAGS: frozenset[str] = YARN_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse yarn command arguments into a structured ParsedCommand.

        Yarn-specific handling:
        - Bare ``yarn`` or ``yarn install`` with no args → SYNC
        - Detects ``--dev`` / ``-D`` flags for dev dependencies

        Args:
            manager_args: Raw yarn command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args or clean_args[0] == "install":
            subcommand = clean_args[0] if clean_args else "install"
            remaining = clean_args[1:] if clean_args else []
            tokens = self.tokenize_args(remaining)
            _, manager_flags = self.extract_packages_and_flags(tokens)
            return ParsedCommand(
                manager=self.manager_name,
                intent=CommandIntent.SYNC,
                packages=[],
                manager_subcommand=subcommand,
                manager_flags=manager_flags,
                pkgd_flags=pkgd_flags,
                file_targets=[],
                raw_args=manager_args,
                ecosystem=self.ecosystem,
            )

        # 3. Extract subcommand
        subcommand = clean_args[0]
        remaining = clean_args[1:]

        # 4. Classify
        intent = self.classify_intent(subcommand)

        if intent == CommandIntent.SAFE_PASSTHROUGH:
            return self._safe_passthrough(
                manager_args,
                pkgd_flags,
                subcommand,
                remaining,
            )

        # 5. Tokenize
        tokens = self.tokenize_args(remaining)

        # 6. Extract packages and flags
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # 7. Detect --dev flag
        is_dev = "--dev" in manager_flags or "-D" in manager_flags

        # 8. Parse packages
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
            is_dev_dependency=is_dev,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct yarn command args for exec.

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
