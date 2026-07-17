# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Bundler adapter — RubyGems registry lookups + bundle command parsing."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import BUNDLER_VALUE_FLAGS
from pkg_defender.registry.gem_unified import GemUnifiedAdapter
from pkg_defender.registry.parsing import parse_gem_package


class BundlerUnifiedAdapter(GemUnifiedAdapter):
    """Unified adapter for bundler — RubyGems registry + bundle command parsing.

    Bundler uses the RubyGems registry for package metadata. This adapter
    extends GemUnifiedAdapter with bundler-specific command parsing,
    including bundle exec support.
    """

    manager_name: str = "bundle"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.SYNC,  # bundle install = from Gemfile
        "add": CommandIntent.INSTALL,
        "update": CommandIntent.UPDATE,
        "exec": CommandIntent.EXECUTE,  # Runs scripts in context
        "check": CommandIntent.SYNC,  # bundle check — no net activity
        "outdated": CommandIntent.SAFE_PASSTHROUGH,
        "why": CommandIntent.SAFE_PASSTHROUGH,  # bundle why — explanation
        "list": CommandIntent.SAFE_PASSTHROUGH,  # bundle list — what's installed
        "show": CommandIntent.SAFE_PASSTHROUGH,  # bundle show — gem details
    }

    VALUE_FLAGS: frozenset[str] = BUNDLER_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse bundle command arguments into a structured ParsedCommand.

        Bundler-specific handling:
        - ``bundle install`` with no packages → SYNC (from Gemfile)
        - ``bundle exec`` → EXECUTE intent

        Args:
            manager_args: Raw bundle command arguments.

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

        # 6. bundle install with no packages = SYNC from Gemfile
        if not package_strings and subcommand == "install":
            intent = CommandIntent.SYNC

        # 7. Parse packages
        packages = [parse_gem_package(s, ecosystem=self.ecosystem) for s in package_strings]

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
        """Reconstruct bundle command args for exec.

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
