"""Unified Bun adapter — npm registry lookups + bun command parsing."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import BUN_VALUE_FLAGS
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.parsing import parse_npm_package


class BunUnifiedAdapter(NpmUnifiedAdapter):
    """Unified adapter for bun — npm registry lookups + bun command parsing.

    Bun uses the npm registry for package metadata. This adapter
    extends NpmUnifiedAdapter with bun-specific command parsing,
    including bunx support.
    """

    manager_name: str = "bun"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "install": CommandIntent.SYNC,
        "update": CommandIntent.UPDATE,
        "upgrade": CommandIntent.UPDATE,
        "x": CommandIntent.EXECUTE,  # bunx — runs without install
        "run": CommandIntent.EXECUTE,
    }

    VALUE_FLAGS: frozenset[str] = BUN_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse bun command arguments into a structured ParsedCommand.

        Bun-specific handling:
        - ``bun install`` with no packages → SYNC
        - Detects ``--save-dev`` / ``-D`` for dev dependencies

        Args:
            manager_args: Raw bun command arguments.

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
            return self._safe_passthrough(
                manager_args,
                pkgd_flags,
                subcommand,
                remaining,
            )

        # 4. Tokenize
        tokens = self.tokenize_args(remaining)

        # 5. Extract packages and flags
        package_strings, manager_flags = self.extract_packages_and_flags(tokens)

        # 6. bun install with no packages = SYNC
        if not package_strings and subcommand == "install":
            intent = CommandIntent.SYNC

        # 7. Detect --save-dev / -D
        is_dev = "--save-dev" in manager_flags or "-D" in manager_flags

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
        """Reconstruct bun command args for exec.

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
