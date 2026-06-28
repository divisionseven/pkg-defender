"""Unified pnpm adapter — npm registry lookups + pnpm command parsing."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import PNPM_VALUE_FLAGS
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.parsing import parse_npm_package


class PnpmUnifiedAdapter(NpmUnifiedAdapter):
    """Unified adapter for pnpm — npm registry lookups + pnpm command parsing.

    pnpm uses the npm registry for package metadata. This adapter
    extends NpmUnifiedAdapter with pnpm-specific command parsing,
    including dlx and workspace support.
    """

    manager_name: str = "pnpm"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "install": CommandIntent.SYNC,
        "i": CommandIntent.SYNC,  # pnpm i = install from manifest
        "update": CommandIntent.UPDATE,
        "upgrade": CommandIntent.UPDATE,
        "remove": CommandIntent.REMOVE,
        "dlx": CommandIntent.EXECUTE,  # pnpm dlx — downloads and executes
        "import": CommandIntent.SAFE_PASSTHROUGH,  # pnpm import — converts lock files
    }

    VALUE_FLAGS: frozenset[str] = PNPM_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse pnpm command arguments into a structured ParsedCommand.

        pnpm-specific handling:
        - ``pnpm install`` / ``pnpm i`` with no packages → SYNC
        - Detects ``--save-dev`` / ``-D`` for dev dependencies
        - Detects ``--global`` for global installs

        Args:
            manager_args: Raw pnpm command arguments.

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

        is_dev = "--save-dev" in manager_flags or "-D" in manager_flags
        is_global = "--global" in manager_flags

        if not package_strings and intent == CommandIntent.INSTALL:
            intent = CommandIntent.SYNC

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
            is_global=is_global,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct pnpm command args for exec.

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
