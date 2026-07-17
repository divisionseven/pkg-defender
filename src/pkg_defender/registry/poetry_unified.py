# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Poetry adapter — Poetry command parsing + PyPI registry lookups."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import POETRY_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_python_package
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter


class PoetryUnifiedAdapter(PyPIUnifiedAdapter):
    """Unified adapter for poetry — PyPI registry + poetry command parsing.

    Poetry uses the PyPI registry for package metadata. This adapter
    extends PyPIUnifiedAdapter with poetry-specific command parsing.
    """

    manager_name: str = "poetry"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "install": CommandIntent.SYNC,
        "update": CommandIntent.UPDATE,
        "remove": CommandIntent.REMOVE,
        "run": CommandIntent.EXECUTE,
    }

    VALUE_FLAGS: frozenset[str] = POETRY_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse poetry command into a structured ParsedCommand.

        Handles: poetry add, poetry install, poetry update,
        poetry remove, poetry run. Special cases: 'poetry install'
        with no packages is SYNC intent; 'poetry remove' is REMOVE
        intent.

        Args:
            manager_args: Raw poetry command arguments.

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
        package_strings, manager_flags = self.extract_packages_and_flags(
            tokens,
        )

        # 6. Special intent overrides
        if subcommand == "remove":
            intent = CommandIntent.REMOVE
        elif not package_strings and subcommand == "install":
            intent = CommandIntent.SYNC

        # 7. Parse packages
        packages = [parse_python_package(s, ecosystem=self.ecosystem) for s in package_strings]

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
        """Reconstruct poetry command args for exec.

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
