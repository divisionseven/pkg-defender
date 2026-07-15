# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified Pipenv adapter — Pipenv command parsing + PyPI registry lookups."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import PIPENV_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_python_package
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter


class PipenvUnifiedAdapter(PyPIUnifiedAdapter):
    """Unified adapter for pipenv — PyPI registry + pipenv command parsing.

    Pipenv uses the PyPI registry for package metadata. This adapter
    extends PyPIUnifiedAdapter with pipenv-specific command parsing.
    """

    manager_name: str = "pipenv"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "install": CommandIntent.INSTALL,
        "sync": CommandIntent.SYNC,
        "update": CommandIntent.UPDATE,
        "upgrade": CommandIntent.UPDATE,
    }

    VALUE_FLAGS: frozenset[str] = PIPENV_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse pipenv command arguments into a structured ParsedCommand.

        Handles: pipenv install, pipenv sync, pipenv update,
        pipenv upgrade. Detects --dev flag for dev dependency
        classification.

        Args:
            manager_args: Raw pipenv command arguments.

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

        # 6. Override intent for sync subcommand
        if subcommand == "sync":
            intent = CommandIntent.SYNC

        # 7. Parse packages
        packages = [parse_python_package(s, ecosystem=self.ecosystem) for s in package_strings]

        # 8. Detect --dev flag
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
        """Reconstruct pipenv command args for exec.

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
