# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Unified uv adapter — uv command parsing + PyPI registry lookups."""

from __future__ import annotations

from pkg_defender.models.command import CommandIntent, ParsedCommand
from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.flags import UV_VALUE_FLAGS
from pkg_defender.registry.parsing import parse_python_package
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter


class UvUnifiedAdapter(PyPIUnifiedAdapter):
    """Unified adapter for uv — PyPI registry + uv command parsing.

    Astral's uv uses the PyPI registry for package metadata. This
    adapter extends PyPIUnifiedAdapter with uv-specific command
    parsing, including support for compound subcommands
    (e.g., 'uv tool install').
    """

    manager_name: str = "uv"
    coverage_tier: CoverageTier = CoverageTier.PARTIAL

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {
        "add": CommandIntent.INSTALL,
        "install": CommandIntent.INSTALL,
        "pip": CommandIntent.INSTALL,
        "pip install": CommandIntent.INSTALL,
        "pip sync": CommandIntent.SYNC,
        "sync": CommandIntent.SYNC,
        "upgrade": CommandIntent.UPDATE,
        "update": CommandIntent.UPDATE,
        "tool": CommandIntent.INSTALL,
        "tool install": CommandIntent.INSTALL,
        "tool upgrade": CommandIntent.UPDATE,
        "run": CommandIntent.EXECUTE,
    }

    VALUE_FLAGS: frozenset[str] = UV_VALUE_FLAGS

    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse uv command arguments into a structured ParsedCommand.

        Handles compound subcommands (e.g., 'uv tool install') and
        -r/--requirement file targets.

        Args:
            manager_args: Raw uv command arguments.

        Returns:
            ParsedCommand with extracted packages, intent, and flags.
        """
        # 1. Strip pkgd flags
        clean_args, pkgd_flags = self.split_pkgd_flags(manager_args)

        if not clean_args:
            return self._safe_passthrough(manager_args, pkgd_flags)

        # 2. Extract subcommand (handle compound: 'tool install', 'pip install')
        subcommand = clean_args[0]
        if len(clean_args) > 1 and clean_args[0] in {"tool", "pip"}:
            subcommand = f"{clean_args[0]} {clean_args[1]}"
            remaining = clean_args[2:]
        else:
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

        file_targets: list[str] = []
        requires_file_audit = False
        for token in tokens:
            if isinstance(token, tuple) and token[0] in {
                "-r",
                "--requirement",
            }:
                file_targets.append(token[1])
                requires_file_audit = True

        # 7. Parse packages
        packages = [parse_python_package(s, ecosystem=self.ecosystem) for s in package_strings]

        return ParsedCommand(
            manager=self.manager_name,
            intent=intent,
            packages=packages,
            manager_subcommand=subcommand,
            manager_flags=manager_flags,
            pkgd_flags=pkgd_flags,
            file_targets=file_targets,
            raw_args=manager_args,
            requires_file_audit=requires_file_audit,
            ecosystem=self.ecosystem,
        )

    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct uv command args for exec.

        Splits compound subcommands: 'tool install' →
        ['tool', 'install'].

        Args:
            parsed: The parsed command to reconstruct.

        Returns:
            List of command-line arguments for exec.
        """
        args = [self.manager_name]
        args.extend(parsed.manager_subcommand.split())
        args.extend(parsed.manager_flags)
        for pkg in parsed.packages:
            args.append(pkg.raw)
        return args
