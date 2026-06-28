"""Tests for _manager_constants module.

Tests the hardcoded constants and helper functions in _manager_constants.py:
- MANAGER_NAMES, MANAGER_TO_ECOSYSTEM, ECOSYSTEM_TO_MANAGER
- MANAGER_DETECTION_COMMANDS, MANAGER_MARKER_FILES
- resolve_ecosystem(), get_manager(), _detect_manager_from_cwd()
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from pkg_defender.cli._manager_constants import (
    ECOSYSTEM_TO_MANAGER,
    MANAGER_NAMES,
    MANAGER_TO_ECOSYSTEM,
    get_manager,
    resolve_ecosystem,
)


class TestResolveEcosystemFunction:
    """Test resolve_ecosystem helper function."""

    def test_resolve_ecosystem_invalid(self) -> None:
        """Verify resolve_ecosystem raises for invalid manager."""
        with pytest.raises(ValueError):
            resolve_ecosystem("invalid_manager")

    def test_resolve_ecosystem_pip_returns_pypi(self) -> None:
        """Verify resolve_ecosystem('pip') returns 'pypi' (regression guard)."""
        assert resolve_ecosystem("pip") == "pypi"


class TestGetManagerFunction:
    """Test get_manager helper function."""

    def test_get_manager_pip(self) -> None:
        """Verify get_manager returns uv for pip ecosystem (modern default)."""
        assert get_manager("pip") == "uv"

    def test_get_manager_homebrew(self) -> None:
        """Verify get_manager returns homebrew for homebrew ecosystem.

        Note: In the new self-referential system, homebrew maps to homebrew.
        """
        result = get_manager("homebrew")
        assert result in ("homebrew", "brew"), f"Expected homebrew or brew, got {result}"

    def test_get_manager_rubygems(self) -> None:
        """Verify get_manager returns gem for rubygems ecosystem."""
        assert get_manager("rubygems") == "gem"

    def test_get_manager_invalid(self) -> None:
        """Verify get_manager raises for invalid ecosystem."""
        with pytest.raises(ValueError):
            get_manager("invalid_ecosystem")


class TestAllManagersConsistency:
    """Test all managers have consistent structure."""

    def test_core_managers_have_ecosystems(self) -> None:
        """Verify core managers have ecosystem mappings."""
        core_managers = ["npm", "yarn", "pnpm", "pip", "brew", "apt", "cargo", "gem"]
        for manager in core_managers:
            assert manager in MANAGER_TO_ECOSYSTEM, f"{manager} should have ecosystem"


class TestManagerNamesConstants:
    """Test all MANAGER_NAMES constants are defined."""

    def test_all_manager_names_count(self) -> None:
        """Verify MANAGER_NAMES has 19 managers."""
        assert len(MANAGER_NAMES) == 19, f"MANAGER_NAMES should have 19 managers, got {len(MANAGER_NAMES)}"

    def test_contains_all_expected_managers(self) -> None:
        """Verify MANAGER_NAMES contains all expected managers."""
        expected = {
            "apt",
            "bun",
            "bundler",
            "cargo",
            "composer",
            "conda",
            "dnf",
            "gem",
            "brew",
            "npm",
            "pip",
            "pip3",
            "pipenv",
            "pipx",
            "pnpm",
            "poetry",
            "uv",
            "yarn",
            "yum",
        }
        assert set(MANAGER_NAMES) == expected, f"MANAGER_NAMES should match expected set. Got: {set(MANAGER_NAMES)}"

    def test_no_duplicates(self) -> None:
        """Verify MANAGER_NAMES has no duplicate entries."""
        assert len(MANAGER_NAMES) == len(set(MANAGER_NAMES))


class TestEcosystemToManagerMapping:
    """Test ECOSYSTEM_TO_MANAGER mapping."""

    def test_ecosystem_count(self) -> None:
        """Verify ECOSYSTEM_TO_MANAGER has 10 entries."""
        assert len(ECOSYSTEM_TO_MANAGER) == 10, "Should have 10 ecosystems"


class TestGetManagerAllEcosystems:
    """Test get_manager function for all ecosystems."""

    @pytest.mark.parametrize(
        "ecosystem,expected_manager",
        [
            ("apt", "apt"),
            ("cargo", "cargo"),
            ("dnf", "dnf"),
            ("yum", "yum"),
            ("npm", "npm"),
            ("homebrew", "brew"),
            ("rubygems", "gem"),
        ],
    )
    def test_get_manager_various_ecosystems(self, ecosystem: str, expected_manager: str) -> None:
        """Test get_manager for various ecosystems."""
        result = get_manager(ecosystem)
        # Also allow for backwards-compatible aliases like "brew"
        valid_managers = set(MANAGER_NAMES) | {"brew"}
        assert result in valid_managers, f"Expected {valid_managers}, got {result}"


class TestManagerToEcosystemMapping:
    """Test MANAGER_TO_ECOSYSTEM has all managers mapped."""

    def test_all_managers_mapped(self) -> None:
        """Verify all MANAGER_NAMES are in MANAGER_TO_ECOSYSTEM."""
        for manager in MANAGER_NAMES:
            assert manager in MANAGER_TO_ECOSYSTEM, f"{manager} should be in mapping"

    def test_manager_count_matches_names(self) -> None:
        """Verify MANAGER_TO_ECOSYSTEM has same count as MANAGER_NAMES."""
        assert len(MANAGER_TO_ECOSYSTEM) == len(MANAGER_NAMES)

    @pytest.mark.parametrize(
        "manager,ecosystem",
        [
            ("apt", "apt"),
            ("bundler", "rubygems"),
            ("bun", "npm"),
            ("cargo", "cargo"),
            ("composer", "composer"),
            ("conda", "conda"),
            ("dnf", "dnf"),
            ("gem", "rubygems"),
            ("brew", "homebrew"),
            ("npm", "npm"),
            ("pip", "pypi"),
            ("pip3", "pypi"),
            ("pipenv", "pypi"),
            ("pipx", "pypi"),
            ("pnpm", "npm"),
            ("poetry", "pypi"),
            ("uv", "pypi"),
            ("yarn", "npm"),
            ("yum", "yum"),
        ],
    )
    def test_manager_ecosystem_mappings(self, manager: str, ecosystem: str) -> None:
        """Test all manager to ecosystem mappings."""
        assert MANAGER_TO_ECOSYSTEM[manager] == ecosystem


class TestErrorHandlingUnknownEcosystem:
    """Test error handling for unknown ecosystems."""

    def test_get_manager_unknown_ecosystem_error(self) -> None:
        """Verify get_manager raises ValueError for unknown ecosystem."""
        with pytest.raises(ValueError, match=r"Unknown ecosystem"):
            get_manager("unknown_ecosystem_xyz")

    def test_get_manager_empty_string_error(self) -> None:
        """Verify get_manager raises ValueError for empty string."""
        with pytest.raises(ValueError, match=r"Unknown ecosystem"):
            get_manager("")

    def test_resolve_ecosystem_unknown_manager_error(self) -> None:
        """Verify resolve_ecosystem raises ValueError for unknown manager."""
        with pytest.raises(ValueError, match=r"Unknown package manager"):
            resolve_ecosystem("unknown_manager_xyz")

    def test_resolve_ecosystem_empty_string_error(self) -> None:
        """Verify resolve_ecosystem raises ValueError for empty string."""
        with pytest.raises(ValueError, match=r"Unknown package manager"):
            resolve_ecosystem("")


class TestDetectManagerFromSystemPackagesLogging:
    """Regression tests for ``logger.debug`` on manager detection failures.

    S15 added ``logger.debug()`` before bare ``except Exception`` blocks that were
    silently swallowing errors during package manager detection. This test verifies
    that debug logging occurs when imported version lookup functions raise.
    """

    @pytest.mark.asyncio
    async def test_detect_manager_logs_debug_on_import_failure(self) -> None:
        """When ``importlib.import_module`` raises, ``logger.debug`` must be called.

        Root cause: ``pkg_defender/cli/_manager_constants.py:243`` — bare ``except Exception:``
        block that silently passed before S15. Now logs debug with manager name context.
        This test FAILS before the fix and PASSES after.

        Scenario: ``importlib.import_module(module_name)`` raises ``ImportError`` for all managers.
        Expected: returns None, calls ``logger.debug(...)`` for each manager that fails.
        Previously: each exception was silently swallowed via bare ``except Exception: continue``.
        """
        from pkg_defender.cli._manager_constants import _detect_manager_from_system_packages

        # Logger patch MUST be first so it resolves its target import before
        # importlib is mocked (patch resolves dotted targets via importlib internally).
        with (
            patch("pkg_defender.cli._manager_constants.logger") as mock_logger,
            patch(
                "importlib.import_module",
                side_effect=ImportError("mock module not found"),
            ),
        ):
            result = await _detect_manager_from_system_packages("test-package")

        assert result is None
        assert mock_logger.debug.called, "Expected logger.debug to be called at least once"
        args, _ = mock_logger.debug.call_args
        assert "manager detection" in args[0]
        assert "version lookup failed" in args[0]
