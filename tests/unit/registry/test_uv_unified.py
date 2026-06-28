"""Tests for UvUnifiedAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.uv_unified import UvUnifiedAdapter


@pytest.fixture
def adapter() -> UvUnifiedAdapter:
    """Create a UvUnifiedAdapter for testing."""
    return UvUnifiedAdapter()


class TestUvUnifiedAdapterIdentity:
    """Test identity attributes."""


class TestUvUnifiedAdapterParse:
    """Test parse() — uv command parsing including compound subcommands."""

    def test_parse_add(self, adapter: UvUnifiedAdapter) -> None:
        result = adapter.parse(["add", "requests"])
        assert result.manager == "uv"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1

    def test_parse_install(self, adapter: UvUnifiedAdapter) -> None:
        result = adapter.parse(["install", "requests"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_pip_install(self, adapter: UvUnifiedAdapter) -> None:
        """uv pip install is INSTALL intent."""
        result = adapter.parse(["pip", "install", "requests"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_tool_install_compound(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """uv tool install is INSTALL intent with compound subcommand."""
        result = adapter.parse(["tool", "install", "ruff"])
        assert result.intent == CommandIntent.INSTALL
        assert result.manager_subcommand == "tool install"

    def test_parse_tool_upgrade_compound(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """uv tool upgrade is UPDATE intent."""
        result = adapter.parse(["tool", "upgrade", "ruff"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_sync(self, adapter: UvUnifiedAdapter) -> None:
        result = adapter.parse(["sync"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_run(self, adapter: UvUnifiedAdapter) -> None:
        result = adapter.parse(["run", "python", "main.py"])
        assert result.intent == CommandIntent.EXECUTE

    def test_parse_requirement_file(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """uv pip install -r requirements.txt captures file target."""
        result = adapter.parse(["pip", "install", "-r", "requirements.txt"])
        assert "requirements.txt" in result.file_targets
        assert result.requires_file_audit is True

    def test_parse_safe_passthrough(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["list"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_is_safe_passthrough(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """Unknown subcommand returns SAFE_PASSTHROUGH (fail-closed)."""
        result = adapter.parse(["nonexistent", "x"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestUvUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — including compound subcommand split."""

    def test_build_install(self, adapter: UvUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "requests"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "uv"
        assert "install" in result
        assert "requests" in result

    def test_build_tool_install_splits(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        """build_exec_args splits 'tool install' into ['tool', 'install']."""
        parsed = adapter.parse(["tool", "install", "ruff"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "uv"
        assert result[1] == "tool"
        assert result[2] == "install"
        assert "ruff" in result


class TestUvUnifiedAdapterRegistryDelegation:
    """Test registry methods inherited from PyPIUnifiedAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: UvUnifiedAdapter,
    ) -> None:
        adapter._pypi_delegate.get_latest_version = AsyncMock(
            return_value="1.0.0",
        )
        result = await adapter.get_latest_version("flask")
        assert result == "1.0.0"
