"""Tests for PoetryUnifiedAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.poetry_unified import PoetryUnifiedAdapter


@pytest.fixture
def adapter() -> PoetryUnifiedAdapter:
    """Create a PoetryUnifiedAdapter for testing."""
    return PoetryUnifiedAdapter()


class TestPoetryUnifiedAdapterIdentity:
    """Test identity attributes."""


class TestPoetryUnifiedAdapterParse:
    """Test parse() — poetry command parsing."""

    def test_parse_add(self, adapter: PoetryUnifiedAdapter) -> None:
        result = adapter.parse(["add", "requests"])
        assert result.manager == "poetry"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1

    def test_parse_install_no_packages_is_sync(
        self,
        adapter: PoetryUnifiedAdapter,
    ) -> None:
        """poetry install with no packages → SYNC intent."""
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_update(self, adapter: PoetryUnifiedAdapter) -> None:
        result = adapter.parse(["update", "requests"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_remove(self, adapter: PoetryUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "requests"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_run(self, adapter: PoetryUnifiedAdapter) -> None:
        result = adapter.parse(["run", "python", "main.py"])
        assert result.intent == CommandIntent.EXECUTE

    def test_parse_safe_passthrough(
        self,
        adapter: PoetryUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["show"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_is_safe_passthrough(
        self,
        adapter: PoetryUnifiedAdapter,
    ) -> None:
        """Unknown subcommand returns SAFE_PASSTHROUGH (fail-closed)."""
        result = adapter.parse(["nonexistent", "x"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: PoetryUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestPoetryUnifiedAdapterBuildExecArgs:
    """Test build_exec_args()."""

    def test_build_add(self, adapter: PoetryUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "requests"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "poetry"
        assert "add" in result
        assert "requests" in result


class TestPoetryUnifiedAdapterRegistryDelegation:
    """Test registry methods inherited from PyPIUnifiedAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: PoetryUnifiedAdapter,
    ) -> None:
        with patch.object(adapter._pypi_delegate, "get_latest_version", new_callable=AsyncMock, return_value="1.0.0"):
            result = await adapter.get_latest_version("flask")
            assert result == "1.0.0"
