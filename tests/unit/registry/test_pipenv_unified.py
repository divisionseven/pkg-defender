"""Tests for PipenvUnifiedAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.pipenv_unified import PipenvUnifiedAdapter


@pytest.fixture
def adapter() -> PipenvUnifiedAdapter:
    """Create a PipenvUnifiedAdapter for testing."""
    return PipenvUnifiedAdapter()


class TestPipenvUnifiedAdapterIdentity:
    """Test identity attributes."""


class TestPipenvUnifiedAdapterParse:
    """Test parse() — pipenv command parsing."""

    def test_parse_install(self, adapter: PipenvUnifiedAdapter) -> None:
        result = adapter.parse(["install", "requests"])
        assert result.manager == "pipenv"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1

    def test_parse_sync(self, adapter: PipenvUnifiedAdapter) -> None:
        result = adapter.parse(["sync"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_update(self, adapter: PipenvUnifiedAdapter) -> None:
        result = adapter.parse(["update", "requests"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_upgrade(self, adapter: PipenvUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade", "requests"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_dev_flag(self, adapter: PipenvUnifiedAdapter) -> None:
        result = adapter.parse(["install", "--dev", "requests"])
        assert result.is_dev_dependency is True
        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"

    def test_parse_safe_passthrough(
        self,
        adapter: PipenvUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["graph"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_is_safe_passthrough(
        self,
        adapter: PipenvUnifiedAdapter,
    ) -> None:
        """Unknown subcommand returns SAFE_PASSTHROUGH (fail-closed)."""
        result = adapter.parse(["nonexistent", "x"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: PipenvUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestPipenvUnifiedAdapterBuildExecArgs:
    """Test build_exec_args()."""

    def test_build_install(self, adapter: PipenvUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "requests"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "pipenv"
        assert "install" in result
        assert "requests" in result


class TestPipenvUnifiedAdapterRegistryDelegation:
    """Test registry methods inherited from PyPIUnifiedAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: PipenvUnifiedAdapter,
    ) -> None:
        adapter._pypi_delegate.get_latest_version = AsyncMock(
            return_value="1.0.0",
        )
        result = await adapter.get_latest_version("flask")
        assert result == "1.0.0"
