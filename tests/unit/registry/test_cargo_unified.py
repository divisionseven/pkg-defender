"""Tests for CargoUnifiedAdapter — combined crates.io registry + cargo command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter


@pytest.fixture
def adapter() -> CargoUnifiedAdapter:
    """Create a CargoUnifiedAdapter for testing."""
    return CargoUnifiedAdapter()


class TestCargoUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_include_threat_intel(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestCargoUnifiedAdapterParse:
    """Test parse() — cargo command parsing."""

    def test_parse_install_with_package(self, adapter: CargoUnifiedAdapter) -> None:
        result = adapter.parse(["install", "serde"])
        assert result.manager == "cargo"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "serde"

    def test_parse_add_install_intent(self, adapter: CargoUnifiedAdapter) -> None:
        """cargo add = install intent."""
        result = adapter.parse(["add", "tokio"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "tokio"

    def test_parse_update_intent(self, adapter: CargoUnifiedAdapter) -> None:
        result = adapter.parse(["update", "serde"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_fetch_is_sync(self, adapter: CargoUnifiedAdapter) -> None:
        """cargo fetch = SYNC (downloads dependencies)."""
        result = adapter.parse(["fetch"])
        assert result.intent == CommandIntent.SYNC
        assert result.packages == []

    def test_parse_build_safe_passthrough(self, adapter: CargoUnifiedAdapter) -> None:
        result = adapter.parse(["build"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_run_execute(self, adapter: CargoUnifiedAdapter) -> None:
        result = adapter.parse(["run", "--bin", "myapp"])
        assert result.intent == CommandIntent.EXECUTE

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestCargoUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: CargoUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "serde"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "cargo"
        assert "install" in result
        assert "serde" in result

    def test_build_exec_args_add(self, adapter: CargoUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "tokio@1.0.0"])
        result = adapter.build_exec_args(parsed)
        assert "tokio@1.0.0" in result


class TestCargoUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to cargo module functions."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._cargo_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "1.0.0"
            result = await adapter.get_latest_version("serde")
            assert result == "1.0.0"
            mock.assert_called_once_with("serde", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch.object(
            adapter._cargo_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "registry_api")
            dt, source = await adapter.get_publish_time("serde", "1.0.0")
            assert dt == expected_dt
            assert source == "registry_api"
            mock.assert_called_once_with("serde", "1.0.0", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._cargo_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("serde")
            assert result == []
            mock.assert_called_once_with("serde", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._cargo_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "1.0.0"
            result = await adapter.get_installed_version("serde")
            assert result == "1.0.0"
            mock.assert_called_once_with("serde")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "1.0.0"
            result = await adapter.resolve_latest_version("serde")
            assert result == "1.0.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: CargoUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "registry_api")
            result = await adapter.get_release_date("serde", "1.0.0")
            assert result == expected_dt
