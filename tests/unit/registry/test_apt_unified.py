"""Tests for AptUnifiedAdapter — combined Debian registry + apt command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.base import EcosystemCapability


@pytest.fixture
def adapter() -> AptUnifiedAdapter:
    """Create an AptUnifiedAdapter for testing."""
    return AptUnifiedAdapter()


class TestAptUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities


class TestAptUnifiedAdapterParse:
    """Test parse() — apt command parsing."""

    def test_parse_install_with_package(self, adapter: AptUnifiedAdapter) -> None:
        result = adapter.parse(["install", "curl"])
        assert result.manager == "apt"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "curl"
        assert result.is_global is True

    def test_parse_update_is_sync(self, adapter: AptUnifiedAdapter) -> None:
        """apt update = SYNC (refreshes package index)."""
        result = adapter.parse(["update"])
        assert result.intent == CommandIntent.SYNC
        assert result.is_global is True

    def test_parse_upgrade_update_intent(self, adapter: AptUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_remove_remove_intent(self, adapter: AptUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "curl"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_purge_remove_intent(self, adapter: AptUnifiedAdapter) -> None:
        result = adapter.parse(["purge", "curl"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_autoremove_remove_intent(self, adapter: AptUnifiedAdapter) -> None:
        result = adapter.parse(["autoremove"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestAptUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: AptUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "curl"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "apt"
        assert "install" in result
        assert "curl" in result

    def test_build_exec_args_with_flags(self, adapter: AptUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "-y", "curl"])
        result = adapter.build_exec_args(parsed)
        assert "-y" in result
        assert "curl" in result


class TestAptUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to apt module functions."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._apt_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.88.1"
            result = await adapter.get_latest_version("curl")
            assert result == "7.88.1"
            mock.assert_called_once_with("curl", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch.object(
            adapter._apt_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "snapshot_debian")
            dt, source = await adapter.get_publish_time("curl", "7.88.1-1")
            assert dt == expected_dt
            assert source == "snapshot_debian"
            mock.assert_called_once_with("curl", "7.88.1-1", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._apt_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("curl")
            assert result == []
            mock.assert_called_once_with("curl", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._apt_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.88.1-1"
            result = await adapter.get_installed_version("curl")
            assert result == "7.88.1-1"
            mock.assert_called_once_with("curl")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "7.88.1"
            result = await adapter.resolve_latest_version("curl")
            assert result == "7.88.1"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: AptUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "snapshot_debian")
            result = await adapter.get_release_date("curl", "7.88.1-1")
            assert result == expected_dt
