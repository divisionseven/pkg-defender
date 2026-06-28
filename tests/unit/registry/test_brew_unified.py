"""Tests for BrewUnifiedAdapter — combined Homebrew registry + brew command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter


@pytest.fixture
def adapter() -> BrewUnifiedAdapter:
    """Create a BrewUnifiedAdapter for testing."""
    return BrewUnifiedAdapter()


class TestBrewUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_proxied_timestamps(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in adapter.capabilities


class TestBrewUnifiedAdapterParse:
    """Test parse() — brew command parsing."""

    def test_parse_install_with_package(self, adapter: BrewUnifiedAdapter) -> None:
        result = adapter.parse(["install", "wget"])
        assert result.manager == "brew"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "wget"
        assert result.is_global is True

    def test_parse_upgrade_update_intent(self, adapter: BrewUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade", "wget"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_upgrade_no_packages_is_sync(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        """brew upgrade with no packages = SYNC (upgrades all)."""
        result = adapter.parse(["upgrade"])
        assert result.intent == CommandIntent.SYNC
        assert result.is_global is True

    def test_parse_reinstall_install_intent(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["reinstall", "wget"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_bundle_install_intent(self, adapter: BrewUnifiedAdapter) -> None:
        """brew bundle = install intent (from Brewfile)."""
        result = adapter.parse(["bundle"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_tap_safe_passthrough(self, adapter: BrewUnifiedAdapter) -> None:
        result = adapter.parse(["tap", "homebrew/cask"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestBrewUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: BrewUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "wget"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "brew"
        assert "install" in result
        assert "wget" in result

    def test_build_exec_args_with_flags(self, adapter: BrewUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "--cask", "firefox"])
        result = adapter.build_exec_args(parsed)
        assert "--cask" in result
        assert "firefox" in result


class TestBrewUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to BrewAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._brew_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "1.21.0"
            result = await adapter.get_latest_version("wget")
            assert result == "1.21.0"
            mock.assert_called_once_with("wget", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch.object(
            adapter._brew_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "brew_api_proxy")
            dt, source = await adapter.get_publish_time("wget", "1.21.0")
            assert dt == expected_dt
            assert source == "brew_api_proxy"
            mock.assert_called_once_with("wget", "1.21.0", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._brew_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("wget")
            assert result == []
            mock.assert_called_once_with("wget", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._brew_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "1.21.0"
            result = await adapter.get_installed_version("wget")
            assert result == "1.21.0"
            mock.assert_called_once_with("wget")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "1.21.0"
            result = await adapter.resolve_latest_version("wget")
            assert result == "1.21.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: BrewUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "brew_api_proxy")
            result = await adapter.get_release_date("wget", "1.21.0")
            assert result == expected_dt
