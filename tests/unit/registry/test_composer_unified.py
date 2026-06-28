"""Tests for ComposerUnifiedAdapter — combined Packagist registry + composer command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter


@pytest.fixture
def adapter() -> ComposerUnifiedAdapter:
    """Create a ComposerUnifiedAdapter for testing."""
    return ComposerUnifiedAdapter()


class TestComposerUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_include_threat_intel(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestComposerUnifiedAdapterParse:
    """Test parse() — composer command parsing."""

    def test_parse_require_is_install(self, adapter: ComposerUnifiedAdapter) -> None:
        """composer require = install intent."""
        result = adapter.parse(["require", "monolog/monolog"])
        assert result.manager == "composer"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "monolog/monolog"

    def test_parse_install_no_packages_is_sync(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        """composer install with no packages = SYNC (from composer.json)."""
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC
        assert result.packages == []

    def test_parse_install_with_packages_is_sync(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        """composer install with packages = SYNC (lockfile sync)."""
        result = adapter.parse(["install", "monolog/monolog"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_update_update_intent(self, adapter: ComposerUnifiedAdapter) -> None:
        result = adapter.parse(["update", "monolog/monolog"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_remove_remove_intent(self, adapter: ComposerUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "monolog/monolog"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_create_project_install(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["create-project", "laravel/laravel"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_dev_flag_detection(self, adapter: ComposerUnifiedAdapter) -> None:
        """--dev flag sets is_dev_dependency."""
        result = adapter.parse(["require", "--dev", "phpunit/phpunit"])
        assert result.is_dev_dependency is True

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestComposerUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_require(self, adapter: ComposerUnifiedAdapter) -> None:
        parsed = adapter.parse(["require", "monolog/monolog"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "composer"
        assert "require" in result
        assert "monolog/monolog" in result

    def test_build_exec_args_with_dev_flag(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        parsed = adapter.parse(["require", "--dev", "phpunit/phpunit"])
        result = adapter.build_exec_args(parsed)
        assert "--dev" in result
        assert "phpunit/phpunit" in result


class TestComposerUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to composer module functions."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._composer_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "2.0.0"
            result = await adapter.get_latest_version("monolog/monolog")
            assert result == "2.0.0"
            mock.assert_called_once_with("monolog/monolog", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch.object(
            adapter._composer_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "packagist_api")
            dt, source = await adapter.get_publish_time(
                "monolog/monolog",
                "2.0.0",
            )
            assert dt == expected_dt
            assert source == "packagist_api"
            mock.assert_called_once_with("monolog/monolog", "2.0.0", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._composer_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("monolog/monolog")
            assert result == []
            mock.assert_called_once_with("monolog/monolog", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._composer_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "2.0.0"
            result = await adapter.get_installed_version("monolog/monolog")
            assert result == "2.0.0"
            mock.assert_called_once_with("monolog/monolog")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "2.0.0"
            result = await adapter.resolve_latest_version("monolog/monolog")
            assert result == "2.0.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: ComposerUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "packagist_api")
            result = await adapter.get_release_date("monolog/monolog", "2.0.0")
            assert result == expected_dt
