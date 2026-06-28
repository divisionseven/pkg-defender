"""Tests for GemUnifiedAdapter — combined RubyGems registry + gem command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.gem_unified import GemUnifiedAdapter


@pytest.fixture
def adapter() -> GemUnifiedAdapter:
    """Create a GemUnifiedAdapter for testing."""
    return GemUnifiedAdapter()


class TestGemUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_include_threat_intel(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestGemUnifiedAdapterParse:
    """Test parse() — command parsing."""

    def test_parse_install_with_package(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["install", "rails"])
        assert result.manager == "gem"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "rails"

    def test_parse_install_with_version(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["install", "rails@7.1.0"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "rails"
        assert result.packages[0].version == "7.1.0"

    def test_parse_install_multiple_packages(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["install", "rails", "rack"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 2

    def test_parse_update_intent(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["update", "rails"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_fetch_intent(self, adapter: GemUnifiedAdapter) -> None:
        """gem fetch = download gem file = INSTALL intent."""
        result = adapter.parse(["fetch", "rails"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_query_safe_passthrough(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["query", "--name", "rails"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_build_safe_passthrough(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["build", "rails.gemspec"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_push_safe_passthrough(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["push", "rails-7.1.0.gem"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_owner_safe_passthrough(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["owner", "-a", "user@example.com", "rails"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_safe_passthrough_list(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["list"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH
        assert result.packages == []

    def test_parse_search_command(self, adapter: GemUnifiedAdapter) -> None:
        """gem search rails — read-only, SAFE_PASSTHROUGH."""
        result = adapter.parse(["search", "rails"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH
        assert result.packages == []

    def test_parse_safe_passthrough_unknown(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_is_global_by_default(self, adapter: GemUnifiedAdapter) -> None:
        """gem install without --local is global."""
        result = adapter.parse(["install", "rails"])
        assert result.is_global is True

    def test_parse_is_not_global_with_local_flag(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        """gem install --local is NOT global."""
        result = adapter.parse(["install", "--local", "rails"])
        assert result.is_global is False

    def test_parse_strips_dry_run_flag(self, adapter: GemUnifiedAdapter) -> None:
        result = adapter.parse(["install", "rails", "--dry-run"])
        assert result.intent == CommandIntent.INSTALL
        assert result.pkgd_flags.get("dry_run") is True


class TestGemUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: GemUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "rails"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "gem"
        assert "install" in result
        assert "rails" in result

    def test_build_exec_args_update(self, adapter: GemUnifiedAdapter) -> None:
        parsed = adapter.parse(["update", "rails"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "gem"
        assert "update" in result


class TestGemUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to rubygems module functions."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._rubygems_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.get_latest_version("rails")
            assert result == "7.1.0"
            mock.assert_called_once_with("rails", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch.object(
            adapter._rubygems_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "registry_api")
            dt, source = await adapter.get_publish_time("rails", "7.1.0")
            assert dt == expected_dt
            assert source == "registry_api"
            mock.assert_called_once_with("rails", "7.1.0", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        fake_versions: list = []
        with patch.object(
            adapter._rubygems_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = fake_versions
            result = await adapter.get_all_versions("rails")
            assert result is fake_versions
            mock.assert_called_once_with("rails", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._rubygems_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.get_installed_version("rails")
            assert result == "7.1.0"
            mock.assert_called_once_with("rails")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.resolve_latest_version("rails")
            assert result == "7.1.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: GemUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "registry_api")
            result = await adapter.get_release_date("rails", "7.1.0")
            assert result == expected_dt
