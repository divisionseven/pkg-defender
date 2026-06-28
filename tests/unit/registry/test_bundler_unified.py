"""Tests for BundlerUnifiedAdapter — RubyGems registry + bundle command parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter


@pytest.fixture
def adapter() -> BundlerUnifiedAdapter:
    """Create a BundlerUnifiedAdapter for testing."""
    return BundlerUnifiedAdapter()


class TestBundlerUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_inherited_from_gem(self, adapter: BundlerUnifiedAdapter) -> None:
        """Bundler inherits RubyGems capabilities from GemUnifiedAdapter."""
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestBundlerUnifiedAdapterParse:
    """Test parse() — bundle command parsing."""

    def test_parse_install_sync(self, adapter: BundlerUnifiedAdapter) -> None:
        """bundle install with no packages = SYNC (from Gemfile)."""
        result = adapter.parse(["install"])
        assert result.manager == "bundle"
        assert result.intent == CommandIntent.SYNC
        assert result.packages == []

    def test_parse_install_with_package_is_sync(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        """bundle install with a .gem file path is SYNC."""
        result = adapter.parse(["install", "--local"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_add_intent(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["add", "rails"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "rails"

    def test_parse_add_with_version(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["add", "rails@7.1.0"])
        assert result.intent == CommandIntent.INSTALL
        assert result.packages[0].version == "7.1.0"

    def test_parse_update_intent(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["update", "rails"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_exec_intent(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["exec", "rake", "db:migrate"])
        assert result.intent == CommandIntent.EXECUTE

    def test_parse_check_sync(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["check"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_outdated_safe(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["outdated"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_why_safe(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["why", "rails"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_list_safe(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["list"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_show_safe(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["show", "rails"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_safe_passthrough_viz(self, adapter: BundlerUnifiedAdapter) -> None:
        """bundle viz is not in the intent map → safe passthrough."""
        result = adapter.parse(["viz"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_strips_dry_run_flag(self, adapter: BundlerUnifiedAdapter) -> None:
        result = adapter.parse(["add", "rails", "--dry-run"])
        assert result.intent == CommandIntent.INSTALL
        assert result.pkgd_flags.get("dry_run") is True


class TestBundlerUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: BundlerUnifiedAdapter) -> None:
        parsed = adapter.parse(["install"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "bundle"
        assert "install" in result

    def test_build_exec_args_add(self, adapter: BundlerUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "rails"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "bundle"
        assert "add" in result
        assert "rails" in result

    def test_build_exec_args_exec(self, adapter: BundlerUnifiedAdapter) -> None:
        parsed = adapter.parse(["exec", "rake", "db:migrate"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "bundle"
        assert "exec" in result
        assert "rake" in result


class TestBundlerUnifiedAdapterRegistryDelegation:
    """Test that BundlerUnifiedAdapter inherits registry methods from GemUnifiedAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._rubygems_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.get_latest_version("rails")
            assert result == "7.1.0"

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._rubygems_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (None, "unresolved")
            dt, source = await adapter.get_publish_time("rails", "7.1.0")
            assert source == "unresolved"

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._rubygems_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.get_installed_version("rails")
            assert result == "7.1.0"

    @pytest.mark.asyncio
    async def test_resolve_latest_version_bridge(
        self,
        adapter: BundlerUnifiedAdapter,
    ) -> None:
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "7.1.0"
            result = await adapter.resolve_latest_version("rails")
            assert result == "7.1.0"
