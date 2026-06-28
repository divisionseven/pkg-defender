"""Tests for NpmUnifiedAdapter — combined npm registry + npm command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter


@pytest.fixture
def adapter() -> NpmUnifiedAdapter:
    """Create an NpmUnifiedAdapter for testing."""
    return NpmUnifiedAdapter()


class TestNpmUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_include_threat_intel(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestNpmUnifiedAdapterParse:
    """Test parse() — command parsing from NpmAdapter."""

    def test_parse_install_with_package(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "express@4.18.0"])
        assert result.manager == "npm"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "express"
        assert result.packages[0].version == "4.18.0"

    def test_parse_install_multiple_packages(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "express", "lodash"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 2

    def test_parse_install_no_packages_is_sync(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        """npm install with no packages = SYNC (from package.json)."""
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC
        assert result.packages == []

    def test_parse_i_shorthand(self, adapter: NpmUnifiedAdapter) -> None:
        """npm i = npm install shorthand."""
        result = adapter.parse(["i", "express"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_add_install_intent(self, adapter: NpmUnifiedAdapter) -> None:
        """npm add = install intent."""
        result = adapter.parse(["add", "lodash"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_remove_intent(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "express"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_rm_shorthand(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["rm", "express"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_uninstall_shorthand(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["uninstall", "express"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_update_intent(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["update", "express"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_up_shorthand(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["up", "express"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_safe_passthrough_list(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["list"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH
        assert result.packages == []

    def test_parse_safe_passthrough_info(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["info", "express"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_global_flag(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "-g", "express"])
        assert result.is_global is True

    def test_parse_dev_dependency_flag(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "--save-dev", "express"])
        assert result.is_dev_dependency is True
        assert "--save-dev" not in result.manager_flags

    def test_parse_dev_d_shorthand(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "-D", "express"])
        assert result.is_dev_dependency is True

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_scoped_package(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "@angular/core@15.0.0"])
        assert len(result.packages) == 1
        assert result.packages[0].name == "@angular/core"
        assert result.packages[0].version == "15.0.0"

    def test_parse_version_range(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "express@^4.0.0"])
        assert len(result.packages) == 1
        assert result.packages[0].version_constraint == "^4.0.0"

    def test_parse_strips_dry_run_flag(self, adapter: NpmUnifiedAdapter) -> None:
        result = adapter.parse(["install", "express", "--dry-run"])
        assert result.intent == CommandIntent.INSTALL
        assert result.pkgd_flags.get("dry_run") is True


class TestNpmUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: NpmUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "express"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "npm"
        assert "install" in result
        assert "express" in result

    def test_build_exec_args_with_version(self, adapter: NpmUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "express@4.18.0"])
        result = adapter.build_exec_args(parsed)
        assert "express@4.18.0" in result

    def test_build_exec_args_with_dev_flag(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        parsed = adapter.parse(["install", "--save-dev", "express"])
        result = adapter.build_exec_args(parsed)
        assert "--save-dev" in result


class TestNpmUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to npm module functions."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        with patch(
            "pkg_defender.registry.npm.get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "5.0.0"
            result = await adapter.get_latest_version("express")
            assert result == "5.0.0"
            mock.assert_called_once_with("express", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        with patch(
            "pkg_defender.registry.npm.get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "registry_api")
            dt, source = await adapter.get_publish_time("express", "4.18.0")
            assert dt == expected_dt
            assert source == "registry_api"
            mock.assert_called_once_with("express", "4.18.0", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        fake_timestamps = {
            "4.18.0": datetime(2024, 1, 1, tzinfo=UTC),
            "4.17.0": datetime(2023, 1, 1, tzinfo=UTC),
        }
        with patch(
            "pkg_defender.registry.npm.get_all_version_timestamps",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = fake_timestamps
            result = await adapter.get_all_versions("express")
            assert len(result) == 2
            assert result[0].version == "4.18.0"
            assert result[0].ecosystem == "npm"

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        with patch(
            "pkg_defender.registry.npm.npm_get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "4.18.0"
            result = await adapter.get_installed_version("express")
            assert result == "4.18.0"
            mock.assert_called_once_with("express")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "5.0.0"
            result = await adapter.resolve_latest_version("express")
            assert result == "5.0.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: NpmUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "registry_api")
            result = await adapter.get_release_date("express", "4.18.0")
            assert result == expected_dt
