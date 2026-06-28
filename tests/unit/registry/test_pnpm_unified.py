"""Tests for PnpmUnifiedAdapter — npm registry + pnpm command parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.pnpm_unified import PnpmUnifiedAdapter


@pytest.fixture
def adapter() -> PnpmUnifiedAdapter:
    return PnpmUnifiedAdapter()


class TestPnpmUnifiedAdapterIdentity:
    pass


class TestPnpmUnifiedAdapterParse:
    def test_pnpm_add_is_install(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["add", "lodash"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "lodash"

    def test_pnpm_install_is_sync(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC

    def test_pnpm_i_is_sync(self, adapter: PnpmUnifiedAdapter) -> None:
        """pnpm i = install from manifest (sync)."""
        result = adapter.parse(["i"])
        assert result.intent == CommandIntent.SYNC

    def test_pnpm_update_is_update(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["update", "lodash"])
        assert result.intent == CommandIntent.UPDATE

    def test_pnpm_remove_is_remove(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "lodash"])
        assert result.intent == CommandIntent.REMOVE

    def test_pnpm_dlx_is_execute(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["dlx", "create-vite"])
        assert result.intent == CommandIntent.EXECUTE

    def test_pnpm_import_is_safe(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["import"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_pnpm_add_no_packages_is_sync(self, adapter: PnpmUnifiedAdapter) -> None:
        """pnpm add with no packages → SYNC (no-op)."""
        result = adapter.parse(["add"])
        assert result.intent == CommandIntent.SYNC

    def test_pnpm_dev_dependency(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["add", "--save-dev", "jest"])
        assert result.is_dev_dependency is True

    def test_pnpm_global(self, adapter: PnpmUnifiedAdapter) -> None:
        result = adapter.parse(["add", "--global", "http-server"])
        assert result.is_global is True

    def test_parse_pnpm_store(self, adapter: PnpmUnifiedAdapter) -> None:
        """pnpm store status is safe passthrough."""
        result = adapter.parse(["store", "status"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_pnpm_audit(self, adapter: PnpmUnifiedAdapter) -> None:
        """pnpm audit is not in intent map → safe passthrough."""
        result = adapter.parse(["audit"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: PnpmUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestPnpmUnifiedAdapterBuildExecArgs:
    def test_build_exec_args_add(self, adapter: PnpmUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "lodash"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "pnpm"
        assert "add" in result
        assert "lodash" in result

    def test_build_exec_args_with_version(self, adapter: PnpmUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "lodash@4.17.21"])
        result = adapter.build_exec_args(parsed)
        assert "lodash@4.17.21" in result

    def test_build_exec_args_remove(self, adapter: PnpmUnifiedAdapter) -> None:
        parsed = adapter.parse(["remove", "lodash"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "pnpm"
        assert "remove" in result
        assert "lodash" in result


class TestPnpmUnifiedAdapterBridgeMethods:
    def test_bridge_methods_inherited(self, adapter: PnpmUnifiedAdapter) -> None:
        """Verify bridge methods are inherited from NpmUnifiedAdapter."""
        assert hasattr(adapter, "resolve_latest_version")
        assert hasattr(adapter, "get_release_date")
        assert hasattr(adapter, "fetch_release_date")

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(self, adapter: PnpmUnifiedAdapter) -> None:
        with patch("pkg_defender.registry.npm.get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "5.0.0"
            result = await adapter.get_latest_version("express")
            assert result == "5.0.0"

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(self, adapter: PnpmUnifiedAdapter) -> None:
        with patch("pkg_defender.registry.npm.get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "registry_api")
            dt, source = await adapter.get_publish_time("express", "4.18.0")
            assert source == "registry_api"

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(self, adapter: PnpmUnifiedAdapter) -> None:
        with patch("pkg_defender.registry.npm.npm_get_installed_version", new_callable=AsyncMock) as mock:
            mock.return_value = "4.18.0"
            result = await adapter.get_installed_version("express")
            assert result == "4.18.0"
