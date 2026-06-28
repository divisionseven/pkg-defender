"""Tests for CondaUnifiedAdapter — combined conda-forge registry + conda command parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.conda_unified import CondaUnifiedAdapter


@pytest.fixture
def adapter() -> CondaUnifiedAdapter:
    """Create a CondaUnifiedAdapter for testing."""
    return CondaUnifiedAdapter()


class TestCondaUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_publish_timestamps(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestCondaUnifiedAdapterParse:
    """Test parse() — conda command parsing."""

    def test_parse_install_with_package(self, adapter: CondaUnifiedAdapter) -> None:
        result = adapter.parse(["install", "numpy"])
        assert result.manager == "conda"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "numpy"

    def test_parse_create_install_intent(self, adapter: CondaUnifiedAdapter) -> None:
        """conda create = install intent."""
        result = adapter.parse(["create", "-n", "myenv", "pandas"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "pandas"

    def test_parse_env_create_compound(self, adapter: CondaUnifiedAdapter) -> None:
        """conda env create = compound subcommand."""
        result = adapter.parse(["env", "create", "-f", "environment.yml"])
        assert result.intent == CommandIntent.INSTALL
        assert result.manager_subcommand == "env create"

    def test_parse_env_update_compound(self, adapter: CondaUnifiedAdapter) -> None:
        """conda env update = compound subcommand."""
        result = adapter.parse(["env", "update", "-f", "environment.yml"])
        assert result.intent == CommandIntent.INSTALL
        assert result.manager_subcommand == "env update"

    def test_parse_update_intent(self, adapter: CondaUnifiedAdapter) -> None:
        result = adapter.parse(["update", "numpy"])
        assert result.intent == CommandIntent.UPDATE

    def test_parse_env_safe_passthrough(self, adapter: CondaUnifiedAdapter) -> None:
        """conda env alone = SAFE_PASSTHROUGH."""
        result = adapter.parse(["env"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestCondaUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: CondaUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "numpy"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "conda"
        assert "install" in result
        assert "numpy" in result

    def test_build_exec_args_env_create_compound(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        """Compound subcommand 'env create' is split back into two args."""
        parsed = adapter.parse(["env", "create", "-f", "environment.yml"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "conda"
        assert result[1] == "env"
        assert result[2] == "create"


class TestCondaUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to CondaAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._conda_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "24.1.0"
            result = await adapter.get_latest_version("numpy")
            assert result == "24.1.0"
            mock.assert_called_once_with("numpy", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_returns_user_manual(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        """Conda does not provide per-version timestamps."""
        with patch.object(
            adapter._conda_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (None, "unresolved")
            dt, source = await adapter.get_publish_time("numpy", "1.24.0")
            assert dt is None
            assert source == "unresolved"
            mock.assert_called_once_with("numpy", "1.24.0", is_latest=False)

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._conda_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("numpy")
            assert result == []
            mock.assert_called_once_with("numpy")

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._conda_delegate,
            "get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "24.1.0"
            result = await adapter.get_installed_version("numpy")
            assert result == "24.1.0"
            mock.assert_called_once_with("numpy")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "24.1.0"
            result = await adapter.resolve_latest_version("numpy")
            assert result == "24.1.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: CondaUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "unresolved")
            result = await adapter.get_release_date("numpy", "1.24.0")
            assert result is None
