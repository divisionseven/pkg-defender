"""Tests for PyPIUnifiedAdapter — combined PyPI registry + pip command parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.pypi_unified import (
    PyPIUnifiedAdapter,
    pypi_unified_get_latest_version,
    pypi_unified_get_publish_time,
)


@pytest.fixture
def adapter() -> PyPIUnifiedAdapter:
    """Create a PyPIUnifiedAdapter for testing."""
    return PyPIUnifiedAdapter()


class TestPyPIUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_verified_timestamps(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """PyPIUnifiedAdapter has VERIFIED_PUBLISH_TIMESTAMPS capability."""
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_include_threat_intel(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """PyPIUnifiedAdapter has THREAT_INTEL_SUPPORT capability."""
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities


class TestPyPIUnifiedAdapterParse:
    """Test parse() — command parsing from PipAdapter."""

    def test_parse_install_with_package(self, adapter: PyPIUnifiedAdapter) -> None:
        """parse(['install', 'requests==2.31.0']) returns INSTALL intent with packages."""
        result = adapter.parse(["install", "requests==2.31.0"])
        assert result.manager == "pip"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"
        assert result.packages[0].version == "2.31.0"
        assert result.packages[0].raw == "requests==2.31.0"

    def test_parse_install_multiple_packages(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['install', 'requests', 'flask']) returns 2 packages."""
        result = adapter.parse(["install", "requests", "flask"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 2
        assert result.packages[0].name == "requests"
        assert result.packages[1].name == "flask"

    def test_parse_safe_passthrough_list(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['list']) returns SAFE_PASSTHROUGH with no packages."""
        result = adapter.parse(["list"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH
        assert result.packages == []

    def test_parse_safe_passthrough_show(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['show', 'requests']) returns SAFE_PASSTHROUGH."""
        result = adapter.parse(["show", "requests"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_download_is_install_intent(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['download', 'requests']) returns INSTALL intent."""
        result = adapter.parse(["download", "requests"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_sync_intent(self, adapter: PyPIUnifiedAdapter) -> None:
        """parse(['sync']) returns SYNC intent."""
        result = adapter.parse(["sync"])
        assert result.intent == CommandIntent.SYNC

    def test_parse_strips_dry_run_flag(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse strips --dry-run into pkgd_flags."""
        result = adapter.parse(["install", "requests", "--dry-run"])
        assert result.intent == CommandIntent.INSTALL
        assert result.pkgd_flags.get("dry_run") is True
        assert "--dry-run" not in result.manager_flags

    def test_parse_requirement_file_target(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['install', '-r', 'requirements.txt']) captures file target."""
        result = adapter.parse(["install", "-r", "requirements.txt"])
        assert result.intent == CommandIntent.INSTALL
        assert "requirements.txt" in result.file_targets
        assert result.requires_file_audit is True

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe_passthrough(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """parse(['unknown-cmd', 'x']) returns SAFE_PASSTHROUGH (fail-closed)."""
        result = adapter.parse(["unknown-cmd", "x"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_extras(self, adapter: PyPIUnifiedAdapter) -> None:
        """parse(['install', 'requests[security,socks]']) parses extras."""
        result = adapter.parse(["install", "requests[security,socks]"])
        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"
        assert "security" in result.packages[0].extras
        assert "socks" in result.packages[0].extras

    def test_parse_vcs_source(self, adapter: PyPIUnifiedAdapter) -> None:
        """parse(['install', 'git+https://...']) detects VCS."""
        result = adapter.parse(
            ["install", "git+https://github.com/user/repo.git"],
        )
        assert len(result.packages) == 1
        from pkg_defender.models.command import InstallSource

        assert result.packages[0].source == InstallSource.VCS


class TestPyPIUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction from PipAdapter."""

    def test_build_exec_args_install(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """build_exec_args reconstructs 'pip install requests'."""
        parsed = adapter.parse(["install", "requests"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "pip"
        assert "install" in result
        assert "requests" in result

    def test_build_exec_args_with_version(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """build_exec_args reconstructs 'pip install requests==2.31.0'."""
        parsed = adapter.parse(["install", "requests==2.31.0"])
        result = adapter.build_exec_args(parsed)
        assert "requests==2.31.0" in result

    def test_build_exec_args_with_requirement_file(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """build_exec_args includes -r for file targets."""
        parsed = adapter.parse(["install", "-r", "requirements.txt"])
        result = adapter.build_exec_args(parsed)
        assert "-r" in result
        assert "requirements.txt" in result


class TestPyPIUnifiedAdapterBridgeDelegation:
    """Test bridge methods delegate to PyPIAdapter."""

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """resolve_latest_version delegates to get_latest_version."""
        adapter._pypi_delegate.get_latest_version = AsyncMock(
            return_value="2.31.0",
        )
        result = await adapter.resolve_latest_version("requests")
        assert result == "2.31.0"
        adapter._pypi_delegate.get_latest_version.assert_called_once_with("requests", None)

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """get_release_date delegates to get_publish_time and returns datetime."""
        expected_dt = datetime(2024, 1, 15, tzinfo=UTC)
        adapter._pypi_delegate.get_publish_time = AsyncMock(
            return_value=(expected_dt, "registry_api"),
        )
        result = await adapter.get_release_date("requests", "2.31.0")
        assert result == expected_dt
        adapter._pypi_delegate.get_publish_time.assert_called_once_with(
            "requests",
            "2.31.0",
            None,
            is_latest=False,
        )

    @pytest.mark.asyncio
    async def test_fetch_release_date_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """fetch_release_date delegates to get_publish_time and returns datetime."""
        expected_dt = datetime(2024, 3, 1, tzinfo=UTC)
        adapter._pypi_delegate.get_publish_time = AsyncMock(
            return_value=(expected_dt, "registry_api"),
        )
        result = await adapter.fetch_release_date("requests", "2.31.0")
        assert result == expected_dt


class TestPyPIUnifiedAdapterRegistryDelegation:
    """Test direct registry method delegation to PyPIAdapter."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """get_latest_version delegates to PyPIAdapter.get_latest_version."""
        adapter._pypi_delegate.get_latest_version = AsyncMock(
            return_value="1.0.0",
        )
        result = await adapter.get_latest_version("flask")
        assert result == "1.0.0"

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """get_publish_time delegates to PyPIAdapter.get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        adapter._pypi_delegate.get_publish_time = AsyncMock(
            return_value=(expected_dt, "registry_api"),
        )
        dt, source = await adapter.get_publish_time("flask", "3.0.0")
        assert dt == expected_dt
        assert source == "registry_api"

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """get_all_versions delegates to PyPIAdapter.get_all_versions."""
        from pkg_defender.models import VersionInfo

        fake_versions = [
            VersionInfo(
                ecosystem="pypi",
                package_name="flask",
                version="3.0.0",
                publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ),
        ]
        adapter._pypi_delegate.get_all_versions = AsyncMock(
            return_value=fake_versions,
        )
        result = await adapter.get_all_versions("flask")
        assert len(result) == 1
        assert result[0].version == "3.0.0"

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: PyPIUnifiedAdapter,
    ) -> None:
        """get_installed_version delegates to PyPIAdapter.get_installed_version."""
        adapter._pypi_delegate.get_installed_version = AsyncMock(
            return_value="2.0.0",
        )
        result = await adapter.get_installed_version("flask")
        assert result == "2.0.0"


class TestPyPIUnifiedStandaloneFunctions:
    """Test standalone convenience functions in pypi_unified.py."""

    async def test_pypi_unified_get_publish_time_delegates(
        self,
    ) -> None:
        """Standalone pypi_unified_get_publish_time delegates to PyPIUnifiedAdapter."""
        from datetime import UTC, datetime

        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch(
            "pkg_defender.registry.pypi.PyPIAdapter.get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "registry_api")
            dt, source = await pypi_unified_get_publish_time("flask", "3.0.0")

        assert dt == expected_dt
        assert source == "registry_api"

    async def test_pypi_unified_get_latest_version_delegates(
        self,
    ) -> None:
        """Standalone pypi_unified_get_latest_version delegates to PyPIUnifiedAdapter."""
        with patch(
            "pkg_defender.registry.pypi.PyPIAdapter.get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "3.0.0"
            result = await pypi_unified_get_latest_version("flask")

        assert result == "3.0.0"
