"""Tests for pkg_defender.registry.cargo module.

Tests the CargoAdapter class and standalone convenience functions.
Covers all public methods: get_publish_time, get_all_versions, get_latest_version.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender._http import FetchResult
from pkg_defender.config.settings import INTEL_FEED_MAX_RETRIES
from pkg_defender.registry import cargo
from pkg_defender.registry._timestamp import ResolutionResult


class TestCargoAdapter:
    """Tests for CargoAdapter class."""

    @pytest.fixture
    def adapter(self) -> cargo.CargoAdapter:
        """Create a CargoAdapter instance."""
        return cargo.CargoAdapter()

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: cargo.CargoAdapter) -> None:
        """Returns latest version when crate exists."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "crate": {
                    "name": "serde",
                    "max_version": "1.0.190",
                }
            }
            result = await adapter.get_latest_version("serde")

        assert result == "1.0.190"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when crate does not exist."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Crate not found",
            )
            result = await adapter.get_latest_version("nonexistent-crate")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_network_error(
        self, adapter: cargo.CargoAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.cargo"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_latest_version("serde")

        assert result is None
        assert "cargo: registry API failed for serde" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: cargo.CargoAdapter) -> None:
        """Returns VersionInfo list with versions and publish times."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {
                        "num": "1.0.190",
                        "created_at": "2024-01-15T10:00:00+00:00",
                        "yanked": False,
                    },
                    {
                        "num": "1.0.189",
                        "created_at": "2024-01-10T10:00:00+00:00",
                        "yanked": False,
                    },
                ]
            }
            result = await adapter.get_all_versions("serde")

        assert len(result) == 2
        assert result[0].ecosystem == "cargo"
        assert result[0].package_name == "serde"
        assert result[0].version == "1.0.190"
        assert result[0].publish_time is not None
        assert result[0].publish_time.isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_get_all_versions_excludes_yanked(self, adapter: cargo.CargoAdapter) -> None:
        """Excludes yanked versions from results."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {
                        "num": "1.0.190",
                        "created_at": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    },
                    {
                        "num": "1.0.189",
                        "created_at": "2024-01-10T10:00:00Z",
                        "yanked": True,
                    },
                ]
            }
            result = await adapter.get_all_versions("serde")

        assert len(result) == 1
        assert result[0].version == "1.0.190"

    @pytest.mark.asyncio
    async def test_get_all_versions_network_error(
        self, adapter: cargo.CargoAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns empty list on network error."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.cargo"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_all_versions("serde")

        assert result == []
        assert "cargo: registry API failed for serde" in caplog.text

    @pytest.mark.asyncio
    async def test_get_publish_time_success(self, adapter: cargo.CargoAdapter) -> None:
        """Returns publish time when version exists."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {"num": "1.0.190", "created_at": "2024-01-15T10:00:00+00:00"},
                    {"num": "1.0.189", "created_at": "2024-01-10T10:00:00+00:00"},
                ]
            }
            result = await adapter.get_publish_time("serde", "1.0.190")

        assert result[0] is not None
        assert result[0].isoformat() == "2024-01-15T10:00:00+00:00"
        assert result[1] == "registry_api"

    @pytest.mark.asyncio
    async def test_get_publish_time_version_not_found(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when version doesn't exist."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {
                "versions": [
                    {"num": "1.0.190", "created_at": "2024-01-15T10:00:00Z"},
                ]
            }
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "0.9.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_no_timestamp(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when version has no timestamp."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {
                "versions": [
                    {"num": "1.0.190", "created_at": None},
                ]
            }
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "1.0.190")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_network_error(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "1.0.190")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestCargoFetch:
    """Tests for _cargo_fetch function.

    Note: Direct testing of _cargo_fetch is indirect through adapter methods
    which already have network error handling tests in TestCargoAdapter.
    Error handling tests:
    - TestCargoAdapter::test_get_latest_version_network_error
    - TestCargoAdapter::test_get_all_versions_network_error
    - TestCargoAdapter::test_get_publish_time_network_error
    """


class TestConstants:
    """Tests for module-level constants."""

    def test_crates_io_url_constant(self) -> None:
        """CRATES_IO_URL is correct."""
        assert cargo.CRATES_IO_URL == "https://crates.io"

    def test_max_retries_constant(self) -> None:
        """INTEL_FEED_MAX_RETRIES is set to 3."""
        assert INTEL_FEED_MAX_RETRIES == 3


class TestGetAllVersionsEdgeCases:
    """Edge case tests for get_all_versions method."""

    @pytest.fixture
    def adapter(self) -> cargo.CargoAdapter:
        """Create a CargoAdapter instance."""
        return cargo.CargoAdapter()

    @pytest.mark.asyncio
    async def test_skips_entry_missing_num_field(self, adapter: cargo.CargoAdapter) -> None:
        """Skips entries without 'num' field."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {"created_at": "2024-01-15T10:00:00+00:00"},  # missing "num"
                    {"num": "1.0.190", "created_at": "2024-01-10T10:00:00+00:00", "yanked": False},
                ]
            }
            result = await adapter.get_all_versions("serde")

        assert len(result) == 1
        assert result[0].version == "1.0.190"

    @pytest.mark.asyncio
    async def test_skips_entry_missing_created_at_field(self, adapter: cargo.CargoAdapter) -> None:
        """Skips entries without 'created_at' field."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {"num": "1.0.190"},  # missing "created_at"
                    {"num": "1.0.189", "created_at": "2024-01-10T10:00:00+00:00", "yanked": False},
                ]
            }
            result = await adapter.get_all_versions("serde")

        assert len(result) == 1
        assert result[0].version == "1.0.189"

    @pytest.mark.asyncio
    async def test_returns_empty_for_all_yanked_versions(self, adapter: cargo.CargoAdapter) -> None:
        """Returns empty list when all versions are yanked."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "versions": [
                    {"num": "1.0.190", "created_at": "2024-01-20T10:00:00+00:00", "yanked": True},
                    {"num": "1.0.189", "created_at": "2024-01-15T10:00:00+00:00", "yanked": True},
                ]
            }
            result = await adapter.get_all_versions("serde")

        assert result == []


class TestGetPublishTimeEdgeCases:
    """Edge case tests for get_publish_time method."""

    @pytest.fixture
    def adapter(self) -> cargo.CargoAdapter:
        """Create a CargoAdapter instance."""
        return cargo.CargoAdapter()

    @pytest.mark.asyncio
    async def test_missing_versions_key_returns_none(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when response has no 'versions' key."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            patch.object(adapter, "_get_github_url", new=AsyncMock(return_value=None)),
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {"crate": "serde"}  # no "versions" key
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "1.0.190")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_empty_versions_array_returns_none(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when versions array is empty."""
        with (
            patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {"versions": []}
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "1.0.190")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestGetLatestVersionEdgeCases:
    """Edge case tests for get_latest_version method."""

    @pytest.fixture
    def adapter(self) -> cargo.CargoAdapter:
        """Create a CargoAdapter instance."""
        return cargo.CargoAdapter()

    @pytest.mark.asyncio
    async def test_missing_crate_key_returns_none(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when response has no 'crate' key."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {"versions": []}  # no "crate" key
            result = await adapter.get_latest_version("serde")

        assert result is None

    @pytest.mark.asyncio
    async def test_missing_max_version_returns_none(self, adapter: cargo.CargoAdapter) -> None:
        """Returns None when crate has no 'max_version' field."""
        with patch("pkg_defender.registry.cargo._cargo_fetch") as mock_fetch:
            mock_fetch.return_value = {"crate": {"name": "serde"}}  # no max_version
            result = await adapter.get_latest_version("serde")

        assert result is None


class TestCargoPublishTimeFallbackChain:
    """Fallback chain tests for get_publish_time."""

    @pytest.fixture
    def adapter(self) -> cargo.CargoAdapter:
        return cargo.CargoAdapter()

    @pytest.mark.asyncio
    async def test_alternate_source_fallback(self, adapter: cargo.CargoAdapter) -> None:
        """Returns from TimestampResolver when registry API fails."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = "https://github.com/serde-rs/serde"
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 1, 15),
                source_label="libraries_io",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("serde", "1.0.190", is_latest=True)
        assert result[0] == datetime(2024, 1, 15)
        assert result[1] == "libraries_io"

    @pytest.mark.asyncio
    async def test_github_release_fallback(self, adapter: cargo.CargoAdapter) -> None:
        """Returns from resolver with github_releases when registry API fails."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = "https://github.com/serde-rs/serde"
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 2, 15),
                source_label="github_releases",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("serde", "1.0.190")
        assert result[0] == datetime(2024, 2, 15)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self, adapter: cargo.CargoAdapter) -> None:
        """Returns user_manual when all sources fail."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = None
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("serde", "1.0.190")
        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_registry_api_exception(self, adapter: cargo.CargoAdapter) -> None:
        """Exception in registry API doesn't prevent fallbacks."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.cargo.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.side_effect = Exception("unexpected error")
            mock_gh_url.return_value = "https://github.com/serde-rs/serde"
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 1, 15),
                source_label="github_tags",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("serde", "1.0.190")
        assert result[0] == datetime(2024, 1, 15)
        assert result[1] == "github_tags"


class TestCargoGetInstalledVersion:
    """Tests for cargo_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_crate_installed(self) -> None:
        """Returns version when crate is installed."""
        with patch(
            "pkg_defender.registry.cargo.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="serde v1.0.190\n"),
        ):
            result = await cargo.cargo_get_installed_version("serde")
        assert result == "1.0.190"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when crate is not installed."""
        with patch(
            "pkg_defender.registry.cargo.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await cargo.cargo_get_installed_version("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.cargo.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("cargo not found"),
        ):
            result = await cargo.cargo_get_installed_version("serde")
        assert result is None


class TestCargoFetchGuard:
    """Tests for _cargo_fetch guard logic (assert → RuntimeError)."""

    @pytest.mark.asyncio
    async def test_cargo_fetch_raises_runtime_error_on_failure(self) -> None:
        """_cargo_fetch raises RuntimeError when fetch_json returns failure."""
        with patch("pkg_defender._http.fetch_json") as mock_fetch:
            mock_fetch.return_value = FetchResult(success=False, data=None, error="test error")
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                await cargo._cargo_fetch("http://example.com")
