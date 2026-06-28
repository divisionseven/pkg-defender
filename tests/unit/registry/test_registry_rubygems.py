"""Tests for pkg_defender.registry.rubygems module.

Tests the RubyGemsAdapter class and standalone convenience functions.
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
from pkg_defender.registry import rubygems
from pkg_defender.registry._timestamp import ResolutionResult


class TestRubyGemsAdapter:
    """Tests for RubyGemsAdapter class."""

    @pytest.fixture
    def adapter(self) -> rubygems.RubyGemsAdapter:
        """Create a RubyGemsAdapter instance."""
        return rubygems.RubyGemsAdapter()

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns latest version when gem exists."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = {"version": "3.4.20"}
            result = await adapter.get_latest_version("rails")

        assert result == "3.4.20"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when gem does not exist."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Gem not found",
            )
            result = await adapter.get_latest_version("nonexistent-gem")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_network_error(
        self, adapter: rubygems.RubyGemsAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.rubygems"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_latest_version("rails")

        assert result is None
        assert "rubygems: registry API failed for rails" in caplog.text

    @pytest.mark.asyncio
    async def test_get_latest_version_invalid_response(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when response is not a dict."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = ["not", "a", "dict"]
            result = await adapter.get_latest_version("rails")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns VersionInfo list with versions and publish times."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {
                    "number": "3.4.20",
                    "created_at": "2024-01-15T10:00:00+00:00",
                    "prerelease": False,
                },
                {
                    "number": "3.4.19",
                    "created_at": "2024-01-10T10:00:00+00:00",
                    "prerelease": False,
                },
            ]
            result = await adapter.get_all_versions("rails")

        assert len(result) == 2
        assert result[0].ecosystem == "rubygems"
        assert result[0].package_name == "rails"
        assert result[0].version == "3.4.20"
        assert result[0].publish_time is not None
        assert result[0].publish_time.isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_get_all_versions_excludes_prerelease(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Excludes prerelease versions from results."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {
                    "number": "3.4.20",
                    "created_at": "2024-01-15T10:00:00Z",
                    "prerelease": False,
                },
                {
                    "number": "4.0.0.rc1",
                    "created_at": "2024-01-20T10:00:00Z",
                    "prerelease": True,
                },
            ]
            result = await adapter.get_all_versions("rails")

        assert len(result) == 1
        assert result[0].version == "3.4.20"

    @pytest.mark.asyncio
    async def test_get_all_versions_network_error(
        self, adapter: rubygems.RubyGemsAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns empty list on network error."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.rubygems"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_all_versions("rails")

        assert result == []
        assert "rubygems: registry API failed for rails" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_versions_invalid_response(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns empty list when response is not a list."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = {"error": "Not found"}
            result = await adapter.get_all_versions("rails")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_publish_time_success(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns publish time when version exists."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {"number": "3.4.20", "created_at": "2024-01-15T10:00:00+00:00"},
                {"number": "3.4.19", "created_at": "2024-01-10T10:00:00+00:00"},
            ]
            result = await adapter.get_publish_time("rails", "3.4.20")

        assert result[0] is not None
        assert result[0].isoformat() == "2024-01-15T10:00:00+00:00"
        assert result[1] == "registry_api"

    @pytest.mark.asyncio
    async def test_get_publish_time_version_not_found(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when version doesn't exist."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = [
                {"number": "3.4.20", "created_at": "2024-01-15T10:00:00Z"},
            ]
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "1.0.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_no_timestamp(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when version has no timestamp."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = [
                {"number": "3.4.20", "created_at": None},
            ]
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_network_error(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestConstants:
    """Tests for module-level constants."""

    def test_rubygems_url_constant(self) -> None:
        """RUBYGEMS_URL is correct."""
        assert rubygems.RUBYGEMS_URL == "https://rubygems.org"

    def test_max_retries_constant(self) -> None:
        """INTEL_FEED_MAX_RETRIES is set to 3."""
        assert INTEL_FEED_MAX_RETRIES == 3


class TestGetAllVersionsEdgeCases:
    """Edge case tests for get_all_versions method."""

    @pytest.fixture
    def adapter(self) -> rubygems.RubyGemsAdapter:
        """Create a RubyGemsAdapter instance."""
        return rubygems.RubyGemsAdapter()

    @pytest.mark.asyncio
    async def test_skips_entry_missing_number_field(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Skips entries without 'number' field."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {"created_at": "2024-01-15T10:00:00+00:00"},  # missing "number"
                {
                    "number": "3.4.20",
                    "created_at": "2024-01-10T10:00:00+00:00",
                    "prerelease": False,
                },
            ]
            result = await adapter.get_all_versions("rails")

        assert len(result) == 1
        assert result[0].version == "3.4.20"

    @pytest.mark.asyncio
    async def test_skips_entry_missing_created_at_field(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Skips entries without 'created_at' field."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {"number": "3.4.20"},  # missing "created_at"
                {
                    "number": "3.4.19",
                    "created_at": "2024-01-10T10:00:00+00:00",
                    "prerelease": False,
                },
            ]
            result = await adapter.get_all_versions("rails")

        assert len(result) == 1
        assert result[0].version == "3.4.19"

    @pytest.mark.asyncio
    async def test_returns_empty_for_all_prerelease_versions(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns empty list when all versions are prerelease."""
        with patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch:
            mock_fetch.return_value = [
                {
                    "number": "4.0.0.alpha",
                    "created_at": "2024-01-20T10:00:00+00:00",
                    "prerelease": True,
                },
                {
                    "number": "4.0.0.beta",
                    "created_at": "2024-01-15T10:00:00+00:00",
                    "prerelease": True,
                },
            ]
            result = await adapter.get_all_versions("rails")

        assert result == []


class TestGetPublishTimeEdgeCases:
    """Edge case tests for get_publish_time method."""

    @pytest.fixture
    def adapter(self) -> rubygems.RubyGemsAdapter:
        """Create a RubyGemsAdapter instance."""
        return rubygems.RubyGemsAdapter()

    @pytest.mark.asyncio
    async def test_non_list_response_returns_none(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when response is not a list (e.g., error dict)."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {"error": "Not Found", "code": 404}
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_empty_list_returns_none(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns None when version list is empty."""
        with (
            patch("pkg_defender.registry.rubygems._rubygems_fetch") as mock_fetch,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = []
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestRubyGemsPublishTimeFallbackChain:
    """Fallback chain tests for get_publish_time."""

    @pytest.fixture
    def adapter(self) -> rubygems.RubyGemsAdapter:
        return rubygems.RubyGemsAdapter()

    @pytest.mark.asyncio
    async def test_resolver_fallback(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns from TimestampResolver when registry API fails."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = "https://github.com/rails/rails"
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 1, 15),
                source_label="libraries_io",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("rails", "3.4.20", is_latest=True)
        assert result[0] == datetime(2024, 1, 15)
        assert result[1] == "libraries_io"

    @pytest.mark.asyncio
    async def test_github_release_fallback(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns from resolver with github_releases when registry API fails."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = "https://github.com/rails/rails"
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 2, 15),
                source_label="github_releases",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("rails", "3.4.20")
        assert result[0] == datetime(2024, 2, 15)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Returns user_manual when all sources fail."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = None
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")
        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_resolver_exception(self, adapter: rubygems.RubyGemsAdapter) -> None:
        """Exception in resolver falls through to user_manual."""
        with (
            patch.object(adapter, "_try_ecosystem_api") as mock_eco,
            patch.object(adapter, "_get_github_url") as mock_gh_url,
            patch("pkg_defender.registry.rubygems.resolve_timestamp") as mock_resolve,
        ):
            mock_eco.return_value = None
            mock_gh_url.return_value = "https://github.com/rails/rails"
            mock_resolve.return_value = ResolutionResult(
                publish_time=None, source_label="unresolved", resolution_status="all_sources_failed", last_error=None
            )
            result = await adapter.get_publish_time("rails", "3.4.20")
        assert result[0] is None
        assert result[1] == "unresolved"


class TestRubyGemsGetInstalledVersion:
    """Tests for rubygems_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_gem_installed(self) -> None:
        """Returns version when gem is installed."""
        with patch(
            "pkg_defender.registry.rubygems.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="rails (3.4.20)\n"),
        ):
            result = await rubygems.rubygems_get_installed_version("rails")
        assert result == "3.4.20"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when gem is not installed."""
        with patch(
            "pkg_defender.registry.rubygems.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await rubygems.rubygems_get_installed_version("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.rubygems.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("gem not found"),
        ):
            result = await rubygems.rubygems_get_installed_version("rails")
        assert result is None

    @pytest.mark.asyncio
    async def test_no_parentheses_in_output(self) -> None:
        """Returns None when output has unexpected format."""
        with patch(
            "pkg_defender.registry.rubygems.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="rails 3.4.20\n"),
        ):
            result = await rubygems.rubygems_get_installed_version("rails")
        assert result is None


class TestRubyGemsFetchGuard:
    """Tests for _rubygems_fetch guard logic (assert → RuntimeError)."""

    @pytest.mark.asyncio
    async def test_rubygems_fetch_raises_runtime_error_on_failure(self) -> None:
        """_rubygems_fetch raises RuntimeError when fetch_json returns failure."""
        with patch("pkg_defender._http.fetch_json") as mock_fetch:
            mock_fetch.return_value = FetchResult(success=False, data=None, error="test error")
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                await rubygems._rubygems_fetch("http://example.com")
