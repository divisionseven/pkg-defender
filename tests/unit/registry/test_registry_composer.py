"""Tests for pkg_defender.registry.composer module.

Tests the ComposerAdapter class and standalone convenience functions.
Covers all public methods: get_publish_time, get_all_versions, get_latest_version.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.registry import composer
from pkg_defender.registry._timestamp import ResolutionResult


class TestParsePackageName:
    """Tests for _parse_package_name."""

    def test_vendor_package_format(self) -> None:
        """Splits vendor/package correctly."""
        assert composer._parse_package_name("laravel/framework") == ("laravel", "framework")

    def test_no_vendor_fallback(self) -> None:
        """Package without / returns (package, package)."""
        assert composer._parse_package_name("monolog") == ("monolog", "monolog")


class TestComposerAdapter:
    """Tests for ComposerAdapter class."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        """Create a ComposerAdapter instance."""
        return composer.ComposerAdapter()

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: composer.ComposerAdapter) -> None:
        """Returns latest version when package exists."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.2.3": {"name": "laravel/framework"},
                        "1.2.2": {"name": "laravel/framework"},
                    }
                }
            }
            # get_latest_version returns first key
            result = await adapter.get_latest_version("laravel/framework")

        assert result == "1.2.3"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None when package does not exist."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Package not found",
            )
            result = await adapter.get_latest_version("nonexistent/package")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_network_error(
        self, adapter: composer.ComposerAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.composer._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.composer"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_latest_version("laravel/framework")

        assert result is None
        assert "composer: Packagist API failed for laravel/framework" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: composer.ComposerAdapter) -> None:
        """Returns VersionInfo list with versions and publish times."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.2.3": {
                            "name": "laravel/framework",
                            "time": "2024-01-15T10:00:00+00:00",
                        },
                        "1.2.2": {
                            "name": "laravel/framework",
                            "time": "2024-01-10T10:00:00+00:00",
                        },
                    }
                }
            }
            result = await adapter.get_all_versions("laravel/framework")

        assert len(result) == 2
        assert result[0].ecosystem == "composer"
        assert result[0].package_name == "laravel/framework"
        assert result[0].version == "1.2.3"

    @pytest.mark.asyncio
    async def test_get_all_versions_network_error(
        self, adapter: composer.ComposerAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns empty list on network error."""
        with (
            patch("pkg_defender.registry.composer._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.composer"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_all_versions("laravel/framework")

        assert result == []
        assert "composer: Packagist API failed for laravel/framework" in caplog.text

    @pytest.mark.asyncio
    async def test_get_publish_time_success(self, adapter: composer.ComposerAdapter) -> None:
        """Returns publish time when version exists."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.2.3": {
                            "name": "laravel/framework",
                            "time": "2024-01-15T10:00:00+00:00",
                        }
                    }
                }
            }
            result = await adapter.get_publish_time("laravel/framework", "1.2.3")

        assert result[0] is not None
        assert result[0].isoformat() == "2024-01-15T10:00:00+00:00"
        assert result[1] == "registry"

    @pytest.mark.asyncio
    async def test_get_publish_time_not_found(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None when version doesn't exist."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"package": {"versions": {}}}
            result = await adapter.get_publish_time("laravel/framework", "0.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"

    @pytest.mark.asyncio
    async def test_get_publish_time_network_error(
        self, adapter: composer.ComposerAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.composer._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.composer"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_publish_time("laravel/framework", "1.2.3")

        assert result[0] is None
        assert result[1] == "user_manual"
        assert "composer: Packagist API failed for laravel/framework" in caplog.text


class TestConstants:
    """Tests for constants."""


class TestComposerAdapterGetLatestVersion:
    """Tests for ComposerAdapter.get_latest_version() dev-branch filtering."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        """Create a ComposerAdapter instance."""
        return composer.ComposerAdapter()

    @pytest.mark.asyncio
    async def test_get_latest_version_skips_dev(self, adapter: composer.ComposerAdapter) -> None:
        """Dev versions like dev-main are filtered out; stable version returned."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "dev-main": {"name": "laravel/framework"},
                        "3.10.0": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_latest_version("laravel/framework")

        assert result == "3.10.0"

    @pytest.mark.asyncio
    async def test_get_latest_version_all_dev(self, adapter: composer.ComposerAdapter) -> None:
        """When only dev versions exist, returns None."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "dev-main": {"name": "laravel/framework"},
                        "dev-master": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_latest_version("laravel/framework")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_filters_unstable(self, adapter: composer.ComposerAdapter) -> None:
        """Alpha, beta, RC versions are filtered out; only stable version returned."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "2.0.0-alpha": {"name": "laravel/framework"},
                        "2.0.0": {"name": "laravel/framework"},
                        "3.0.0-beta": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_latest_version("laravel/framework")

        assert result == "2.0.0"

    @pytest.mark.asyncio
    async def test_get_latest_version_all_unstable(self, adapter: composer.ComposerAdapter) -> None:
        """All versions are pre-release (alpha/beta/RC filter) → returns None."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "2.0.0-alpha": {"name": "laravel/framework"},
                        "2.1.0-beta": {"name": "laravel/framework"},
                        "3.0.0-RC": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_latest_version("laravel/framework")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_parse_fallback(self, adapter: composer.ComposerAdapter) -> None:
        """Version parsing fails for a version string → falls back to unsorted last version."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "not-a-valid-version": {"name": "laravel/framework"},
                        "1.0.0": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_latest_version("laravel/framework")

        # Should return the last valid version (falls back to unsorted list)
        assert result == "1.0.0"


class TestFetchJson:
    """Tests for _fetch_json bridge function."""

    @pytest.mark.asyncio
    async def test_returns_dict_when_fetch_succeeds(self) -> None:
        """Returns dict when fetch_json succeeds."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.data = {"key": "value"}
        mock_result.error = None

        with patch("pkg_defender._http.fetch_json", new=AsyncMock(return_value=mock_result)):
            result = await composer._fetch_json("http://example.com")
            assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_runtime_error_on_failure(self) -> None:
        """Raises RuntimeError when fetch_json fails."""
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.data = None
        mock_result.error = "Not found"

        with (
            patch("pkg_defender._http.fetch_json", new=AsyncMock(return_value=mock_result)),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await composer._fetch_json("http://example.com")


class TestExtractGithubRepo:
    """Tests for _extract_github_repo."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        return composer.ComposerAdapter()

    def test_github_url_found(self, adapter: composer.ComposerAdapter) -> None:
        """Returns GitHub URL when repository has github.com."""
        data = {"repository": {"url": "https://github.com/laravel/framework.git"}}
        result = adapter._extract_github_repo(data)
        assert result == "https://github.com/laravel/framework.git"

    def test_non_github_url(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None for non-GitHub repository."""
        data = {"repository": {"url": "https://gitlab.com/laravel/framework.git"}}
        result = adapter._extract_github_repo(data)
        assert result is None

    def test_no_repository_key(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None when no repository key."""
        data = {}
        result = adapter._extract_github_repo(data)
        assert result is None

    def test_no_url_in_repo(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None when repository has no url key."""
        data = {"repository": {}}
        result = adapter._extract_github_repo(data)
        assert result is None


class TestComposerPublishTimeGithubFallback:
    """Tests for get_publish_time GitHub fallback chain."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        return composer.ComposerAdapter()

    @pytest.mark.asyncio
    async def test_no_version_data_github_fallback(self, adapter: composer.ComposerAdapter) -> None:
        """Falls back to TimestampResolver when version not in Packagist data."""
        with (
            patch("pkg_defender.registry.composer._fetch_json") as mock_fetch,
            patch("pkg_defender.registry.composer.resolve_timestamp") as mock_resolve,
        ):
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.0.0": {"time": "2024-01-10T10:00:00+00:00"},
                    },
                    "repository": {"url": "https://github.com/laravel/framework.git"},
                }
            }
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 2, 15),
                source_label="github_releases",
                resolution_status="resolved",
                last_error=None,
            )
            result = await adapter.get_publish_time("laravel/framework", "1.2.3")

        assert result[0] == datetime(2024, 2, 15)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self, adapter: composer.ComposerAdapter) -> None:
        """Returns user_manual when all sources fail."""
        with (
            patch("pkg_defender.registry.composer._fetch_json") as mock_fetch,
        ):
            mock_fetch.side_effect = aiohttp.ClientError("timeout")
            result = await adapter.get_publish_time("laravel/framework", "1.2.3")

        assert result[0] is None
        assert result[1] == "user_manual"


class TestComposerGetAllVersions:
    """Tests for get_all_versions uncovered paths."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        return composer.ComposerAdapter()

    @pytest.mark.asyncio
    async def test_skips_version_without_time(self, adapter: composer.ComposerAdapter) -> None:
        """Versions without 'time' field are skipped."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.2.3": {"name": "laravel/framework", "time": "2024-01-15T10:00:00+00:00"},
                        "1.0.0": {"name": "laravel/framework"},  # no time field
                    }
                }
            }
            result = await adapter.get_all_versions("laravel/framework")

        assert len(result) == 1
        assert result[0].version == "1.2.3"

    @pytest.mark.asyncio
    async def test_empty_versions(self, adapter: composer.ComposerAdapter) -> None:
        """Returns empty list when no versions have time."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "package": {
                    "versions": {
                        "1.0.0": {"name": "laravel/framework"},
                    }
                }
            }
            result = await adapter.get_all_versions("laravel/framework")
        assert result == []


class TestComposerGetLatestVersion:
    """Tests for get_latest_version uncovered paths."""

    @pytest.fixture
    def adapter(self) -> composer.ComposerAdapter:
        return composer.ComposerAdapter()

    @pytest.mark.asyncio
    async def test_empty_versions_dict(self, adapter: composer.ComposerAdapter) -> None:
        """Returns None when versions dict is empty."""
        with patch("pkg_defender.registry.composer._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"package": {"versions": {}}}
            result = await adapter.get_latest_version("laravel/framework")
        assert result is None


class TestComposerGetInstalledVersion:
    """Tests for composer_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_composer_show_succeeds(self) -> None:
        """Returns version when composer show succeeds."""
        with patch(
            "pkg_defender.registry.composer.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="versions : v1.2.3\n"),
        ):
            result = await composer.composer_get_installed_version("laravel/framework")

        assert result == "1.2.3"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        with patch(
            "pkg_defender.registry.composer.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await composer.composer_get_installed_version("laravel/framework")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises exception."""
        with patch(
            "pkg_defender.registry.composer.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("composer not found"),
        ):
            result = await composer.composer_get_installed_version("laravel/framework")
        assert result is None
