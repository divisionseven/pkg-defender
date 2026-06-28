"""Tests for pkg_defender.registry.npm module.

Tests the module-level functions for npm registry operations:
get_publish_time, get_all_versions, get_latest_version,
get_all_version_timestamps, get_version_info, and helpers.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.registry import npm
from pkg_defender.registry._timestamp import ResolutionResult


class TestEncodePackageName:
    """Tests for _encode_package_name URL encoding."""

    def test_plain_package(self) -> None:
        """Non-scoped package names are returned unchanged."""
        assert npm._encode_package_name("lodash") == "lodash"

    def test_scoped_package(self) -> None:
        """Scoped package names are URL-encoded."""
        encoded = npm._encode_package_name("@scope/name")
        assert encoded == "%40scope%2Fname"

    def test_scoped_with_dots(self) -> None:
        """Scoped package with dots is URL-encoded."""
        encoded = npm._encode_package_name("@types/node")
        assert encoded == "%40types%2Fnode"


class TestFetchJson:
    """Tests for _fetch_json bridge function."""

    @pytest.mark.asyncio
    async def test_returns_parsed_json_dict_on_success(self) -> None:
        """Returns parsed JSON dict on success."""
        with patch("pkg_defender._http.fetch_json") as mock_impl:
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {"version": "1.0.0"}
            mock_result.error = None
            mock_impl.return_value = mock_result

            result = await npm._fetch_json("https://registry.npmjs.org/test")

        assert result == {"version": "1.0.0"}

    @pytest.mark.asyncio
    async def test_failure_raises_runtime_error(self) -> None:
        """Raises RuntimeError when fetch_json returns failure."""
        with patch("pkg_defender._http.fetch_json") as mock_impl:
            mock_result = MagicMock()
            mock_result.success = False
            mock_result.data = None
            mock_result.error = "404 Not Found"
            mock_impl.return_value = mock_result

            with pytest.raises(RuntimeError, match="Failed to fetch"):
                await npm._fetch_json("https://registry.npmjs.org/test")


class TestTryEcosystemApi:
    """Tests for _try_ecosystem_api."""

    @pytest.mark.asyncio
    async def test_returns_datetime_when_version_has_timestamp(self) -> None:
        """Returns datetime when version has a timestamp."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "time": {
                    "1.0.0": "2024-01-15T10:00:00+00:00",
                    "created": "2023-01-01T00:00:00+00:00",
                    "modified": "2024-06-01T00:00:00+00:00",
                }
            }
            result = await npm._try_ecosystem_api("lodash", "1.0.0")

        assert result is not None
        assert result.isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_version_not_in_time_dict(self) -> None:
        """Returns None when version not found in time dict."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"time": {}}
            result = await npm._try_ecosystem_api("lodash", "1.0.0")

        assert result is None

    @pytest.mark.asyncio
    async def test_version_no_timestamp(self) -> None:
        """Returns None when version has no timestamp."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"time": {"1.0.0": None}}
            result = await npm._try_ecosystem_api("lodash", "1.0.0")

        assert result is None

    @pytest.mark.asyncio
    async def test_handles_error(self) -> None:
        """Propagates error from _fetch_json."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.side_effect = RuntimeError("Fetch failed")
            with pytest.raises(RuntimeError):
                await npm._try_ecosystem_api("lodash", "1.0.0")


class TestGetPublishTime:
    """Tests for get_publish_time standalone function."""

    @pytest.mark.asyncio
    async def test_ecosystem_api_success(self) -> None:
        """Returns datetime and registry_api source on ecosystem API success."""
        with patch("pkg_defender.registry.npm._try_ecosystem_api") as mock_api:
            mock_api.return_value = datetime(2024, 1, 15, 10, 0, 0)
            result = await npm.get_publish_time("lodash", "1.0.0")

        assert result[0] == datetime(2024, 1, 15, 10, 0, 0)
        assert result[1] == "registry_api"

    @pytest.mark.asyncio
    async def test_github_releases_fallback(self) -> None:
        """Falls back to TimestampResolver when ecosystem API returns None."""
        with (
            patch("pkg_defender.registry.npm._try_ecosystem_api") as mock_api,
            patch("pkg_defender.registry.npm.resolve_timestamp") as mock_resolve,
        ):
            mock_api.return_value = None
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 1, 15, 10, 0, 0),
                source_label="github_releases",
                resolution_status="resolved",
                last_error=None,
            )
            result = await npm.get_publish_time("lodash", "1.0.0")

        assert result[0] == datetime(2024, 1, 15, 10, 0, 0)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self) -> None:
        """Returns None and user_manual when all sources fail."""
        with (
            patch("pkg_defender.registry.npm._try_ecosystem_api") as mock_api,
            patch("pkg_defender.registry.npm.resolve_timestamp") as mock_resolve,
        ):
            mock_api.return_value = None
            mock_resolve.return_value = ResolutionResult(
                publish_time=None,
                source_label="unresolved",
                resolution_status="all_sources_failed",
                last_error=None,
            )
            result = await npm.get_publish_time("lodash", "1.0.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_ecosystem_api_exception_caught(self) -> None:
        """Catches exception from ecosystem API and continues to fallback."""
        with (
            patch("pkg_defender.registry.npm._try_ecosystem_api") as mock_api,
            patch("pkg_defender.registry.npm.resolve_timestamp") as mock_resolve,
        ):
            mock_api.side_effect = RuntimeError("API down")
            mock_resolve.return_value = ResolutionResult(
                publish_time=datetime(2024, 1, 15, 10, 0, 0),
                source_label="libraries_io",
                resolution_status="resolved",
                last_error=None,
            )
            result = await npm.get_publish_time("lodash", "1.0.0")

        assert result[0] == datetime(2024, 1, 15, 10, 0, 0)
        assert result[1] == "libraries_io"

    @pytest.mark.asyncio
    async def test_all_exceptions_caught(self) -> None:
        """Catches exceptions from all sources and returns user_manual."""
        with (
            patch("pkg_defender.registry.npm._try_ecosystem_api") as mock_api,
            patch("pkg_defender.registry.npm.resolve_timestamp") as mock_resolve,
        ):
            mock_api.side_effect = RuntimeError("API down")
            mock_resolve.return_value = ResolutionResult(
                publish_time=None,
                source_label="unresolved",
                resolution_status="all_sources_failed",
                last_error=None,
            )
            result = await npm.get_publish_time("lodash", "1.0.0")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestGetAllVersions:
    """Tests for get_all_versions."""

    @pytest.mark.asyncio
    async def test_returns_version_list_on_success(self) -> None:
        """Returns list of version strings on success."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "versions": {
                    "1.0.0": {},
                    "1.0.1": {},
                    "2.0.0": {},
                }
            }
            result = await npm.get_all_versions("lodash")

        assert sorted(result) == ["1.0.0", "1.0.1", "2.0.0"]

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self, caplog: pytest.LogCaptureFixture) -> None:
        """Returns empty list on fetch error."""
        with (
            patch("pkg_defender.registry.npm._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.npm"),
        ):
            mock_fetch.side_effect = TimeoutError("Timeout")
            result = await npm.get_all_versions("lodash")

        assert result == []
        assert "npm: registry API failed for lodash" in caplog.text

    @pytest.mark.asyncio
    async def test_no_versions_key(self) -> None:
        """Returns empty list when response has no versions key."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {}
            result = await npm.get_all_versions("lodash")

        assert result == []

    @pytest.mark.asyncio
    async def test_scoped_package(self) -> None:
        """Works with scoped package names."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"versions": {"1.0.0": {}}}
            result = await npm.get_all_versions("@types/node")

        assert result == ["1.0.0"]


class TestGetLatestVersion:
    """Tests for get_latest_version."""

    @pytest.mark.asyncio
    async def test_returns_latest_version_from_dist_tags(self) -> None:
        """Returns latest version from dist-tags."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "dist-tags": {"latest": "2.0.0"},
            }
            result = await npm.get_latest_version("lodash")

        assert result == "2.0.0"

    @pytest.mark.asyncio
    async def test_fetch_error_returns_none(self, caplog: pytest.LogCaptureFixture) -> None:
        """Returns None on fetch error."""
        with (
            patch("pkg_defender.registry.npm._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.npm"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Error")
            result = await npm.get_latest_version("lodash")

        assert result is None
        assert "npm: registry API failed for lodash" in caplog.text

    @pytest.mark.asyncio
    async def test_no_dist_tags(self) -> None:
        """Returns None when dist-tags is missing."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {}
            result = await npm.get_latest_version("lodash")

        assert result is None

    @pytest.mark.asyncio
    async def test_no_latest_tag(self) -> None:
        """Returns None when latest tag is missing."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {"dist-tags": {}}
            result = await npm.get_latest_version("lodash")

        assert result is None


class TestGetAllVersionTimestamps:
    """Tests for get_all_version_timestamps."""

    @pytest.mark.asyncio
    async def test_returns_version_timestamp_dict_on_success(self) -> None:
        """Returns dict of version to datetime on success."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "time": {
                    "1.0.0": "2024-01-15T10:00:00+00:00",
                    "1.0.1": "2024-02-15T10:00:00+00:00",
                    "created": "2023-01-01T00:00:00+00:00",
                    "modified": "2024-06-01T00:00:00+00:00",
                }
            }
            result = await npm.get_all_version_timestamps("lodash")

        assert "1.0.0" in result
        assert "1.0.1" in result
        assert "created" not in result
        assert "modified" not in result
        assert result["1.0.0"].isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty_dict(self, caplog: pytest.LogCaptureFixture) -> None:
        """Returns empty dict on fetch error."""
        with (
            patch("pkg_defender.registry.npm._fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.npm"),
        ):
            mock_fetch.side_effect = TimeoutError("Timeout")
            result = await npm.get_all_version_timestamps("lodash")

        assert result == {}
        assert "npm: registry API failed for lodash" in caplog.text

    @pytest.mark.asyncio
    async def test_no_time_key(self) -> None:
        """Returns empty dict when time key is missing."""
        with patch("pkg_defender.registry.npm._fetch_json") as mock_fetch:
            mock_fetch.return_value = {}
            result = await npm.get_all_version_timestamps("lodash")

        assert result == {}


class TestGetVersionInfo:
    """Tests for get_version_info."""

    @pytest.mark.asyncio
    async def test_returns_version_info_when_publish_time_found(self) -> None:
        """Returns VersionInfo when publish time is found."""
        with patch("pkg_defender.registry.npm.get_publish_time") as mock_get:
            mock_get.return_value = (datetime(2024, 1, 15, 10, 0, 0), "registry_api")
            result = await npm.get_version_info("lodash", "1.0.0")

        assert result is not None
        assert result.version == "1.0.0"
        assert result.ecosystem == "npm"
        assert result.package_name == "lodash"
        assert result.publish_time == datetime(2024, 1, 15, 10, 0, 0)

    @pytest.mark.asyncio
    async def test_no_publish_time_returns_none(self) -> None:
        """Returns None when publish time is not found."""
        with patch("pkg_defender.registry.npm.get_publish_time") as mock_get:
            mock_get.return_value = (None, "unresolved")
            result = await npm.get_version_info("lodash", "1.0.0")

        assert result is None


class TestNpmGetInstalledVersion:
    """Tests for npm_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_from_npm_list_output(self) -> None:
        """Returns version from npm list output."""
        import json

        payload = json.dumps(
            {
                "dependencies": {
                    "lodash": {"version": "4.17.21"},
                }
            }
        )
        with patch(
            "pkg_defender.registry.npm.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout=payload),
        ):
            result = await npm.npm_get_installed_version("lodash")

        assert result == "4.17.21"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        import json

        payload = json.dumps({"dependencies": {}})
        with patch(
            "pkg_defender.registry.npm.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout=payload),
        ):
            result = await npm.npm_get_installed_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_non_zero_returncode(self) -> None:
        """Returns None when npm list fails."""
        with patch(
            "pkg_defender.registry.npm.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await npm.npm_get_installed_version("lodash")

        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises an exception."""
        with patch(
            "pkg_defender.registry.npm.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("npm not found"),
        ):
            result = await npm.npm_get_installed_version("lodash")

        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_json_returns_none(self) -> None:
        """Returns None when npm list output is invalid JSON."""
        with patch(
            "pkg_defender.registry.npm.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="not valid json"),
        ):
            result = await npm.npm_get_installed_version("lodash")

        assert result is None
