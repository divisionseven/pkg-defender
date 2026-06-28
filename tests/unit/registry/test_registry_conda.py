"""Tests for pkg_defender.registry.conda module.

Tests the CondaAdapter class and standalone convenience functions.
Covers all public methods: get_publish_time, get_all_versions, get_latest_version.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.config.settings import INTEL_FEED_MAX_RETRIES
from pkg_defender.registry import conda
from pkg_defender.registry._timestamp import ResolutionResult


class TestCondaAdapter:
    """Tests for CondaAdapter class."""

    @pytest.fixture
    def adapter(self) -> conda.CondaAdapter:
        """Create a CondaAdapter instance."""
        return conda.CondaAdapter()

    def test_capabilities_property(self, adapter: conda.CondaAdapter) -> None:
        """Returns capabilities including VERIFIED_PUBLISH_TIMESTAMPS."""
        from pkg_defender.registry.base import EcosystemCapability

        caps = adapter.capabilities
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in caps
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in caps

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: conda.CondaAdapter) -> None:
        """Returns latest version when package exists."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.return_value = """# Name                    Version  Build         Channel
# ______________________________
numpy                     1.26.4   py312haa1c40_202  conda-forge
numpy                     1.24.3   py311hcf9a2d4_103  conda-forge
"""
            result = await adapter.get_latest_version("numpy")

        assert result == "1.26.4"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when package does not exist."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["conda", "search", "nonexistent"],
            )
            result = await adapter.get_latest_version("nonexistent-package")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_timeout(self, adapter: conda.CondaAdapter) -> None:
        """Returns None on timeout."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.side_effect = TimeoutError("timed out after 30s")
            result = await adapter.get_latest_version("numpy")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_conda_not_installed(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when conda is not installed."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.side_effect = FileNotFoundError("conda not found")
            result = await adapter.get_latest_version("numpy")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: conda.CondaAdapter) -> None:
        """Returns VersionInfo list with versions."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.return_value = """# Name                    Version  Build         Channel
numpy                     1.26.4   py312haa1c40_202  conda-forge
numpy                     1.24.3   py311hcf9a2d4_103  conda-forge
"""
            result = await adapter.get_all_versions("numpy")

        assert len(result) == 2
        assert result[0].ecosystem == "conda"
        assert result[0].package_name == "numpy"
        assert result[0].version == "1.26.4"
        assert result[1].version == "1.24.3"

    @pytest.mark.asyncio
    async def test_get_all_versions_not_found(self, adapter: conda.CondaAdapter) -> None:
        """Returns empty list when package not found."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["conda", "search", "nonexistent"],
            )
            result = await adapter.get_all_versions("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_timeout(self, adapter: conda.CondaAdapter) -> None:
        """Returns empty list on timeout."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.side_effect = TimeoutError("timed out after 30s")
            result = await adapter.get_all_versions("numpy")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_publish_time_always_none(self, adapter: conda.CondaAdapter) -> None:
        """Returns user_manual when TimestampResolver returns None (fallback path)."""
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="user_manual",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            result = await adapter.get_publish_time("numpy", "1.26.4")

        assert result[0] is None
        assert result[1] == "user_manual"

    @pytest.mark.asyncio
    async def test_get_publish_time_via_github(self, adapter: conda.CondaAdapter) -> None:
        """Returns github publish time when TimestampResolver succeeds (fallback path)."""
        from datetime import datetime

        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2026, 3, 15),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            result = await adapter.get_publish_time("numpy", "1.26.4")

        assert result[0] is not None
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_get_installed_version(self, adapter: conda.CondaAdapter) -> None:
        """get_installed_version delegates to conda_get_installed_version (line 385)."""
        with patch("pkg_defender.registry.conda.conda_get_installed_version", new_callable=AsyncMock) as mock_conda:
            mock_conda.return_value = "3.12.0"
            result = await adapter.get_installed_version("python")

        assert result == "3.12.0"

    @pytest.mark.asyncio
    async def test_get_all_versions_no_package_info(self, adapter: conda.CondaAdapter) -> None:
        """Returns empty list when parsed data has no package info (line 323)."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            mock_search.return_value = "# Name  Version  Build  Channel\n"
            result = await adapter.get_all_versions("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_latest_version_empty_versions(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when versions list is empty (lines 367, 372)."""
        with patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search:
            # Return output with package name but no version data
            mock_search.return_value = (
                "# Name                    Version  Build         Channel\n"
                "# _______________________________________________________\n"
            )
            result = await adapter.get_latest_version("numpy")

        assert result is None


class TestTryAnacondaApi:
    """Tests for CondaAdapter._try_anaconda_api()."""

    @pytest.fixture
    def adapter(self) -> conda.CondaAdapter:
        return conda.CondaAdapter()

    @pytest.mark.asyncio
    async def test_returns_datetime_when_version_has_upload_time(self, adapter: conda.CondaAdapter) -> None:
        """Returns datetime when version found with upload_time."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "files": [
                    {"version": "1.0.0", "upload_time": "2024-01-15 10:00:00.000000+00:00"},
                    {"version": "1.0.0", "upload_time": "2024-01-15 10:00:00.000000+00:00"},
                ],
            }
            result = await adapter._try_anaconda_api("boltons", "1.0.0")
        assert result is not None
        assert result.isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_version_not_found(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when version not in files array."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "files": [
                    {"version": "2.0.0", "upload_time": "2024-01-15 10:00:00.000000+00:00"},
                ],
            }
            result = await adapter._try_anaconda_api("boltons", "1.0.0")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_files(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when files array is empty."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"files": []}
            result = await adapter._try_anaconda_api("boltons", "1.0.0")
        assert result is None

    @pytest.mark.asyncio
    async def test_api_error(self, adapter: conda.CondaAdapter) -> None:
        """Returns None when _fetch_json raises."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.side_effect = RuntimeError("API error")
            result = await adapter._try_anaconda_api("boltons", "1.0.0")
        assert result is None


class TestGetPublishTimeAnaconda:
    """Tests for CondaAdapter.get_publish_time with Anaconda API."""

    @pytest.fixture
    def adapter(self) -> conda.CondaAdapter:
        return conda.CondaAdapter()

    @pytest.mark.asyncio
    async def test_anaconda_api_primary_path(self, adapter: conda.CondaAdapter) -> None:
        """Returns (datetime, "registry_api") when Anaconda API succeeds."""
        from datetime import datetime

        with (
            patch.object(adapter, "_try_anaconda_api") as mock_api,
            patch("pkg_defender.registry.conda.resolve_timestamp") as mock_resolve,
        ):
            mock_api.return_value = datetime(2026, 3, 15)
            result = await adapter.get_publish_time("boltons", "1.0.0")

        assert result[0] is not None
        assert result[1] == "registry_api"
        mock_resolve.assert_not_called()

    @pytest.mark.asyncio
    async def test_anaconda_api_fallback_to_resolver(self, adapter: conda.CondaAdapter) -> None:
        """Falls through to resolve_timestamp when Anaconda API returns None."""
        from datetime import datetime

        with (
            patch.object(adapter, "_try_anaconda_api") as mock_api,
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2026, 3, 15),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            mock_api.return_value = None
            result = await adapter.get_publish_time("boltons", "1.0.0")

        assert result[0] is not None
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_anaconda_api_failure_fallback_to_user_manual(
        self,
        adapter: conda.CondaAdapter,
    ) -> None:
        """Returns (None, "user_manual") when both fail."""
        with (
            patch.object(adapter, "_try_anaconda_api") as mock_api,
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="user_manual",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            mock_api.return_value = None
            result = await adapter.get_publish_time("boltons", "1.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"


class TestGetAllVersionsAnaconda:
    """Tests for CondaAdapter.get_all_versions with Anaconda API."""

    @pytest.fixture
    def adapter(self) -> conda.CondaAdapter:
        return conda.CondaAdapter()

    @pytest.mark.asyncio
    async def test_anaconda_api_populates_publish_time(
        self,
        adapter: conda.CondaAdapter,
    ) -> None:
        """Publish_time populated from Anaconda API when available."""
        with (
            patch.object(adapter, "_fetch_json") as mock_fetch,
            patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search,
        ):
            mock_fetch.return_value = {
                "files": [
                    {"version": "1.26.4", "upload_time": "2024-03-01 12:00:00.000000+00:00"},
                    {"version": "1.24.3", "upload_time": "2023-06-15 08:30:00.000000+00:00"},
                ],
            }
            mock_search.return_value = (
                "# Name                    Version  Build         Channel\n"
                "numpy                     1.26.4   py312haa1c40_202  conda-forge\n"
                "numpy                     1.24.3   py311hcf9a2d4_103  conda-forge\n"
            )
            result = await adapter.get_all_versions("numpy")

        assert len(result) == 2
        assert result[0].version == "1.26.4"
        assert result[0].publish_time is not None
        assert result[0].publish_time.isoformat() == "2024-03-01T12:00:00+00:00"
        assert result[1].version == "1.24.3"
        assert result[1].publish_time is not None
        assert result[1].publish_time.isoformat() == "2023-06-15T08:30:00+00:00"

    @pytest.mark.asyncio
    async def test_anaconda_api_failure_returns_none_timestamps(
        self,
        adapter: conda.CondaAdapter,
    ) -> None:
        """Versions still returned with publish_time=None when Anaconda API fails."""
        with (
            patch.object(adapter, "_fetch_json") as mock_fetch,
            patch("pkg_defender.registry.conda._conda_search_with_retry") as mock_search,
        ):
            mock_fetch.side_effect = RuntimeError("API error")
            mock_search.return_value = (
                "# Name                    Version  Build         Channel\n"
                "numpy                     1.26.4   py312haa1c40_202  conda-forge\n"
            )
            result = await adapter.get_all_versions("numpy")

        assert len(result) == 1
        assert result[0].version == "1.26.4"
        assert result[0].publish_time is None


class TestRunCondaSearch:
    """Tests for _run_conda_search function."""

    @pytest.mark.asyncio
    async def test_run_conda_search_success(self) -> None:
        """Returns stdout on successful command."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        proc.communicate.return_value = (b"numpy                     1.26.4   py312haa1c40_202  conda-forge", b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc):
            result = await conda._run_conda_search("numpy")

        assert "numpy" in result

    @pytest.mark.asyncio
    async def test_run_conda_search_failure(self) -> None:
        """Raises CalledProcessError on failure."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 1
        proc.communicate.return_value = (b"", b"Package not found")
        with (
            patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc),
            pytest.raises(subprocess.CalledProcessError),
        ):
            await conda._run_conda_search("nonexistent")

    @pytest.mark.asyncio
    async def test_run_conda_search_with_info(self) -> None:
        """Appends --info flag when info=True (line 140)."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        proc.communicate.return_value = (b"some info output", b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            result = await conda._run_conda_search("numpy", info=True)

        assert "some info output" in result
        # Verify the --info flag was in the command
        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert "--info" in args


class TestCondaSearchWithRetry:
    """Tests for _conda_search_with_retry function."""

    @pytest.mark.asyncio
    async def test_search_with_retry_success(self) -> None:
        """Returns result on first success."""
        with patch("pkg_defender.registry.conda._run_conda_search") as mock_run:
            mock_run.return_value = "numpy 1.26.4"
            result = await conda._conda_search_with_retry("numpy")

        assert result == "numpy 1.26.4"

    @pytest.mark.asyncio
    async def test_search_with_retry_timeout_retries(self) -> None:
        """Retries on timeout and succeeds on second attempt."""
        with patch("pkg_defender.registry.conda._run_conda_search") as mock_run:
            mock_run.side_effect = [
                TimeoutError("timed out"),
                "numpy 1.26.4",
            ]
            result = await conda._conda_search_with_retry("numpy")

        assert result == "numpy 1.26.4"

    @pytest.mark.asyncio
    async def test_search_with_retry_all_fail(self) -> None:
        """Raises after all retries exhausted."""
        with patch("pkg_defender.registry.conda._run_conda_search") as mock_run:
            mock_run.side_effect = [
                TimeoutError("timed out"),
                TimeoutError("timed out"),
                TimeoutError("timed out"),
            ]
            with pytest.raises(TimeoutError):
                await conda._conda_search_with_retry("numpy")

    @pytest.mark.asyncio
    async def test_search_with_retry_non_transient_error(self) -> None:
        """Does not retry non-transient errors."""
        with patch("pkg_defender.registry.conda._run_conda_search") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["conda", "search"],
            )
            with pytest.raises(subprocess.CalledProcessError):
                await conda._conda_search_with_retry("nonexistent")


class TestParseSearchOutput:
    """Tests for _parse_search_output function."""

    def test_parse_search_output_basic(self) -> None:
        """Parses basic conda search output."""
        lines = [
            "# Name                    Version  Build         Channel",
            "# _______________________________________________________",
            "numpy                     1.26.4   py312haa1c40_202  conda-forge",
        ]
        result = conda._parse_search_output(lines)

        assert "numpy" in result
        assert len(result["numpy"]["versions"]) == 1
        assert result["numpy"]["versions"][0]["version"] == "1.26.4"
        assert result["numpy"]["versions"][0]["build"] == "py312haa1c40_202"

    def test_parse_search_output_multiple_versions(self) -> None:
        """Parses output with multiple versions."""
        lines = [
            "# Name                    Version  Build         Channel",
            "numpy                     1.26.4   py312haa1c40_202  conda-forge",
            "numpy                     1.24.3   py311hcf9a2d4_103  conda-forge",
        ]
        result = conda._parse_search_output(lines)

        assert len(result["numpy"]["versions"]) == 2

    def test_parse_search_output_skips_comments(self) -> None:
        """Skips comment lines."""
        lines = [
            "# This is a comment",
            "# Another comment",
            "numpy                     1.26.4   py312haa1c40_202  conda-forge",
        ]
        result = conda._parse_search_output(lines)

        assert "numpy" in result

    def test_parse_search_output_skips_empty_lines(self) -> None:
        """Skips empty lines."""
        lines = [
            "",
            "   ",
            "numpy                     1.26.4   py312haa1c40_202  conda-forge",
        ]
        result = conda._parse_search_output(lines)

        assert "numpy" in result

    def test_parse_search_output_short_line(self) -> None:
        """Skips lines with fewer than 3 parts (line 88)."""
        lines = [
            "# Name  Version  Build  Channel",
            "only_two_parts",
            "numpy                     1.26.4   py312haa1c40_202  conda-forge",
        ]
        result = conda._parse_search_output(lines)

        assert "numpy" in result
        assert "only_two_parts" not in result


class TestConstants:
    """Tests for module-level constants."""

    def test_timeout_seconds_constant(self) -> None:
        """TIMEOUT_SECONDS is set to 30."""
        assert conda.TIMEOUT_SECONDS == 30

    def test_max_retries_constant(self) -> None:
        """INTEL_FEED_MAX_RETRIES is set to 3."""
        assert INTEL_FEED_MAX_RETRIES == 3

    def test_default_channel_constant(self) -> None:
        """DEFAULT_CHANNEL is set to conda-forge."""
        assert conda.DEFAULT_CHANNEL == "conda-forge"


import subprocess  # noqa: E402


class TestCondaPublishTimeWarning:
    """Regression tests for Gap 6: Conda publish time warnings."""

    @pytest.fixture
    def mock_resolve_ts(self) -> AsyncMock:
        """Return a mock resolve_timestamp that returns (None, "user_manual")."""
        return AsyncMock(
            return_value=ResolutionResult(
                publish_time=None, source_label="user_manual", resolution_status="all_sources_failed", last_error=None
            )
        )

    @pytest.mark.asyncio
    async def test_conda_get_publish_time_warns(
        self, mock_resolve_ts: AsyncMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Regression: Conda get_publish_time must emit log warning when returning None."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache to ensure warning is emitted
        conda._warned_conda_packages.clear()

        adapter = conda.CondaAdapter()
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch("pkg_defender.registry.conda.resolve_timestamp", mock_resolve_ts),
        ):
            result = await adapter.get_publish_time("nonexistent-package-xyz-456", "1.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"
        assert any("Conda does not expose" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_conda_adapter_get_publish_time_warns(
        self, mock_resolve_ts: AsyncMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Regression: CondaAdapter.get_publish_time emits log warning when returning None."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache to ensure warning is emitted
        conda._warned_conda_packages.clear()

        adapter = conda.CondaAdapter()

        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch("pkg_defender.registry.conda.resolve_timestamp", mock_resolve_ts),
        ):
            result = await adapter.get_publish_time("test-package-abc", "2.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"
        assert any("Conda does not expose" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_conda_warning_only_emits_once_per_package(
        self, mock_resolve_ts: AsyncMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning should only be emitted once per package to avoid spam."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache
        conda._warned_conda_packages.clear()

        adapter = conda.CondaAdapter()
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch("pkg_defender.registry.conda.resolve_timestamp", mock_resolve_ts),
        ):
            for _ in range(3):
                await adapter.get_publish_time("same-package", "1.0.0")

        # Should only have one warning for the same package
        conda_warnings = [r for r in caplog.records if "Conda does not expose" in r.message]
        assert len(conda_warnings) == 1

    @pytest.mark.asyncio
    async def test_conda_warning_different_packages(
        self, mock_resolve_ts: AsyncMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warning should be emitted for different packages."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache
        conda._warned_conda_packages.clear()

        adapter = conda.CondaAdapter()
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch("pkg_defender.registry.conda.resolve_timestamp", mock_resolve_ts),
        ):
            await adapter.get_publish_time("package-a", "1.0.0")
            await adapter.get_publish_time("package-b", "1.0.0")

        # Should have two warnings for different packages
        conda_warnings = [r for r in caplog.records if "Conda does not expose" in r.message]
        assert len(conda_warnings) == 2


class TestCondaGetInstalledVersion:
    """Tests for conda_get_installed_version."""

    @pytest.mark.asyncio
    async def test_returns_version_when_package_installed(self) -> None:
        """Returns version when package is installed."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        proc.communicate.return_value = (b'[{"name": "python", "version": "3.12.0"}]', b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc):
            result = await conda.conda_get_installed_version("python")
        assert result == "3.12.0"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 1
        proc.communicate.return_value = (b"[]", b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc):
            result = await conda.conda_get_installed_version("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.conda.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("conda not found"),
        ):
            result = await conda.conda_get_installed_version("python")
        assert result is None

    @pytest.mark.asyncio
    async def test_version_not_found_in_line(self) -> None:
        """Returns version from first entry in JSON list."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        stdout = b'[{"name": "python", "version": "3.12.0"}, {"name": "python", "version": "3.11.0"}]'
        proc.communicate.return_value = (stdout, b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc):
            result = await conda.conda_get_installed_version("python")
        assert result == "3.12.0"

    @pytest.mark.asyncio
    async def test_json_parse_branch(self) -> None:
        """Returns None when JSON data is empty list."""
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        proc.communicate.return_value = (b"[]", b"")
        with patch("pkg_defender.registry.conda.asyncio.create_subprocess_exec", return_value=proc):
            result = await conda.conda_get_installed_version("nonexistent")
        assert result is None


class TestCondaResolverBehavior:
    """Tests for CondaAdapter delegating to TimestampResolver."""

    @pytest.mark.asyncio
    async def test_resolver_returns_github_release(self) -> None:
        """Returns datetime when resolver returns github_releases (fallback path)."""
        from datetime import datetime

        adapter = conda.CondaAdapter()
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2026, 1, 15, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            result = await adapter.get_publish_time("numpy", "1.26.4")

        assert result is not None
        assert result[0] is not None
        assert result[0].year == 2026
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_resolver_raises_exception(self) -> None:
        """Returns user_manual when resolver raises (fallback path)."""
        adapter = conda.CondaAdapter()
        with (
            patch.object(adapter, "_try_anaconda_api", new_callable=AsyncMock, return_value=None),
            patch(
                "pkg_defender.registry.conda.resolve_timestamp",
                new_callable=AsyncMock,
                side_effect=RuntimeError("API error"),
            ),
        ):
            result = await adapter.get_publish_time("numpy", "1.26.4")

        assert result[0] is None
        assert result[1] == "user_manual"


class TestCondaSearchWithRetryConsolidated:
    """Tests for _conda_search_with_retry (consolidated duplicate)."""

    @pytest.mark.asyncio
    async def test_first_attempt_succeeds(self) -> None:
        """Returns stdout on first attempt."""
        from pkg_defender.registry.conda import _conda_search_with_retry

        with patch("pkg_defender.registry.conda._run_conda_search", new=AsyncMock(return_value="search result")):
            result = await _conda_search_with_retry("python")
        assert result == "search result"

    @pytest.mark.asyncio
    async def test_retry_on_failure(self) -> None:
        """Retries on first failure, succeeds on second attempt."""
        from pkg_defender.registry.conda import _conda_search_with_retry

        with patch(
            "pkg_defender.registry.conda._run_conda_search",
            new=AsyncMock(
                side_effect=[
                    FileNotFoundError("conda not found"),
                    "search result",
                ]
            ),
        ):
            result = await _conda_search_with_retry("python")
        assert result == "search result"

    @pytest.mark.asyncio
    async def test_all_attempts_fail(self) -> None:
        """Raises when all attempts fail."""
        from pkg_defender.registry.conda import _conda_search_with_retry

        with (
            patch(
                "pkg_defender.registry.conda._run_conda_search",
                new=AsyncMock(side_effect=FileNotFoundError("conda not found")),
            ),
            pytest.raises(FileNotFoundError),
        ):
            await _conda_search_with_retry("python")

    @pytest.mark.asyncio
    async def test_no_retries_fallthrough(self) -> None:
        """Raises RuntimeError when max_retries=0 (fallthrough lines 198-199)."""
        from pkg_defender.registry.conda import _conda_search_with_retry

        with (
            patch("pkg_defender.registry.conda.get_max_retries", return_value=0),
            patch("pkg_defender.registry.conda._run_conda_search", new=AsyncMock()),
            pytest.raises(RuntimeError, match="unreachable"),
        ):
            await _conda_search_with_retry("python")
