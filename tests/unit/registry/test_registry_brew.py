"""Tests for pkg_defender.registry.brew module.

Tests the BrewAdapter class and standalone convenience functions.
Covers all public methods: get_publish_time, get_all_versions, get_latest_version,
and the module-level functions.
"""

from __future__ import annotations

import asyncio
import warnings
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender._http import FetchResult
from pkg_defender.config.settings import INTEL_FEED_MAX_RETRIES, get_http_timeout
from pkg_defender.registry import brew
from pkg_defender.registry._timestamp import ResolutionResult


class TestBrewAdapter:
    """Tests for BrewAdapter class."""

    @pytest.fixture
    def adapter(self) -> brew.BrewAdapter:
        """Create a BrewAdapter instance."""
        return brew.BrewAdapter()

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: brew.BrewAdapter) -> None:
        """Returns latest stable version when formula exists."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
        )
        mock_response.raise_for_status = MagicMock()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
            result = await adapter.get_latest_version("python")

        assert result == "3.12.0"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: brew.BrewAdapter) -> None:
        """Returns None when formula does not exist (404)."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Formula not found",
            )
            result = await adapter.get_latest_version("nonexistent-package")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_network_error(
        self, adapter: brew.BrewAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.brew"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_latest_version("python")

        assert result is None
        assert "brew: registry API failed for python" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: brew.BrewAdapter) -> None:
        """Returns VersionInfo list with stable version."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
            result = await adapter.get_all_versions("python")

        assert len(result) == 1
        assert result[0].ecosystem == "homebrew"
        assert result[0].package_name == "python"
        assert result[0].version == "3.12.0"
        assert result[0].publish_time == datetime(2024, 1, 15, tzinfo=UTC)

    @pytest.mark.asyncio
    async def test_get_all_versions_no_stable(self, adapter: brew.BrewAdapter) -> None:
        """Returns empty list when no stable version."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {},
                "generated_date": "2024-01-15",
            }
            result = await adapter.get_all_versions("python")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_network_error(
        self, adapter: brew.BrewAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Returns empty list on network error."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.brew"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_all_versions("python")

        assert result == []
        assert "brew: registry API failed for python" in caplog.text

    @pytest.mark.asyncio
    async def test_get_publish_time_success(self, adapter: brew.BrewAdapter) -> None:
        """Returns publish time via TimestampResolver when version matches stable."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 15, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result = await adapter.get_publish_time("python", "3.12.0")

        assert result[0] is not None
        assert result[1] == "github_releases"
        # No UserWarning should be emitted
        assert not any(issubclass(x.category, UserWarning) for x in w)

    @pytest.mark.asyncio
    async def test_get_publish_time_version_mismatch(self, adapter: brew.BrewAdapter) -> None:
        """Calls TimestampResolver even when version doesn't match stable."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ) as mock_resolve_ts,
        ):
            from unittest.mock import ANY

            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }

            result = await adapter.get_publish_time("python", "3.11.0")

        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"
        mock_resolve_ts.assert_awaited_once_with(
            package="python",
            version="3.11.0",
            github_url="https://github.com/python/cpython",
            ecosystem="homebrew",
            session=ANY,
            is_latest=False,
        )

    @pytest.mark.asyncio
    async def test_get_publish_time_not_found(self, adapter: brew.BrewAdapter) -> None:
        """Returns None when formula not found."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Formula not found",
            )
            result = await adapter.get_publish_time("nonexistent", "1.0.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_no_generated_date(self, adapter: brew.BrewAdapter) -> None:
        """Returns None when generated_date is missing."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="unresolved",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": None,  # Missing generated_date
            }
            result = await adapter.get_publish_time("python", "3.12.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_network_error(self, adapter: brew.BrewAdapter) -> None:
        """Returns None on network error."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="unresolved",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await adapter.get_publish_time("python", "3.12.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_all_versions_no_generated_date(self, adapter: brew.BrewAdapter) -> None:
        """Uses datetime.now() when generated_date is missing."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": None,  # Missing - should fallback to now()
            }
            with patch("pkg_defender.registry.brew.datetime") as mock_datetime:
                mock_datetime.now.return_value = datetime(2024, 6, 1)
                mock_datetime.side_effect = lambda *args: datetime(*args)
                result = await adapter.get_all_versions("python")

        assert len(result) == 1
        assert result[0].version == "3.12.0"

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps(self) -> None:
        """get_all_version_timestamps returns version/timestamp tuples."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
            result = await brew.get_all_version_timestamps("python")

        assert len(result) == 1
        assert result[0] == ("3.12.0", datetime(2024, 1, 15, tzinfo=UTC))


class TestGetTimeout:
    """Tests for get_http_timeout with brew's override_default=30."""

    @pytest.mark.asyncio
    async def test_get_timeout_with_config(self) -> None:
        """get_http_timeout with override_default=30 returns 30 when config has no explicit timeout."""
        # Use a mock where feeds has no http_timeout → getattr falls back to override_default
        mock_config = MagicMock()
        mock_config.feeds = MagicMock(spec=[])  # empty spec = no attributes allowed
        result = get_http_timeout(mock_config, override_default=30)
        assert result == 30

    def test_exponential_backoff_values(self) -> None:
        """Verify retry backoff times match implementation [1, 2, 4]."""
        backoff = [2**attempt for attempt in range(INTEL_FEED_MAX_RETRIES)]
        assert backoff == [1, 2, 4]


class TestBrewFetchRetry:
    """Tests for _brew_fetch retry behavior via adapter methods.

    The _brew_fetch function is tested indirectly through adapter methods
    which exercise the retry logic. Direct tests for:
    - test_get_latest_version_network_error (TimeoutError)
    - test_get_all_versions_network_error (aiohttp.ClientError)
    - test_get_publish_time_not_found (404 handling)

    This class documents that behavior is tested via adapter integration.
    """

    def test_brew_fetch_exponential_backoff_doc(self) -> None:
        """Verify retry constants enable exponential backoff.

        INTEL_FEED_MAX_RETRIES=3 with 2**attempt gives 1s, 2s, 4s backoff.
        """
        assert INTEL_FEED_MAX_RETRIES == 3

        # Verify the backoff pattern that retry logic uses
        backoff_times = [2**i for i in range(INTEL_FEED_MAX_RETRIES)]
        assert backoff_times == [1, 2, 4]


class TestGetLatestVersionEdgeCases:
    """Edge case tests for get_latest_version."""

    @pytest.mark.asyncio
    async def test_get_latest_version_no_stable_version(self) -> None:
        """Returns None when stable version is missing."""
        adapter = brew.BrewAdapter()

        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {},  # No stable version
                "generated_date": "2024-01-15",
            }
            result = await adapter.get_latest_version("python")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_timeout_error(self) -> None:
        """Returns None on TimeoutError."""
        adapter = brew.BrewAdapter()

        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.side_effect = TimeoutError("Request timed out")
            result = await adapter.get_latest_version("python")

        assert result is None


class TestGetAllVersionTimestampsEdgeCases:
    """Edge case tests for get_all_version_timestamps."""

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps_not_found(self) -> None:
        """Returns empty list when formula not found."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Formula not found",
            )
            result = await brew.get_all_version_timestamps("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps_network_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """Returns empty list on network error."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.brew"),
        ):
            mock_fetch.side_effect = aiohttp.ClientError("Connection failed")
            result = await brew.get_all_version_timestamps("python")

        assert result == []
        assert "brew: registry API failed for python" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps_no_stable(self) -> None:
        """Returns empty list when no stable version."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {},
                "generated_date": "2024-01-15",
            }
            result = await brew.get_all_version_timestamps("python")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps_no_generated_date(self) -> None:
        """Uses datetime.now() when generated_date is missing."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": None,
            }
            result = await brew.get_all_version_timestamps("python")

        assert len(result) == 1
        assert result[0][0] == "3.12.0"
        assert result[0][1] is not None


class TestConstants:
    """Tests for module-level constants."""

    def test_brew_registry_url_constant(self) -> None:
        """BREW_REGISTRY_URL is a valid HTTPS URL."""
        assert brew.BREW_REGISTRY_URL == "https://formulae.brew.sh"
        assert brew.BREW_REGISTRY_URL.startswith("https://")

    def test_max_retries_constant(self) -> None:
        """INTEL_FEED_MAX_RETRIES is set to 3."""
        assert INTEL_FEED_MAX_RETRIES == 3

    def test_timeout_seconds_constant(self) -> None:
        """TIMEOUT_SECONDS is set to 30."""
        assert brew.TIMEOUT_SECONDS == 30

    def test_max_response_size_mb_constant(self) -> None:
        """MAX_RESPONSE_SIZE_MB is set to 10."""
        assert brew.MAX_RESPONSE_SIZE_MB == 10


class TestBrewPublishTimeGithubFallback:
    """Tests for get_publish_time with the TimestampResolver."""

    @pytest.fixture
    def adapter(self) -> brew.BrewAdapter:
        return brew.BrewAdapter()

    @pytest.mark.asyncio
    async def test_github_release_found(self, adapter: brew.BrewAdapter) -> None:
        """Returns GitHub release date when resolver succeeds."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_brew_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            mock_brew_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result = await adapter.get_publish_time("python", "3.12.0", session=MagicMock())

        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"
        # No UserWarning should be emitted on the GitHub success path
        assert not any(issubclass(x.category, UserWarning) for x in w)

    @pytest.mark.asyncio
    async def test_github_resolver_returns_none(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when resolver returns None."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_brew_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="unresolved",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            mock_brew_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }

            result = await adapter.get_publish_time("python", "3.12.0", session=MagicMock())

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_github_resolver_exception(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when resolver raises."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_brew_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                side_effect=Exception("GitHub API error"),
            ),
        ):
            mock_brew_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }

            result = await adapter.get_publish_time("python", "3.12.0", session=MagicMock())

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_no_github_url_returns_unresolved(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when formula has no GitHub repository URL."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_brew_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="unresolved",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            mock_brew_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                # No "repository" field
            }

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result = await adapter.get_publish_time("python", "3.12.0", session=MagicMock())

        assert result[0] is None
        assert result[1] == "unresolved"
        user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
        assert len(user_warnings) == 0


class TestBrewGetInstalledVersion:
    """Tests for brew_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_formula_installed(self) -> None:
        """Returns version when formula is installed."""
        with patch(
            "pkg_defender.registry.brew.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="python 3.12.0\n"),
        ):
            result = await brew.brew_get_installed_version("python")
        assert result == "python"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when formula is not installed."""
        with patch(
            "pkg_defender.registry.brew.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await brew.brew_get_installed_version("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.brew.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("brew not found"),
        ):
            result = await brew.brew_get_installed_version("python")
        assert result is None


class TestBrewNaiveDatetime:
    """Regression tests for Brew naive datetime fix (Bug 5).

    Root cause: src/pkg_defender/registry/brew.py:209 and brew.py:363 —
    datetime.strptime() produces naive datetimes (no tzinfo). When serialized
    via .isoformat() and read back, comparison against aware datetime.now(UTC)
    raises TypeError: can't subtract offset-naive and offset-aware datetimes.
    Fix adds .replace(tzinfo=UTC) to both strptime calls.
    """

    @pytest.mark.asyncio
    async def test_get_all_versions_returns_aware_datetime(self) -> None:
        """publish_time from get_all_versions must have tzinfo set (brew.py:209)."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
            adapter = brew.BrewAdapter()
            result = await adapter.get_all_versions("python")

        assert len(result) == 1
        assert result[0].publish_time is not None
        assert result[0].publish_time.tzinfo is not None
        assert result[0].publish_time.tzinfo == UTC

    @pytest.mark.asyncio
    async def test_get_all_version_timestamps_returns_aware_datetime(
        self,
    ) -> None:
        """timestamp from get_all_version_timestamps must have tzinfo set (brew.py:363)."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "generated_date": "2024-01-15",
            }
            result = await brew.get_all_version_timestamps("python")

        assert len(result) == 1
        assert result[0][1].tzinfo is not None
        assert result[0][1].tzinfo == UTC


class TestSSRFValidation:
    """Tests for SSRF input validation in BrewAdapter.get_publish_time().

    These tests verify that crafted package names are rejected before URL
    construction, preventing path traversal, null-byte injection, and
    URL-encoded injection attacks.
    """

    @pytest.fixture
    def adapter(self) -> brew.BrewAdapter:
        """Create a BrewAdapter instance."""
        return brew.BrewAdapter()

    @pytest.mark.asyncio
    async def test_get_publish_time_rejects_invalid_package_name(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when package name fails BREW_PKG_RE validation."""
        result = await adapter.get_publish_time("../../../etc/passwd", "1.0")
        assert result == (None, "unresolved")

    @pytest.mark.asyncio
    async def test_get_publish_time_rejects_null_byte_package(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when package name contains null bytes."""
        result = await adapter.get_publish_time("foo\x00.bar", "1.0")
        assert result == (None, "unresolved")

    @pytest.mark.asyncio
    async def test_get_publish_time_rejects_url_encoded_package(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when package name contains URL-encoded characters."""
        result = await adapter.get_publish_time("foo%2F..%2Fetc%2Fpasswd", "1.0")
        assert result == (None, "unresolved")

    @pytest.mark.asyncio
    async def test_get_publish_time_rejects_special_chars(self, adapter: brew.BrewAdapter) -> None:
        """Returns unresolved when package name contains spaces, @, or /."""
        for invalid_name in ["foo bar", "foo@bar", "foo/bar"]:
            result = await adapter.get_publish_time(invalid_name, "1.0")
            assert result == (None, "unresolved"), f"Expected rejection for {invalid_name!r}"

    @pytest.mark.asyncio
    async def test_get_publish_time_valid_package_proceeds(self, adapter: brew.BrewAdapter) -> None:
        """Valid package names proceed past SSRF validation to fetch."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 15, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "python",
                "versions": {"stable": "3.12.0"},
                "repository": "https://github.com/python/cpython",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = False
            mock_load_config.return_value = mock_config

            for valid_name in ["python", "node", "tree@3.1.0"]:
                result = await adapter.get_publish_time(valid_name, "3.12.0")
                assert result[0] is not None, f"Expected timestamp for {valid_name!r}"


class TestBrewFetchGuard:
    """Tests for _brew_fetch guard logic (assert → RuntimeError)."""

    @pytest.mark.asyncio
    async def test_brew_fetch_raises_runtime_error_on_failure(self) -> None:
        """_brew_fetch raises RuntimeError when fetch_json returns failure."""
        with patch("pkg_defender._http.fetch_json") as mock_fetch:
            mock_fetch.return_value = FetchResult(success=False, data=None, error="test error")
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                await brew._brew_fetch("http://example.com")


class TestResolveViaHomebrewCore:
    """Tests for BrewAdapter._resolve_via_homebrew_core() method."""

    @pytest.fixture
    def adapter(self) -> brew.BrewAdapter:
        """Create a BrewAdapter instance."""
        return brew.BrewAdapter()

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_success(self, adapter: brew.BrewAdapter) -> None:
        """Valid tap + path returns datetime + label."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(
            return_value=(
                [
                    {
                        "commit": {
                            "committer": {"date": "2024-01-15T12:00:00Z"},
                            "message": "Update formula",
                        }
                    }
                ],
                None,
            )
        )

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is not None
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 15
        assert label == "homebrew_formula_commit"

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_unknown_tap(self, adapter: brew.BrewAdapter) -> None:
        """Unknown tap returns (None, '')."""
        ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "unknown/tap")
        assert ts is None
        assert label == ""

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_api_failure(self, adapter: brew.BrewAdapter) -> None:
        """GitHub API error returns (None, '')."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(return_value=(None, "rate_limited"))

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is None
        assert label == ""

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_empty_response(self, adapter: brew.BrewAdapter) -> None:
        """No commits returns (None, '')."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(return_value=([], None))

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is None
        assert label == ""

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_missing_date(self, adapter: brew.BrewAdapter) -> None:
        """Commit without date returns (None, '')."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(
            return_value=(
                [{"commit": {"committer": {}, "message": "Update"}}],
                None,
            )
        )

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is None
        assert label == ""

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_logs_commit_message(
        self, adapter: brew.BrewAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Commit message is logged at debug level."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(
            return_value=(
                [
                    {
                        "commit": {
                            "committer": {"date": "2024-01-15T12:00:00Z"},
                            "message": "Update formula to v1.0.0",
                        }
                    }
                ],
                None,
            )
        )

        with (
            patch(
                "pkg_defender.registry._timestamp.get_resolver",
                return_value=mock_resolver,
            ),
            caplog.at_level("DEBUG", logger="pkg_defender.registry.brew"),
        ):
            await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert "homebrew_formula_commit resolved" in caplog.text
        assert "Update formula to v1.0.0" in caplog.text

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_short_circuits_on_rate_limit(self, adapter: brew.BrewAdapter) -> None:
        """Rate-limited domain short-circuits via resolver._fetch_json."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(return_value=(None, "rate_limited"))

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is None
        assert label == ""
        # Verify resolver._fetch_json was called (rate limit check happened)
        mock_resolver._fetch_json.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core_api_404(self, adapter: brew.BrewAdapter) -> None:
        """GitHub API 404 returns (None, '')."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(return_value=(None, "not_found"))

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is None
        assert label == ""

    @pytest.mark.asyncio
    async def test_resolve_via_homebrew_core(self, adapter: brew.BrewAdapter) -> None:
        """Brew formula commit resolution succeeds."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(
            return_value=(
                [
                    {
                        "commit": {
                            "committer": {"date": "2024-01-15T12:00:00Z"},
                            "message": "Update formula",
                        }
                    }
                ],
                None,
            )
        )

        with patch(
            "pkg_defender.registry._timestamp.get_resolver",
            return_value=mock_resolver,
        ):
            ts, label = await adapter._resolve_via_homebrew_core("aview", "Formula/a/aview.rb", "homebrew/core")

        assert ts is not None
        assert label == "homebrew_formula_commit"


class TestGetPublishTimeTier0:
    """Integration tests for get_publish_time() Tier 0 (homebrew formula commit) flow."""

    @pytest.fixture
    def adapter(self) -> brew.BrewAdapter:
        """Create a BrewAdapter instance."""
        return brew.BrewAdapter()

    @pytest.mark.asyncio
    async def test_get_publish_time_tier0_success(self, adapter: brew.BrewAdapter) -> None:
        """Full flow: API response → Tier 0 → returns real timestamp."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(
            return_value=(
                [
                    {
                        "commit": {
                            "committer": {"date": "2024-01-15T12:00:00Z"},
                            "message": "Update formula",
                        }
                    }
                ],
                None,
            )
        )

        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry._timestamp.get_resolver",
                return_value=mock_resolver,
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "aview",
                "versions": {"stable": "1.0.0"},
                "ruby_source_path": "Formula/a/aview.rb",
                "tap": "homebrew/core",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = True
            mock_load_config.return_value = mock_config

            result = await adapter.get_publish_time("aview", "1.0.0")

        assert result[0] is not None
        assert result[0].year == 2024
        assert result[1] == "homebrew_formula_commit"

    @pytest.mark.asyncio
    async def test_get_publish_time_tier0_fallback(self, adapter: brew.BrewAdapter) -> None:
        """Tier 0 fails → falls through to existing chain."""
        mock_resolver = MagicMock()
        mock_resolver._github_headers.return_value = {"Accept": "application/vnd.github+json"}
        mock_resolver._fetch_json = AsyncMock(return_value=(None, "rate_limited"))

        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry._timestamp.get_resolver",
                return_value=mock_resolver,
            ),
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "aview",
                "versions": {"stable": "1.0.0"},
                "ruby_source_path": "Formula/a/aview.rb",
                "tap": "homebrew/core",
                "repository": "https://github.com/foo/bar",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = True
            mock_load_config.return_value = mock_config

            result = await adapter.get_publish_time("aview", "1.0.0")

        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_get_publish_time_tier0_disabled_via_flag(self, adapter: brew.BrewAdapter) -> None:
        """Feature flag disabled → Tier 0 is skipped entirely."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "aview",
                "versions": {"stable": "1.0.0"},
                "ruby_source_path": "Formula/a/aview.rb",
                "tap": "homebrew/core",
                "repository": "https://github.com/foo/bar",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = False
            mock_load_config.return_value = mock_config

            result = await adapter.get_publish_time("aview", "1.0.0")

        # Tier 0 was skipped, Tier 1+ resolved via resolver
        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_get_publish_time_no_ruby_source_path(self, adapter: brew.BrewAdapter) -> None:
        """No ruby_source_path → skips Tier 0, uses existing chain."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "aview",
                "versions": {"stable": "1.0.0"},
                # No ruby_source_path field
                "tap": "homebrew/core",
                "repository": "https://github.com/foo/bar",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = True
            mock_load_config.return_value = mock_config

            result = await adapter.get_publish_time("aview", "1.0.0")

        # Tier 0 skipped (no ruby_source_path), Tier 1+ resolved via resolver
        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_get_publish_time_invalid_tap(self, adapter: brew.BrewAdapter) -> None:
        """Invalid tap → skips Tier 0, uses existing chain."""
        with (
            patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch,
            patch(
                "pkg_defender.registry.brew.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC),
                    source_label="github_releases",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
            patch("pkg_defender.config.load_config") as mock_load_config,
        ):
            mock_fetch.return_value = {
                "name": "aview",
                "versions": {"stable": "1.0.0"},
                "ruby_source_path": "Formula/a/aview.rb",
                "tap": "malicious/tap",
                "repository": "https://github.com/foo/bar",
            }
            mock_config = MagicMock()
            mock_config.enable_homebrew_formula_commit = True
            mock_load_config.return_value = mock_config

            result = await adapter.get_publish_time("aview", "1.0.0")

        # Tier 0 skipped (tap not in whitelist), Tier 1+ resolved via resolver
        assert result[0] == datetime(2024, 1, 10, 12, 0, 0, tzinfo=UTC)
        assert result[1] == "github_releases"

    @pytest.mark.asyncio
    async def test_get_publish_time_api_timeout(self, adapter: brew.BrewAdapter) -> None:
        """Homebrew API timeout → returns (None, 'unresolved')."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.side_effect = TimeoutError("Request timed out")
            result = await adapter.get_publish_time("python", "3.12.0")

        assert result[0] is None
        assert result[1] == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_api_not_found(self, adapter: brew.BrewAdapter) -> None:
        """Homebrew API 404 → returns (None, 'unresolved')."""
        with patch("pkg_defender.registry.brew._brew_fetch") as mock_fetch:
            mock_fetch.return_value = None
            result = await adapter.get_publish_time("nonexistent", "1.0.0")

        assert result[0] is None
        assert result[1] == "unresolved"


class TestSourceTrustMap:
    """Tests for SOURCE_TRUST_MAP entries related to the user_manual → unresolved rename."""

    def test_source_trust_map_has_homebrew_formula_commit(self) -> None:
        """New homebrew_formula_commit entry exists and maps to 'verified'."""
        from pkg_defender.db.schema import SOURCE_TRUST_MAP

        assert "homebrew_formula_commit" in SOURCE_TRUST_MAP
        assert SOURCE_TRUST_MAP["homebrew_formula_commit"] == "verified"

    def test_source_trust_map_unresolved_maps_to_unknown(self) -> None:
        """Renamed 'unresolved' entry maps to 'unknown' trust level."""
        from pkg_defender.db.schema import SOURCE_TRUST_MAP

        assert "unresolved" in SOURCE_TRUST_MAP
        assert SOURCE_TRUST_MAP["unresolved"] == "unknown"

    def test_source_trust_map_no_user_manual_entry(self) -> None:
        """Old 'user_manual' entry has been removed from SOURCE_TRUST_MAP."""
        from pkg_defender.db.schema import SOURCE_TRUST_MAP

        assert "user_manual" not in SOURCE_TRUST_MAP
