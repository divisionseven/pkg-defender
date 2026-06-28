"""Tests for intel npm_advisory module.

Tests the NpmAdvisoryFeed class and related functions.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from pkg_defender.intel import npm_advisory
from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.npm_advisory import (
    NpmAdvisoryFeed,
)


class TestNpmAdvisoryFeedInit:
    """Tests for NpmAdvisoryFeed initialization."""

    async def test_init_creates_instance(self) -> None:
        """Test that NpmAdvisoryFeed is created successfully."""
        feed = NpmAdvisoryFeed()

        assert isinstance(feed, NpmAdvisoryFeed)
        assert feed.name == "npm_advisory"


class TestName:
    """Tests for NpmAdvisoryFeed.name property."""

    async def test_name_returns_npm_advisory(self) -> None:
        """Test that name returns 'npm_advisory'."""
        feed = NpmAdvisoryFeed()

        assert feed.name == "npm_advisory"


class TestSupportsIncremental:
    """Tests for NpmAdvisoryFeed.supports_incremental property."""

    async def test_supports_incremental_returns_true(self) -> None:
        """Test that supports_incremental returns True."""
        feed = NpmAdvisoryFeed()

        assert feed.supports_incremental is True


class TestIsConfigured:
    """Tests for NpmAdvisoryFeed.is_configured()."""

    async def test_is_configured_enabled(self) -> None:
        """Test that is_configured returns True when enabled."""
        feed = NpmAdvisoryFeed()
        mock_config = MagicMock()
        mock_config.feeds.npm_advisory_enabled = True

        assert feed.is_configured(mock_config) is True

    async def test_is_configured_disabled(self) -> None:
        """Test that is_configured returns False when disabled."""
        feed = NpmAdvisoryFeed()
        mock_config = MagicMock()
        mock_config.feeds.npm_advisory_enabled = False

        assert feed.is_configured(mock_config) is False


class TestFetch:
    """Tests for NpmAdvisoryFeed.fetch()."""

    async def test_fetch_with_mock_npm(self) -> None:
        """Test that fetch returns ThreatRecords from npm audit JSON."""
        feed = NpmAdvisoryFeed()
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(
                b'{"vulnerabilities": {"express": {"severity": "high", "via": [{"title": "Test Advisory"}]}}}',
                b"",
            )
        )

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            result = await feed.fetch()

        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].package_name == "express"

    async def test_fetch_npm_not_found(self) -> None:
        """Test that fetch handles missing npm gracefully."""
        feed = NpmAdvisoryFeed()

        # Mock subprocess to raise FileNotFoundError
        async def mock_create_subprocess(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("npm not found")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess):
            result = await feed.fetch()

        assert result == FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)


class TestCheckPackage:
    """Tests for NpmAdvisoryFeed.check_package()."""

    async def test_check_package_returns_empty(self) -> None:
        """Test that check_package returns empty result for individual package queries."""
        feed = NpmAdvisoryFeed()

        result = await feed.check_package("express", "4.17.1", "npm")

        assert result == FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)


class TestModuleFunctions:
    """Tests for module-level functions."""

    async def test_has_npm_advisory_feed_class(self) -> None:
        """Test that module exposes NpmAdvisoryFeed."""
        assert hasattr(npm_advisory, "NpmAdvisoryFeed")
        assert callable(NpmAdvisoryFeed)

    async def test_has_fetch_feed(self) -> None:
        """Test that module exposes fetch method on NpmAdvisoryFeed."""
        assert hasattr(npm_advisory.NpmAdvisoryFeed, "fetch")
        assert callable(npm_advisory.NpmAdvisoryFeed.fetch)


class TestFetchTimeout:
    """Tests for NpmAdvisoryFeed.fetch() timeout handling."""

    async def test_fetch_timeout_kills_process(self) -> None:
        """Test that a hanging npm audit process is killed on timeout."""
        feed = NpmAdvisoryFeed()
        mock_process = MagicMock()
        mock_process.returncode = None  # Still running
        mock_process.communicate = AsyncMock(side_effect=TimeoutError)
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            result = await feed.fetch()

        assert result.status == FetchStatus.FAILED
        assert result.records == []
        mock_process.kill.assert_called_once()
        mock_process.wait.assert_called_once()

    async def test_fetch_timeout_does_not_kill_exited_process(self) -> None:
        """Test that an already-exited process is not killed on timeout."""
        feed = NpmAdvisoryFeed()
        mock_process = MagicMock()
        mock_process.returncode = 1  # Already exited
        mock_process.communicate = AsyncMock(side_effect=TimeoutError)
        mock_process.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            result = await feed.fetch()

        assert result.status == FetchStatus.FAILED
        mock_process.kill.assert_not_called()
