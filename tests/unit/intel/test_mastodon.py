"""Tests for intel mastodon module.

Tests the MastodonFeed class and related functions.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.intel import mastodon
from pkg_defender.intel.base import FeedFetchResult
from pkg_defender.intel.mastodon import MastodonFeed


class TestMastodonFeedInit:
    """Tests for MastodonFeed initialization."""

    def test_init_creates_instance(self) -> None:
        """Test that MastodonFeed is created successfully."""
        feed = MastodonFeed()

        assert isinstance(feed, MastodonFeed)
        assert feed.name == "mastodon"


class TestName:
    """Tests for MastodonFeed.name property."""

    def test_name_returns_mastodon(self) -> None:
        """Test that name returns 'mastodon'."""
        feed = MastodonFeed()

        assert feed.name == "mastodon"


class TestSupportsIncremental:
    """Tests for MastodonFeed.supports_incremental property."""

    def test_supports_incremental_returns_true(self) -> None:
        """Test that supports_incremental returns True."""
        feed = MastodonFeed()

        assert feed.supports_incremental is True


class TestIsConfigured:
    """Tests for MastodonFeed.is_configured()."""

    def test_is_configured_enabled(self) -> None:
        """Test that is_configured returns True when enabled."""
        feed = MastodonFeed()
        mock_config = MagicMock()
        mock_config.feeds.mastodon_enabled = True
        mock_config.feeds.mastodon_client_id = "test_id"
        mock_config.feeds.mastodon_client_secret = "test_secret"

        assert feed.is_configured(mock_config) is True

    def test_is_configured_disabled(self) -> None:
        """Test that is_configured returns False when disabled."""
        feed = MastodonFeed()
        mock_config = MagicMock()
        mock_config.feeds.mastodon_enabled = False

        assert feed.is_configured(mock_config) is False

    def test_is_configured_no_credentials(self) -> None:
        """Test that is_configured returns True when enabled (only checks enabled flag)."""
        feed = MastodonFeed()
        mock_config = MagicMock()
        mock_config.feeds.mastodon_enabled = True
        mock_config.feeds.mastodon_client_id = None
        mock_config.feeds.mastodon_client_secret = "test_secret"

        assert feed.is_configured(mock_config) is True


class TestGetTimeout:
    """Tests for get_http_timeout()."""

    def test_get_timeout_with_none(self) -> None:
        """Test that get_http_timeout returns fallback when no config."""
        from pkg_defender.config.settings import get_http_timeout

        result = get_http_timeout(None)

        assert isinstance(result, int)
        assert result > 0

    def test_get_timeout_with_config(self) -> None:
        """Test that get_http_timeout returns the configured value."""
        from pkg_defender.config.settings import get_http_timeout

        mock_config = MagicMock()
        mock_config.feeds.http_timeout = 30

        result = get_http_timeout(mock_config)

        assert result == 30


class TestFetch:
    """Tests for MastodonFeed.fetch()."""

    @pytest.mark.asyncio
    async def test_fetch_with_mock(self) -> None:
        """Test that fetch returns a FeedFetchResult."""
        feed = MastodonFeed()
        mock_session = AsyncMock()

        # Mock the _mastodon_get to return empty data
        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await feed.fetch(session=mock_session)

        assert isinstance(result, FeedFetchResult)


class TestCheckPackage:
    """Tests for MastodonFeed.check_package()."""

    def test_check_package_returns_empty(self) -> None:
        """Test that check_package returns empty records for individual package queries."""
        feed = MastodonFeed()

        result = asyncio.run(feed.check_package("requests", "2.28.0", "pypi"))

        assert result.records == []


class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_has_mastodon_feed(self) -> None:
        """Test that module exposes MastodonFeed."""
        assert hasattr(mastodon, "MastodonFeed")
        assert callable(MastodonFeed)
