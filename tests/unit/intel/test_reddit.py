"""Tests for intel reddit module.

Tests the RedditFeed class and related functions.
"""

from unittest.mock import MagicMock, patch

from pkg_defender.intel import reddit
from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.reddit import (
    BASE_CONFIDENCE,
    RedditFeed,
    _compute_engagement_confidence,
    _post_to_threat_records,
)


class TestRedditFeedInit:
    """Tests for RedditFeed initialization."""

    async def test_init_creates_instance(self) -> None:
        """Test that RedditFeed is created successfully."""
        feed = RedditFeed()

        assert isinstance(feed, RedditFeed)
        assert feed.name == "reddit"


class TestName:
    """Tests for RedditFeed.name property."""

    async def test_name_returns_reddit(self) -> None:
        """Test that name returns 'reddit'."""
        feed = RedditFeed()

        assert feed.name == "reddit"


class TestSupportsIncremental:
    """Tests for RedditFeed.supports_incremental property."""

    async def test_supports_incremental_returns_true(self) -> None:
        """Test that supports_incremental returns True."""
        feed = RedditFeed()

        assert feed.supports_incremental is True


class TestIsConfigured:
    """Tests for RedditFeed.is_configured()."""

    async def test_is_configured_with_credentials(self) -> None:
        """Test that is_configured returns True when credentials are provided."""
        feed = RedditFeed()
        mock_config = MagicMock()
        mock_config.feeds.reddit_enabled = True
        mock_config.feeds.reddit_client_id = "test_id"
        mock_config.feeds.reddit_client_secret = "test_secret"

        assert feed.is_configured(mock_config) is True

    async def test_is_configured_disabled(self) -> None:
        """Test that is_configured returns False when disabled."""
        feed = RedditFeed()
        mock_config = MagicMock()
        mock_config.feeds.reddit_enabled = False

        assert feed.is_configured(mock_config) is False

    async def test_is_configured_no_credentials(self) -> None:
        """Test that is_configured returns False when credentials are missing."""
        feed = RedditFeed()
        mock_config = MagicMock()
        mock_config.feeds.reddit_enabled = True
        mock_config.feeds.reddit_client_id = None
        mock_config.feeds.reddit_client_secret = "test_secret"

        assert feed.is_configured(mock_config) is False


class TestComputeEngagementConfidence:
    """Tests for _compute_engagement_confidence()."""

    async def test_high_upvotes(self) -> None:
        """Test that high upvotes boost confidence."""
        post = {"ups": 300, "num_comments": 10}

        result = _compute_engagement_confidence(post)

        assert result == BASE_CONFIDENCE * 1.2

    async def test_low_engagement(self) -> None:
        """Test that low engagement returns base confidence."""
        post = {"ups": 50, "num_comments": 10}

        result = _compute_engagement_confidence(post)

        assert result == BASE_CONFIDENCE


class TestPostToThreatRecords:
    """Tests for _post_to_threat_records()."""

    async def test_valid_post(self) -> None:
        """Test that a valid post with package names returns ThreatRecords."""
        from datetime import UTC, datetime

        # Use a recent timestamp (within the last hour) to pass age filter
        recent_timestamp = datetime.now(UTC).timestamp() - 3600  # 1 hour ago

        post = {
            "id": "12345",
            "created_utc": recent_timestamp,
            "title": "Warning: malicious express package",
            "selftext": "Check express and lodash",
            "permalink": "/r/infosec/12345",
            "ups": 50,
            "num_comments": 10,
        }
        subreddit = "infosec"
        max_age_hours = 24

        # Mock extract_packages to return test data
        mock_pkg1 = MagicMock()
        mock_pkg1.package = "express"
        mock_pkg1.ecosystem = "npm"
        mock_pkg2 = MagicMock()
        mock_pkg2.package = "lodash"
        mock_pkg2.ecosystem = "npm"

        with patch(
            "pkg_defender.intel.reddit.extract_packages",
            return_value=[mock_pkg1, mock_pkg2],
        ):
            result = _post_to_threat_records(post, subreddit, max_age_hours)

        assert isinstance(result, list)
        assert len(result) == 2
        assert all(r.source == "reddit" for r in result)
        assert result[0].package_name == "express"

    async def test_old_post(self) -> None:
        """Test that an old post returns an empty list."""
        post = {
            "id": "12345",
            "created_utc": 1600000000.0,  # Old timestamp
            "title": "Old post",
            "selftext": "Old content",
        }
        subreddit = "infosec"
        max_age_hours = 24

        result = _post_to_threat_records(post, subreddit, max_age_hours)

        assert result == []


class TestFetch:
    """Tests for RedditFeed.fetch()."""

    async def test_fetch_with_mock(self) -> None:
        """Test that fetch returns a FeedFetchResult."""
        feed = RedditFeed()

        # Mock the _reddit_get to return empty data
        with patch("pkg_defender.intel.reddit._reddit_get", return_value=[]):
            result = await feed.fetch(session=MagicMock())

        assert isinstance(result, FeedFetchResult)


class TestCheckPackage:
    """Tests for RedditFeed.check_package()."""

    async def test_check_package_returns_empty(self) -> None:
        """Test that check_package returns empty result for individual package queries."""
        feed = RedditFeed()

        result = await feed.check_package("express", "4.17.1", "npm")

        assert result == FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)


class TestModuleFunctions:
    """Tests for module-level functions."""

    async def test_has_reddit_feed_class(self) -> None:
        """Test that module exposes RedditFeed."""
        assert hasattr(reddit, "RedditFeed")
        assert callable(RedditFeed)

    async def test_has_compute_engagement(self) -> None:
        """Test that module exposes _compute_engagement_confidence."""
        assert hasattr(reddit, "_compute_engagement_confidence")
        assert callable(_compute_engagement_confidence)

    async def test_has_post_to_threat_records(self) -> None:
        """Test that module exposes _post_to_threat_records."""
        assert hasattr(reddit, "_post_to_threat_records")
        assert callable(_post_to_threat_records)
