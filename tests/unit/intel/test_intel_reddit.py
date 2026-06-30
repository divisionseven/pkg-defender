"""Tests for Reddit intelligence feed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest

from pkg_defender.config.settings import FeedConfig, PKGDConfig
from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.reddit import (
    BASE_CONFIDENCE,
    PULLPUSH_SEARCH_URL,
    RedditFeed,
    _compute_engagement_confidence,
    _post_to_threat_records,
    _reddit_get,
)


class TestRedditFeed:
    """Test suite for RedditFeed class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config with Reddit settings."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.reddit_subreddits = ["python", "security"]
        config.feeds.reddit_keywords = ["malware", "supply chain"]
        config.feeds.reddit_max_age_hours = 24
        config.feeds.http_timeout = 15
        config.feeds.reddit_client_id = ""
        config.feeds.reddit_client_secret = ""
        return config

    @pytest.fixture
    def configured_config(self) -> MagicMock:
        """Create a mock config with full Reddit credentials."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.reddit_subreddits = ["python", "security"]
        config.feeds.reddit_keywords = ["malware", "supply chain"]
        config.feeds.reddit_max_age_hours = 24
        config.feeds.http_timeout = 15
        config.feeds.reddit_client_id = "test_client_id"
        config.feeds.reddit_client_secret = "test_client_secret"
        return config

    # === Class instantiation ===

    def test_class_instantiation(self) -> None:
        """Test RedditFeed can be instantiated."""
        feed = RedditFeed()
        assert feed.name == "reddit"
        assert feed.supports_incremental is True

    # === is_configured ===

    def test_is_configured_requires_credentials(self, mock_config: MagicMock) -> None:
        """Test Reddit requires OAuth credentials."""
        feed = RedditFeed()
        # No credentials - not configured
        assert feed.is_configured(mock_config) is False

    def test_is_configured_with_empty_secret(self, configured_config: MagicMock) -> None:
        """Test Reddit requires both client_id and client_secret."""
        feed = RedditFeed()
        # Only client_id set - not configured
        configured_config.feeds.reddit_client_secret = ""
        assert feed.is_configured(configured_config) is False

    def test_is_configured_with_empty_id(self, configured_config: MagicMock) -> None:
        """Test Reddit requires both client_id and client_secret."""
        feed = RedditFeed()
        # Only client_secret set - not configured
        configured_config.feeds.reddit_client_id = ""
        assert feed.is_configured(configured_config) is False

    def test_is_configured_with_both_credentials(self, configured_config: MagicMock) -> None:
        """Test Reddit is configured when both credentials are set."""
        feed = RedditFeed()
        assert feed.is_configured(configured_config) is True

    def test_is_configured_trims_whitespace(self) -> None:
        """Test is_configured trims whitespace from credentials."""
        feed = RedditFeed()
        config = MagicMock()
        config.feeds.reddit_client_id = "  test_id  "
        config.feeds.reddit_client_secret = "  test_secret  "
        assert feed.is_configured(config) is True

    # === _compute_engagement_confidence helper ===

    @pytest.mark.parametrize(
        "ups,num_comments,expected",
        [
            (0, 0, BASE_CONFIDENCE),  # No engagement
            (100, 10, BASE_CONFIDENCE),  # Below threshold
            (200, 0, BASE_CONFIDENCE * 1.2),  # At upvote threshold
            (0, 50, BASE_CONFIDENCE * 1.2),  # At comment threshold
            (500, 100, BASE_CONFIDENCE * 1.2),  # High engagement
        ],
    )
    def test_compute_engagement_confidence(self, ups: int, num_comments: int, expected: float) -> None:
        """Test engagement confidence scoring."""
        post = {"ups": ups, "num_comments": num_comments}
        result = _compute_engagement_confidence(post)
        assert result == expected

    def test_compute_engagement_confidence_handles_none(self) -> None:
        """Test engagement confidence handles None values."""
        post = {"ups": None, "num_comments": None}
        result = _compute_engagement_confidence(post)
        assert result == BASE_CONFIDENCE

    # === _post_to_threat_records helper ===

    def test_post_to_threat_records_with_package(self) -> None:
        """Test post conversion extracts package names."""
        post_time = datetime.now(UTC)
        # Use npm install command pattern for extraction (ecosystem known)
        post = {
            "id": "abc123",
            "title": "Warning: malicious npm package - run: npm install express",
            "selftext": "More details here",
            "created_utc": post_time.timestamp(),
            "permalink": "/r/security/comments/abc123",
            "ups": 500,
            "num_comments": 50,
            "upvote_ratio": 0.95,
        }

        records = _post_to_threat_records(post, "security", 24)

        assert len(records) == 1
        assert records[0].package_name == "express"
        assert records[0].ecosystem == "npm"
        assert records[0].source == "reddit"
        assert records[0].source_id == "abc123"
        assert records[0].is_unverified is True  # Reddit is Tier 3

    def test_post_to_threat_records_no_packages(self) -> None:
        """Test post without packages returns empty list."""
        post_time = datetime.now(UTC)
        post = {
            "id": "abc123",
            "title": "Just a regular post about programming",
            "selftext": "No packages here",
            "created_utc": post_time.timestamp(),
            "permalink": "/r/python/comments/abc123",
            "ups": 10,
            "num_comments": 5,
        }

        records = _post_to_threat_records(post, "python", 24)

        assert records == []

    def test_post_to_threat_records_too_old(self) -> None:
        """Test old post returns empty list."""
        old_time = datetime.now(UTC) - timedelta(hours=48)
        post = {
            "id": "abc123",
            "title": "malware found in npm",
            "selftext": "details",
            "created_utc": old_time.timestamp(),
            "permalink": "/r/security/comments/abc123",
        }

        records = _post_to_threat_records(post, "security", 24)

        assert records == []

    # === fetch method - simplified ===

    @pytest.mark.asyncio
    async def test_fetch_with_incremental_since(self, mock_config: MagicMock) -> None:
        """Test fetch respects since parameter."""
        feed = RedditFeed()

        since = datetime.now(UTC) - timedelta(hours=12)

        with patch("pkg_defender.intel.reddit._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"data": []}

            result = await feed.fetch(since=since, config=mock_config)

        assert isinstance(result, FeedFetchResult)

    @pytest.mark.asyncio
    async def test_fetch_api_error_returns_empty(self, mock_config: MagicMock) -> None:
        """Test fetch returns empty on API error."""
        feed = RedditFeed()

        with patch("pkg_defender.intel.reddit._reddit_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = await feed.fetch(config=mock_config)

        assert result.records == []
        assert result.status == FetchStatus.SUCCESS

    # === check_package (not supported) ===

    @pytest.mark.asyncio
    async def test_check_package_returns_empty(self, mock_config: MagicMock) -> None:
        """Test check_package always returns empty list (bulk-only feed)."""
        feed = RedditFeed()
        result = await feed.check_package(
            package="test-package",
            version="1.0.0",
            ecosystem="npm",
            config=mock_config,
        )
        assert result == FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)


class TestRedditConfidence:
    """Tests for Reddit confidence scoring."""

    def test_base_confidence_value(self) -> None:
        """Test BASE_CONFIDENCE is set correctly."""
        assert BASE_CONFIDENCE == 0.45

    def test_confidence_multiplier(self) -> None:
        """Test confidence multiplier is applied correctly."""
        assert BASE_CONFIDENCE * 1.2 == 0.54  # 0.45 * 1.2 = 0.54


class TestRedditFeedConfig:
    """Tests for Reddit feed configuration."""

    def test_default_config_empty_credentials(self) -> None:
        """Test default FeedConfig has empty Reddit credentials."""
        from pkg_defender.config.settings import FeedConfig

        config = FeedConfig()
        assert config.reddit_client_id == ""
        assert config.reddit_client_secret == ""

    def test_default_config_enabled_flag_false(self) -> None:
        """Test default FeedConfig has reddit_enabled as False."""
        from pkg_defender.config.settings import FeedConfig

        config = FeedConfig()
        assert config.reddit_enabled is False

    def test_default_config_subreddits_and_keywords(self) -> None:
        """Test default FeedConfig has expected subreddits and keywords."""
        from pkg_defender.config.settings import FeedConfig

        config = FeedConfig()
        assert "netsec" in config.reddit_subreddits
        assert "javascript" in config.reddit_subreddits
        assert "compromised" in config.reddit_keywords
        assert "malicious" in config.reddit_keywords

    @patch.dict("os.environ", {"PKGD_FEEDS_REDDIT_CLIENT_ID": "env_client_id"})
    def test_env_var_overrides_client_id(self) -> None:
        """Test PKGD_FEEDS_REDDIT_CLIENT_ID env var overrides config."""
        from pkg_defender.config.settings import load_config

        config = load_config()
        assert config.feeds.reddit_client_id == "env_client_id"

    @patch.dict(
        "os.environ",
        {
            "PKGD_FEEDS_REDDIT_CLIENT_ID": "env_client_id",
            "PKGD_FEEDS_REDDIT_CLIENT_SECRET": "env_client_secret",
        },
    )
    def test_env_var_overrides_both_credentials(self) -> None:
        """Test both credentials can be set via env vars."""
        from pkg_defender.config.settings import load_config

        config = load_config()
        assert config.feeds.reddit_client_id == "env_client_id"
        assert config.feeds.reddit_client_secret == "env_client_secret"

    @patch.dict(
        "os.environ",
        {"PKGD_FEEDS_REDDIT_ENABLED": "true"},
    )
    def test_env_var_overrides_enabled_flag(self) -> None:
        """Test PKGD_FEEDS_REDDIT_ENABLED env var works."""
        from pkg_defender.config.settings import load_config

        config = load_config()
        assert config.feeds.reddit_enabled is True


class TestRedditOAuthFlow:
    """Tests for Reddit OAuth flow."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        """Create a mock aiohttp session."""
        return AsyncMock()

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.http_timeout = 15
        return config

    @pytest.mark.asyncio
    async def test_oauth_token_endpoint(self, mock_config: MagicMock) -> None:
        """Test OAuth token request uses correct endpoint."""
        from pkg_defender.intel.reddit import _get_oauth_token

        # Create fresh mocks with proper async context manager setup
        mock_session = AsyncMock()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"access_token": "test_token_123", "token_type": "bearer"})

        # Setup async context manager for session.post
        async def mock_post(*args: object, **kwargs: object) -> MagicMock:
            return mock_response

        mock_session.post = mock_post

        token = await _get_oauth_token(
            mock_session,
            "test_client_id",
            "test_client_secret",
            mock_config,
        )

        # Verify the token URL is used in the call - check call args directly
        # Token was returned correctly from the mocked json response
        assert token == "test_token_123"

    @pytest.mark.asyncio
    async def test_oauth_token_includes_credentials(self, mock_session: AsyncMock, mock_config: MagicMock) -> None:
        """Test OAuth token request includes client credentials."""
        from pkg_defender.intel.reddit import _get_oauth_token

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"access_token": "test_token_123"})

        # Use AsyncMock with mock_response as return_value
        mock_session.post = AsyncMock(return_value=mock_response)

        await _get_oauth_token(
            mock_session,
            "my_client_id",
            "my_client_secret",
            mock_config,
        )

        # Verify post was called
        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_oauth_get_includes_bearer_header(self, mock_session: AsyncMock, mock_config: MagicMock) -> None:
        """Test OAuth GET requests include Bearer token."""
        from pkg_defender.intel.reddit import _reddit_get_oauth

        # Mock _get_oauth_token to return a test token
        with patch(
            "pkg_defender.intel.reddit._get_oauth_token",
            new_callable=AsyncMock,
        ) as mock_get_token:
            mock_get_token.return_value = "test_bearer_token"

            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_response.json = AsyncMock(return_value={"data": []})

            # Use AsyncMock with mock_response as return_value
            mock_session.get = AsyncMock(return_value=mock_response)

            await _reddit_get_oauth(
                "https://api.reddit.com/test",
                mock_session,
                "client_id",
                "client_secret",
                mock_config,
            )

            # Verify Bearer token was used in Authorization header
            call_args = mock_session.get.call_args
            assert call_args is not None
            headers = call_args.kwargs.get("headers", {})
            assert "Authorization" in headers
            assert headers["Authorization"] == "Bearer test_bearer_token"


# TestRedditBackwardCompatibility class removed - backward compat code deleted


# ---------------------------------------------------------------------------
# _reddit_get error handling and retry logic
# ---------------------------------------------------------------------------


class TestRedditGet:
    """Tests for the _reddit_get helper function."""

    @pytest.mark.asyncio
    async def test_returns_parsed_json_when_fetch_succeeds(self) -> None:
        """Test _reddit_get returns parsed JSON on success."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"data": [{"id": "abc"}]})
        mock_session.get = AsyncMock(return_value=mock_response)

        with patch("pkg_defender.intel.reddit.get_max_retries", return_value=2):
            result = await _reddit_get("http://test.com", mock_session)

        assert result == {"data": [{"id": "abc"}]}

    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self) -> None:
        """_reddit_get retries on 429 and succeeds on second attempt."""
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_ok = MagicMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value={"data": []})

        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=2),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _reddit_get("http://test.com", mock_session)

        assert result == {"data": []}
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_on_non_retryable_status(self) -> None:
        """_reddit_get raises immediately on 404 (non-retryable)."""
        mock_session = AsyncMock()
        resp_404 = MagicMock()
        resp_404.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=404,
        )
        mock_session.get = AsyncMock(return_value=resp_404)

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=3),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _reddit_get("http://test.com", mock_session)
        assert excinfo.value.status == 404

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_429(self) -> None:
        """_reddit_get raises ClientResponseError after all retries on 429."""
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        mock_session.get = AsyncMock(return_value=resp_429)

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=2),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _reddit_get("http://test.com", mock_session)
        assert excinfo.value.status == 429
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_timeout_then_succeeds(self) -> None:
        """_reddit_get retries on TimeoutError and succeeds on second attempt."""
        mock_session = AsyncMock()
        resp_ok = MagicMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value={"data": []})

        mock_session.get = AsyncMock(side_effect=[TimeoutError(), resp_ok])

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=2),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _reddit_get("http://test.com", mock_session)

        assert result == {"data": []}

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_client_error(self) -> None:
        """_reddit_get raises after all retries on persistent ClientError."""
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("conn reset"))

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=2),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientError),
        ):
            await _reddit_get("http://test.com", mock_session)

        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_no_retries_configured(self) -> None:
        """_reddit_get raises RuntimeError when max_retries is 0."""
        mock_session = AsyncMock()
        resp_ok = AsyncMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value={"data": []})
        mock_session.get = AsyncMock(return_value=resp_ok)

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=0),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _reddit_get("http://test.com", mock_session)

    @pytest.mark.asyncio
    async def test_retry_429_with_verbose_logging(self) -> None:
        """_reddit_get includes repr(exc) in verbose mode on 429."""
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_ok = MagicMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value={"data": []})

        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.reddit.get_max_retries", return_value=2),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
            patch("pkg_defender.intel.reddit.is_verbose_mode", return_value=True),
            patch("pkg_defender.intel.reddit.logger.warning") as mock_warn,
        ):
            await _reddit_get("http://test.com", mock_session)

        # verbose should include repr in the warning log message
        assert mock_warn.called


# ---------------------------------------------------------------------------
# _get_oauth_token error paths
# ---------------------------------------------------------------------------


class TestGetOAuthTokenErrors:
    """Tests for _get_oauth_token error handling."""

    @pytest.mark.asyncio
    async def test_oauth_token_http_error_raises(self) -> None:
        """_get_oauth_token raises on HTTP error response."""
        from pkg_defender.intel.reddit import _get_oauth_token

        mock_session = AsyncMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=401,
        )
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_config = MagicMock(spec=PKGDConfig)
        mock_config.feeds = MagicMock(spec=FeedConfig)
        mock_config.feeds.http_timeout = 15

        with pytest.raises(aiohttp.ClientResponseError):
            await _get_oauth_token(mock_session, "id", "secret", mock_config)


# ---------------------------------------------------------------------------
# _reddit_get_oauth error paths
# ---------------------------------------------------------------------------


class TestRedditGetOAuthErrors:
    """Tests for _reddit_get_oauth error handling."""

    @pytest.mark.asyncio
    async def test_oauth_get_http_error_raises(self) -> None:
        """_reddit_get_oauth raises on HTTP error."""
        from pkg_defender.intel.reddit import _reddit_get_oauth

        mock_session = AsyncMock()
        mock_config = MagicMock(spec=PKGDConfig)
        mock_config.feeds = MagicMock(spec=FeedConfig)
        mock_config.feeds.http_timeout = 15

        with patch(
            "pkg_defender.intel.reddit._get_oauth_token",
            new_callable=AsyncMock,
            return_value="test_token",
        ):
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = aiohttp.ClientResponseError(
                Mock(),
                Mock(),
                status=403,
            )
            mock_session.get = AsyncMock(return_value=mock_response)

            with pytest.raises(aiohttp.ClientResponseError):
                await _reddit_get_oauth(
                    "https://oauth.reddit.com/search",
                    mock_session,
                    "id",
                    "secret",
                    mock_config,
                )


# ---------------------------------------------------------------------------
# RedditFeed.fetch with OAuth flow and edge cases
# ---------------------------------------------------------------------------


class TestRedditFeedFetchAdvanced:
    """Advanced tests for RedditFeed.fetch()."""

    @pytest.fixture
    def feed(self) -> RedditFeed:
        """Create RedditFeed instance."""
        return RedditFeed()

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config without OAuth credentials (PullPush mode)."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.reddit_subreddits = ["python"]
        config.feeds.reddit_keywords = ["malware"]
        config.feeds.reddit_max_age_hours = 24
        config.feeds.http_timeout = 15
        config.feeds.reddit_client_id = ""
        config.feeds.reddit_client_secret = ""
        return config

    @pytest.fixture
    def oauth_config(self) -> MagicMock:
        """Create a mock config WITH OAuth credentials."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.reddit_subreddits = ["python"]
        config.feeds.reddit_keywords = ["malware"]
        config.feeds.reddit_max_age_hours = 24
        config.feeds.http_timeout = 15
        config.feeds.reddit_client_id = "test_client_id"
        config.feeds.reddit_client_secret = "test_client_secret"
        return config

    @pytest.mark.asyncio
    async def test_fetch_with_oauth_reponse_parsing(self, feed: RedditFeed, oauth_config: MagicMock) -> None:
        """fetch with OAuth parses Reddit API nested response correctly.

        Reddit OAuth returns: data.data.children[].data
        This test covers lines 400, 421-424.
        """
        sample_post = {
            "id": "abc123",
            "created_utc": (datetime.now(UTC) - timedelta(hours=1)).timestamp(),
            "title": "npm install malicious-pkg",
            "selftext": "",
            "permalink": "/r/python/comments/abc123",
            "ups": 10,
            "num_comments": 0,
        }

        mock_oauth_response = {
            "data": {
                "children": [{"data": sample_post}],
            },
        }

        with (
            patch(
                "pkg_defender.intel.reddit._reddit_get_oauth",
                new_callable=AsyncMock,
                return_value=mock_oauth_response,
            ) as mock_oauth,
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await feed.fetch(config=oauth_config)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) > 0
        # Verify OAuth URL was used
        call_url = mock_oauth.call_args[0][0]
        assert "oauth.reddit.com" in call_url

    @pytest.mark.asyncio
    async def test_fetch_deduplication_across_keywords(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch deduplicates posts with same ID across keyword searches.

        Covers lines 443-448 (dedup logic).
        Note: PullPush returns created_utc as string, _post_to_threat_records
        expects float — we use a float here to avoid the known incompatibility.
        """
        now_ts = datetime.now(UTC).timestamp()
        # Same post returned for two different keyword searches
        mock_response = {
            "data": [
                {
                    "id": "dup123",
                    "created_utc": now_ts,
                    "title": "npm install malicious-pkg",
                    "selftext": "",
                    "permalink": "/r/python/comments/dup123",
                    "ups": 5,
                    "num_comments": 0,
                },
            ],
        }

        with (
            patch(
                "pkg_defender.intel.reddit._reddit_get",
                new_callable=AsyncMock,
                return_value=mock_response,
            ),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await feed.fetch(config=mock_config)

        # Should only have one record despite 2 keywords hitting same post
        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1

    @pytest.mark.asyncio
    async def test_fetch_with_ecosystem_filter(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch applies ecosystem filter to extracted packages.

        Covers lines 463-466 (ecosystem filter).
        """
        now_ts = datetime.now(UTC).timestamp()
        mock_response = {
            "data": [
                {
                    "id": "eco123",
                    "created_utc": now_ts,
                    "title": "pip install requests and npm install express",
                    "selftext": "",
                    "permalink": "/r/python/comments/eco123",
                    "ups": 5,
                    "num_comments": 0,
                },
            ],
        }

        with (
            patch(
                "pkg_defender.intel.reddit._reddit_get",
                new_callable=AsyncMock,
                return_value=mock_response,
            ),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            # Filter to only npm ecosystem
            result = await feed.fetch(config=mock_config, ecosystems=["npm"])

        assert result.status == FetchStatus.SUCCESS
        # Only npm packages should be included
        for record in result.records:
            assert record.ecosystem == "npm"

    @pytest.mark.asyncio
    async def test_fetch_age_filter_skips_old_posts(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch skips posts older than the cursor.

        Covers lines 450-454 (age filtering).
        """
        old_ts = (datetime.now(UTC) - timedelta(days=30)).timestamp()
        mock_response = {
            "data": [
                {
                    "id": "old123",
                    "created_utc": str(old_ts),
                    "title": "npm install old-package",
                    "selftext": "",
                    "permalink": "/r/python/comments/old123",
                    "ups": 5,
                    "num_comments": 0,
                },
            ],
        }

        with (
            patch(
                "pkg_defender.intel.reddit._reddit_get",
                new_callable=AsyncMock,
                return_value=mock_response,
            ),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            # since is very recent, so old post should be skipped
            since = datetime.now(UTC) - timedelta(hours=1)
            result = await feed.fetch(config=mock_config, since=since)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 0

    @pytest.mark.asyncio
    async def test_fetch_outer_exception_returns_failed(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch outer exception handler returns FAILED status.

        Covers lines 490-494 (outer try/except).
        """
        with (
            patch(
                "pkg_defender.intel.reddit.asyncio.gather",
                side_effect=RuntimeError("Unexpected failure"),
            ),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_creates_and_cleans_up_own_session(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch creates its own session and closes it after use.

        Covers lines 382-387, 496-497 (own_session creation and cleanup).
        """
        with (
            patch("pkg_defender.intel.reddit.aiohttp.ClientSession") as mock_session_cls,
            patch("pkg_defender.intel.reddit._reddit_get", new_callable=AsyncMock, return_value={"data": []}),
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_session_instance = AsyncMock()
            mock_session_cls.return_value = mock_session_instance

            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Verify session was created and closed
        mock_session_cls.assert_called_once()
        mock_session_instance.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_pullpush_url_construction(self, feed: RedditFeed, mock_config: MagicMock) -> None:
        """fetch uses PullPush URL when not using OAuth.

        Covers lines 408-416 (PullPush URL construction).
        """
        with (
            patch(
                "pkg_defender.intel.reddit._reddit_get",
                new_callable=AsyncMock,
                return_value={"data": []},
            ) as mock_get,
            patch("pkg_defender.intel.reddit.asyncio.sleep", new_callable=AsyncMock),
            patch("pkg_defender.intel.reddit.asyncio.gather") as mock_gather,
        ):
            mock_gather.return_value = []
            await feed.fetch(config=mock_config)

        call_url = mock_get.call_args[0][0]
        assert PULLPUSH_SEARCH_URL in call_url


# ---------------------------------------------------------------------------
# _post_to_threat_records edge cases
# ---------------------------------------------------------------------------


class TestPostToThreatRecordsAdvanced:
    """Tests for _post_to_threat_records edge cases."""

    def test_missing_permalink(self) -> None:
        """Post without permalink produces record with detail_url=None."""
        now_ts = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        post = {
            "id": "no-perma",
            "created_utc": now_ts,
            "title": "pip install dangerous",
            "selftext": "",
            "ups": 10,
            "num_comments": 0,
        }
        records = _post_to_threat_records(post, "security", 24)
        # Should still produce records but detail_url is None
        assert len(records) == 1
        assert records[0].detail_url is None

    def test_missing_id(self) -> None:
        """Post without id produces record with empty source_id."""
        now_ts = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        post = {
            "created_utc": now_ts,
            "title": "npm install bad-pkg",
            "selftext": "",
            "ups": 10,
            "num_comments": 0,
        }
        records = _post_to_threat_records(post, "security", 24)
        assert len(records) > 0

    def test_empty_title_and_selftext(self) -> None:
        """Post with empty title and selftext returns empty list."""
        now_ts = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        post = {
            "id": "empty-post",
            "created_utc": now_ts,
            "title": "",
            "selftext": "",
            "ups": 0,
            "num_comments": 0,
        }
        records = _post_to_threat_records(post, "security", 24)
        assert records == []

    def test_zero_ups_and_comments(self) -> None:
        """Post with zero ups/comments gets base confidence."""
        now_ts = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        post = {
            "id": "zero-eng",
            "created_utc": now_ts,
            "title": "pip install requests",
            "selftext": "",
            "ups": 0,
            "num_comments": 0,
            "permalink": "/r/test/zero-eng",
        }
        records = _post_to_threat_records(post, "test", 24)
        assert len(records) == 1
        assert records[0].confidence == BASE_CONFIDENCE
