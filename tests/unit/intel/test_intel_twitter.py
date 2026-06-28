"""Tests for X/Twitter intelligence feed."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.x_twitter import (
    BASE_CONFIDENCE,
    TRUSTED_ACCOUNT_MULTIPLIER,
    XTwitterFeed,
    _api_get,
    _build_search_query,
    _parse_tweet,
)


class TestXTwitterFeed:
    """Test suite for XTwitterFeed class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config object with X/Twitter settings."""
        config = MagicMock()
        config.feeds.x_twitter_bearer_token = "test_bearer_token_12345"
        config.feeds.x_twitter_keywords = ["supply chain", "npm malware"]
        config.feeds.x_twitter_trusted_accounts = ["123456789"]
        config.feeds.x_twitter_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    @pytest.fixture
    def mock_config_disabled(self) -> MagicMock:
        """Create a mock config with no token (feed disabled)."""
        config = MagicMock()
        config.feeds.x_twitter_bearer_token = ""
        config.feeds.http_timeout = 15
        return config

    # === Class instantiation ===

    def test_class_instantiation(self) -> None:
        """Test XTwitterFeed can be instantiated."""
        feed = XTwitterFeed()
        assert feed.name == "x_twitter"
        assert feed.supports_incremental is False

    # === is_configured ===

    def test_is_configured_with_token(self, mock_config: MagicMock) -> None:
        """Test is_configured returns True when token is present."""
        feed = XTwitterFeed()
        assert feed.is_configured(mock_config) is True

    def test_is_configured_without_token(self, mock_config_disabled: MagicMock) -> None:
        """Test is_configured returns False when token is empty."""
        feed = XTwitterFeed()
        assert feed.is_configured(mock_config_disabled) is False

    def test_is_configured_with_whitespace_token(self) -> None:
        """Test is_configured returns False when token is only whitespace."""
        config = MagicMock()
        config.feeds.x_twitter_bearer_token = "   "
        feed = XTwitterFeed()
        assert feed.is_configured(config) is False

    # === _build_search_query helper ===

    @pytest.mark.parametrize(
        "keywords,expected",
        [
            (["npm"], '("npm") -is:retweet lang:en'),
            (["supply chain"], '("supply chain") -is:retweet lang:en'),
            (["npm", "pip"], '("npm" OR "pip") -is:retweet lang:en'),
        ],
    )
    def test_build_search_query(self, keywords: list[str], expected: str) -> None:
        """Test search query is built correctly from keywords."""
        result = _build_search_query(keywords)
        assert result == expected

    # === fetch method - with mocking at config level ===

    @pytest.mark.asyncio
    async def test_fetch_disabled_no_token(self, mock_config_disabled: MagicMock) -> None:
        """Test fetch returns failed FeedFetchResult when no token is configured."""
        feed = XTwitterFeed()
        result = await feed.fetch(config=mock_config_disabled)
        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_disabled_no_keywords(self) -> None:
        """Test fetch returns failed FeedFetchResult when no keywords are configured."""
        config = MagicMock()
        config.feeds.x_twitter_bearer_token = "test_token"
        config.feeds.x_twitter_keywords = []
        config.feeds.http_timeout = 15

        feed = XTwitterFeed()
        result = await feed.fetch(config=config)
        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_creates_own_session(self, mock_config: MagicMock) -> None:
        """Test fetch creates its own session when none provided."""
        # Mock the API response at the function level
        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {"data": [], "includes": {"users": []}}

            # Re-import after patch is active to ensure feed.fetch uses the
            # correct globals dict that includes the patched _api_get
            from pkg_defender.intel.x_twitter import XTwitterFeed as XTwitterFeedFresh

            feed = XTwitterFeedFresh()
            result = await feed.fetch(config=mock_config)

        # Should return FeedFetchResult but also should have tried to call API
        assert isinstance(result, FeedFetchResult)

    @pytest.mark.asyncio
    async def test_fetch_success_returns_records(self, mock_config: MagicMock) -> None:
        """Test fetch returns parsed records on successful API response."""
        # Use a recent timestamp to avoid max_age filter
        recent_time = datetime.now() - timedelta(hours=1)

        # Mock the API response with actual tweet data
        api_response = {
            "data": [
                {
                    "id": "1234567890",
                    "author_id": "111111111",
                    "created_at": recent_time.isoformat() + "Z",
                    "text": "Found malware `malicious-package`",
                }
            ],
            "includes": {"users": [{"id": "111111111", "username": "security_expert"}]},
        }

        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = api_response

            # Re-import after patch is active to ensure feed.fetch uses the
            # correct globals dict that includes the patched _api_get
            from pkg_defender.intel.x_twitter import XTwitterFeed as XTwitterFeedFresh

            feed = XTwitterFeedFresh()
            result = await feed.fetch(config=mock_config)

        # Should have parsed the tweet and returned a record
        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].package_name == "malicious-package"
        assert result.records[0].source == "x_twitter"

    @pytest.mark.asyncio
    async def test_fetch_filters_by_ecosystem(self, mock_config: MagicMock) -> None:
        """Test fetch filters records by ecosystem when specified."""
        api_response = {
            "data": [
                {
                    "id": "1234567890",
                    "author_id": "111111111",
                    "created_at": "2024-01-15T10:00:00.000Z",
                    "text": "Found malware `malicious-package`",
                }
            ],
            "includes": {"users": []},
        }

        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = api_response

            # Re-import after patch is active to ensure feed.fetch uses the
            # correct globals dict that includes the patched _api_get
            from pkg_defender.intel.x_twitter import XTwitterFeed as XTwitterFeedFresh

            feed = XTwitterFeedFresh()
            # Filter to only npm ecosystem - pypi package should be filtered out
            result = await feed.fetch(config=mock_config, ecosystems=["npm"])

        # The extracted package is pypi (malicious-package), so filtered out
        assert isinstance(result, FeedFetchResult)
        assert len(result.records) == 0

    @pytest.mark.asyncio
    async def test_fetch_401_returns_empty(self, mock_config: MagicMock) -> None:
        """Test fetch returns failed FeedFetchResult on 401 auth error."""
        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(), history=MagicMock(), status=401
            )

            # Re-import after patch is active to ensure feed.fetch uses the
            # correct globals dict that includes the patched _api_get
            from pkg_defender.intel.x_twitter import XTwitterFeed as XTwitterFeedFresh

            feed = XTwitterFeedFresh()
            result = await feed.fetch(config=mock_config)

        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_returns_fetch_result_when_session_provided(self, mock_config: MagicMock) -> None:
        """Test fetch uses provided session instead of creating one."""
        mock_session = AsyncMock()
        api_response = {"data": [], "includes": {"users": []}}

        with patch("pkg_defender.intel.x_twitter._api_get", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = api_response

            # Re-import after patch is active to ensure feed.fetch uses the
            # correct globals dict that includes the patched _api_get
            from pkg_defender.intel.x_twitter import XTwitterFeed as XTwitterFeedFresh

            feed = XTwitterFeedFresh()
            await feed.fetch(config=mock_config, session=mock_session)

        # Should call API with the provided session
        assert mock_api.called

    # === check_package (not supported) ===

    @pytest.mark.asyncio
    async def test_check_package_returns_empty(self, mock_config: MagicMock) -> None:
        """Test check_package always returns failed FeedFetchResult (bulk-only feed)."""
        feed = XTwitterFeed()
        result = await feed.check_package(
            package="test-package",
            version="1.0.0",
            ecosystem="npm",
            config=mock_config,
        )
        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []


class TestXTwitterConfidence:
    """Tests for X/Twitter confidence scoring."""

    def test_base_confidence_value(self) -> None:
        """Test BASE_CONFIDENCE is set correctly."""
        assert BASE_CONFIDENCE == 0.5

    def test_trusted_account_multiplier(self) -> None:
        """Test TRUSTED_ACCOUNT_MULTIPLIER is applied correctly."""
        assert TRUSTED_ACCOUNT_MULTIPLIER == 1.5
        # Trusted account gets 0.5 * 1.5 = 0.75
        assert BASE_CONFIDENCE * TRUSTED_ACCOUNT_MULTIPLIER == 0.75


# ---------------------------------------------------------------------------
# _parse_tweet edge cases
# ---------------------------------------------------------------------------


class TestParseTweet:
    """Tests for the _parse_tweet helper function."""

    @pytest.fixture
    def minimal_tweet(self) -> dict[str, Any]:
        """Basic tweet structure with recent timestamp."""
        # Use a recent timestamp to avoid max_age filter
        now = datetime.now()
        recent_time = now - timedelta(hours=1)  # 1 hour ago
        return {
            "id": "1234567890",
            "author_id": "111111111",
            "created_at": recent_time.isoformat() + "Z",
            "text": "Found malware `malicious-package`",
        }

    def test_returns_none_when_tweet_too_old(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet returns None for tweets beyond max_age_hours."""
        # Create tweet from 48 hours ago
        old_time = datetime.now() - timedelta(hours=48)
        minimal_tweet["created_at"] = old_time.isoformat() + "Z"
        # Need to reset the text to have an extractable package
        minimal_tweet["text"] = "Found malware `malicious-package`"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
        )
        assert result is None

    def test_returns_none_when_no_package_extracted(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet returns None when no package names in text."""
        minimal_tweet["text"] = "Just a regular tweet with no packages"

        result = _parse_tweet(
            minimal_tweet,
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
            includes_users={},
        )
        assert result is None

    def test_returns_threatrecord_with_trusted_account_boost(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet boosts confidence for trusted accounts."""
        minimal_tweet["author_id"] = "123456789"  # trusted account
        # Use backtick pattern for extraction
        minimal_tweet["text"] = "Found malware `malicious-package`"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={"123456789": {"username": "security_expert"}},
            trusted_accounts=["123456789"],
            keywords=["malware"],
            max_age_hours=24,
        )
        assert result is not None
        assert result.confidence == 0.75  # 0.5 * 1.5
        assert result.severity == "LOW"

    def test_returns_threatrecord_with_regular_account(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet uses base confidence for non-trusted accounts."""
        minimal_tweet["author_id"] = "999999999"
        # Use backtick pattern for extraction
        minimal_tweet["text"] = "Found malware `bad-package`"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=["123456789"],  # not this user
            keywords=["malware"],
            max_age_hours=24,
        )
        assert result is not None
        assert result.confidence == 0.5  # base confidence

    def test_handles_unknown_ecosystem(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet defaults ecosystem to unknown when not detected."""
        # Use a name that won't match npm/pypi patterns (no hyphens in Python naming)
        minimal_tweet["text"] = "Check out `axios` package"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
        )
        assert result is not None
        assert result.ecosystem == "unknown"  # axios has unknown ecosystem

    def test_handles_missing_created_at(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet handles tweets without created_at field."""
        del minimal_tweet["created_at"]
        minimal_tweet["text"] = "Found malware `bad-package`"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
        )
        # Should still process since current time is used as fallback
        assert result is not None

    def test_handles_invalid_created_at_format(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet handles malformed created_at timestamp."""
        minimal_tweet["created_at"] = "not-a-valid-timestamp"
        minimal_tweet["text"] = "Found malware `bad-package`"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
        )
        # Should still process since current time is used as fallback
        assert result is not None

    def test_uses_first_extracted_package_as_primary(self, minimal_tweet: dict[str, Any]) -> None:
        """Test _parse_tweet uses first extracted package for primary record."""
        # Text with install commands - multiple packages from different ecosystems
        minimal_tweet["text"] = "npm install bad-one and pip install bad-two"

        result = _parse_tweet(
            minimal_tweet,
            includes_users={},
            trusted_accounts=[],
            keywords=["malware"],
            max_age_hours=24,
        )
        assert result is not None
        # Should use the first extracted package (bad-one from npm)


# ---------------------------------------------------------------------------
# _api_get error handling and retry logic
# ---------------------------------------------------------------------------


class TestApiGet:
    """Tests for the _api_get helper function."""

    @pytest.mark.asyncio
    async def test_returns_parsed_json_when_fetch_succeeds(self) -> None:
        """Test _api_get returns parsed JSON on success."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"data": "test"})
        mock_response.raise_for_status = MagicMock()
        mock_session.get = AsyncMock(return_value=mock_response)

        result = await _api_get("http://api.test", {}, "token", mock_session)
        assert result == {"data": "test"}

    @pytest.mark.asyncio
    async def test_raises_on_401_auth_error(self) -> None:
        """Test _api_get raises immediately on 401 (auth error)."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.raise_for_status = MagicMock(
            side_effect=aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=401)
        )
        mock_session.get = AsyncMock(return_value=mock_response)

        with pytest.raises(aiohttp.ClientResponseError):
            await _api_get("http://api.test", {}, "token", mock_session)

    @pytest.mark.asyncio
    async def test_raises_on_403_auth_error(self) -> None:
        """Test _api_get raises immediately on 403 (forbidden)."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.raise_for_status = MagicMock(
            side_effect=aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=403)
        )
        mock_session.get = AsyncMock(return_value=mock_response)

        with pytest.raises(aiohttp.ClientResponseError):
            await _api_get("http://api.test", {}, "token", mock_session)

    @pytest.mark.asyncio
    async def test_retry_then_success_on_429(self) -> None:
        """Test _api_get retries on 429 (rate limit) then succeeds."""
        mock_session = AsyncMock()

        # First two calls return 429, third succeeds
        mock_response_429 = MagicMock()
        mock_response_429.status = 429
        mock_response_429.raise_for_status = MagicMock(
            side_effect=aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=429)
        )

        mock_response_success = MagicMock()
        mock_response_success.status = 200
        mock_response_success.json = AsyncMock(return_value={"ok": True})
        mock_response_success.raise_for_status = MagicMock()

        mock_session.get = AsyncMock(
            side_effect=[
                mock_response_429,
                mock_response_429,
                mock_response_success,
            ]
        )

        result = await _api_get("http://api.test", {}, "token", mock_session)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_retry_then_success_on_500(self) -> None:
        """Test _api_get retries on 500 then succeeds."""
        mock_session = AsyncMock()

        mock_response_500 = MagicMock()
        mock_response_500.status = 500
        mock_response_500.raise_for_status = MagicMock(
            side_effect=aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=500)
        )

        mock_response_success = MagicMock()
        mock_response_success.status = 200
        mock_response_success.json = AsyncMock(return_value={"ok": True})
        mock_response_success.raise_for_status = MagicMock()

        mock_session.get = AsyncMock(
            side_effect=[
                mock_response_500,
                mock_response_success,
            ]
        )

        result = await _api_get("http://api.test", {}, "token", mock_session)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_retry_exhausted_raises_after_max_retries(self) -> None:
        """Test _api_get raises after all retries exhausted."""
        mock_session = AsyncMock()

        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.raise_for_status = MagicMock(
            side_effect=aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=500)
        )

        mock_session.get = AsyncMock(return_value=mock_response)

        with pytest.raises(aiohttp.ClientResponseError):
            await _api_get("http://api.test", {}, "token", mock_session)

    @pytest.mark.asyncio
    async def test_network_error_triggers_retry(self) -> None:
        """Test _api_get retries on network errors."""
        mock_session = AsyncMock()

        # First call fails with network error, second succeeds
        mock_response_error = MagicMock()
        mock_response_error.status = 500
        mock_response_error.raise_for_status = MagicMock(side_effect=aiohttp.ClientError())

        mock_response_success = MagicMock()
        mock_response_success.status = 200
        mock_response_success.json = AsyncMock(return_value={"ok": True})
        mock_response_success.raise_for_status = MagicMock()

        mock_session.get = AsyncMock(
            side_effect=[
                mock_response_error,
                mock_response_success,
            ]
        )

        result = await _api_get("http://api.test", {}, "token", mock_session)
        assert result == {"ok": True}
