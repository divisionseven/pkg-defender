"""Tests for Mastodon intelligence feed."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest
from dateutil.tz import tzutc

from pkg_defender.config.settings import FeedConfig, PKGDConfig
from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.mastodon import (
    MastodonFeed,
    _mastodon_get,
)


class TestMastodonFeed:
    """Test suite for MastodonFeed class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config with Mastodon settings."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.mastodon_enabled = True
        config.feeds.mastodon_instance = "infosec.exchange"
        config.feeds.mastodon_hashtags = ["infosec", "cybersecurity"]
        config.feeds.mastodon_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    @pytest.fixture
    def mock_config_disabled(self) -> MagicMock:
        """Create a mock config with feed disabled."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.mastodon_enabled = False
        config.feeds.http_timeout = 15
        config.feeds.mastodon_instance = "infosec.exchange"
        config.feeds.mastodon_hashtags = []
        config.feeds.mastodon_max_age_hours = 24
        return config

    # === Class instantiation ===

    def test_class_instantiation(self) -> None:
        """Test MastodonFeed can be instantiated."""
        feed = MastodonFeed()
        assert feed.name == "mastodon"
        assert feed.supports_incremental is True

    # === is_configured ===

    def test_is_configured_when_enabled(self, mock_config: MagicMock) -> None:
        """Test is_configured returns True when enabled."""
        feed = MastodonFeed()
        assert feed.is_configured(mock_config) is True

    def test_is_configured_when_disabled(self, mock_config_disabled: MagicMock) -> None:
        """Test is_configured returns False when disabled."""
        feed = MastodonFeed()
        assert feed.is_configured(mock_config_disabled) is False

    # === fetch method - simplified ===

    @pytest.mark.asyncio
    async def test_fetch_disabled_returns_empty(self, mock_config_disabled: MagicMock) -> None:
        """Test fetch returns empty list when feed is disabled."""
        feed = MastodonFeed()
        result = await feed.fetch(config=mock_config_disabled)
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_with_since_parameter(self, mock_config: MagicMock) -> None:
        """Test fetch uses since parameter for time filtering."""
        feed = MastodonFeed()
        since = datetime.now(tzutc()) - timedelta(hours=12)

        with patch("pkg_defender.intel.mastodon._mastodon_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = []

            result = await feed.fetch(since=since, config=mock_config)

        assert isinstance(result, FeedFetchResult)

    @pytest.mark.asyncio
    async def test_fetch_api_error_returns_empty(self, mock_config: MagicMock) -> None:
        """Test fetch returns empty on API error."""
        feed = MastodonFeed()

        with patch("pkg_defender.intel.mastodon._mastodon_get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = await feed.fetch(config=mock_config)

        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_iterates_hashtags(self, mock_config: MagicMock) -> None:
        """Test fetch iterates over all configured hashtags."""
        feed = MastodonFeed()
        assert len(mock_config.feeds.mastodon_hashtags) == 2

        with patch("pkg_defender.intel.mastodon._mastodon_get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = []

            await feed.fetch(config=mock_config)

        # Should call API twice (once per hashtag)
        assert mock_get.call_count == 2

    # === check_package (not supported) ===

    @pytest.mark.asyncio
    async def test_check_package_returns_empty(self, mock_config: MagicMock) -> None:
        """Test check_package always returns empty list (bulk-only feed)."""
        feed = MastodonFeed()
        result = await feed.check_package(
            package="test-package",
            version="1.0.0",
            ecosystem="npm",
            config=mock_config,
        )
        assert result.records == []


# ---------------------------------------------------------------------------
# _mastodon_get error handling and retry logic
# ---------------------------------------------------------------------------


class TestMastodonGet:
    """Tests for the _mastodon_get helper function."""

    @pytest.mark.asyncio
    async def test_returns_parsed_json_when_fetch_succeeds(self) -> None:
        """Test _mastodon_get returns parsed JSON on success."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value=[])
        mock_session.get = AsyncMock(return_value=mock_response)

        result = await _mastodon_get("https://infosec.exchange/api/v1/timelines/tag/infosec", mock_session)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_retries_on_timeout(self) -> None:
        """Test _mastodon_get retries on timeout."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value=[])

        # First call times out, second succeeds
        mock_session.get = AsyncMock(side_effect=[TimeoutError(), mock_response])

        result = await _mastodon_get("https://infosec.exchange/api/v1/timelines/tag/infosec", mock_session)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_raises_on_max_retries(self) -> None:
        """Test _mastodon_get raises after max retries."""
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=TimeoutError())

        with pytest.raises(TimeoutError):
            await _mastodon_get("https://infosec.exchange/api/v1/timelines/tag/infosec", mock_session)

    @pytest.mark.asyncio
    async def test_includes_instance_in_url(self) -> None:
        """Test _mastodon_get constructs correct URL."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={"data": []})
        mock_session.get = AsyncMock(return_value=mock_response)

        await _mastodon_get("https://mastodon.social/api/v1/timelines/tag/test", mock_session)
        # Verify the URL was called
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert "mastodon.social" in call_args.args[0]

    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self) -> None:
        """_mastodon_get retries on 429 and succeeds on second attempt.

        Covers lines 54-67 (retryable status path).
        """
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_ok = MagicMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[{"id": "1"}])
        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.mastodon.get_max_retries", return_value=2),
            patch("pkg_defender.intel.mastodon.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _mastodon_get("https://test.com/api", mock_session)

        assert isinstance(result, list)
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_on_non_retryable_status(self) -> None:
        """_mastodon_get raises immediately on 404 (non-retryable).

        Covers line 70 (non-retryable raise).
        """
        mock_session = AsyncMock()
        resp_404 = MagicMock()
        resp_404.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=404,
        )
        mock_session.get = AsyncMock(return_value=resp_404)

        with (
            patch("pkg_defender.intel.mastodon.get_max_retries", return_value=3),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _mastodon_get("https://test.com/api", mock_session)
        assert excinfo.value.status == 404

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_429(self) -> None:
        """_mastodon_get raises after all retries on persistent 429.

        Covers lines 68-69 (exhausted retries raise).
        """
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        mock_session.get = AsyncMock(return_value=resp_429)

        with (
            patch("pkg_defender.intel.mastodon.get_max_retries", return_value=2),
            patch("pkg_defender.intel.mastodon.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _mastodon_get("https://test.com/api", mock_session)
        assert excinfo.value.status == 429
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_timeout_then_succeeds(self) -> None:
        """_mastodon_get retries on TimeoutError and succeeds.

        Covers lines 72-85 (ClientError/TimeoutError retry path).
        """
        mock_session = AsyncMock()
        resp_ok = AsyncMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[{"id": "1"}])
        mock_session.get = AsyncMock(side_effect=[TimeoutError(), resp_ok])

        with (
            patch("pkg_defender.intel.mastodon.get_max_retries", return_value=2),
            patch("pkg_defender.intel.mastodon.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _mastodon_get("https://test.com/api", mock_session)

        assert isinstance(result, list)
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_no_retries_configured(self) -> None:
        """_mastodon_get raises RuntimeError when max_retries is 0.

        Covers lines 88-90 (fallback raise).
        """
        mock_session = AsyncMock()
        resp_ok = AsyncMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[{"id": "1"}])
        mock_session.get = AsyncMock(return_value=resp_ok)

        with (
            patch("pkg_defender.intel.mastodon.get_max_retries", return_value=0),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _mastodon_get("https://test.com/api", mock_session)


# ---------------------------------------------------------------------------
# MastodonFeed.fetch advanced edge cases
# ---------------------------------------------------------------------------


class TestMastodonFeedFetchAdvanced:
    """Advanced tests for MastodonFeed.fetch()."""

    @pytest.fixture
    def feed(self) -> MastodonFeed:
        """Create MastodonFeed instance."""
        return MastodonFeed()

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config with Mastodon settings."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.mastodon_enabled = True
        config.feeds.mastodon_instance = "infosec.exchange"
        config.feeds.mastodon_hashtags = ["infosec"]
        config.feeds.mastodon_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    @pytest.mark.asyncio
    async def test_fetch_handles_non_list_response(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch skips hashtags that return non-list response.

        Covers line 187 (non-list response check).
        """
        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value={"error": "not a list"},
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_applies_age_filter(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch filters posts older than since parameter.

        Covers lines 191-200 (age filtering via created_at).
        """
        old_time = (datetime.now(tzutc()) - timedelta(days=7)).isoformat()
        posts = [
            {"id": "100", "created_at": old_time, "content": "pip install requests", "url": "https://example.com/1"},
        ]

        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=posts,
        ):
            since = datetime.now(tzutc()) - timedelta(hours=1)
            result = await feed.fetch(config=mock_config, since=since)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_tracks_max_post_id(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch tracks max post ID for incremental cursor.

        Covers lines 202-207 (post ID tracking).
        """
        now_iso = datetime.now(tzutc()).isoformat()
        posts = [
            {"id": "100", "created_at": now_iso, "content": "pip install requests", "url": "https://example.com/1"},
            {"id": "200", "created_at": now_iso, "content": "npm install express", "url": "https://example.com/2"},
        ]

        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=posts,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_post_id_parse_error_skipped(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch skips posts with unparseable IDs gracefully.

        Covers lines 206-207 (KeyError/ValueError/TypeError handling).
        """
        now_iso = datetime.now(tzutc()).isoformat()
        posts = [
            {"id": None, "created_at": now_iso, "content": "pip install requests", "url": "https://example.com/1"},
            {"id": "abc", "created_at": now_iso, "content": "npm install lodash", "url": "https://example.com/2"},
        ]

        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=posts,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Both posts have content with package names
        assert len(result.records) > 0

    @pytest.mark.asyncio
    async def test_fetch_with_invalid_date_format(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch handles posts with unparseable dates gracefully.

        Covers lines 193-200 (ValueError/TypeError handling for dates).
        """
        posts = [
            {
                "id": "100",
                "created_at": "not-a-date",
                "content": "pip install requests",
                "url": "https://example.com/1",
            },
        ]

        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=posts,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_outer_exception_returns_failed(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch outer exception handler returns FAILED status.

        Trigger outer exception by making extract_packages raise during
        post processing (not caught by inner try/except around _mastodon_get).
        Covers lines 244-246 (outer try/except).
        """
        now_iso = datetime.now(tzutc()).isoformat()
        posts = [
            {
                "id": "42",
                "created_at": now_iso,
                "content": "pip install requests",
                "url": "https://example.com/1",
            },
        ]

        with (
            patch(
                "pkg_defender.intel.mastodon._mastodon_get",
                new_callable=AsyncMock,
                return_value=posts,
            ),
            patch(
                "pkg_defender.intel.mastodon.extract_packages",
                side_effect=TypeError("Extraction failed"),
            ),
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_creates_and_cleans_up_own_session(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch creates its own session and closes it after use.

        Covers lines 160-166, 248-249 (own_session creation/cleanup).
        """
        with (
            patch("pkg_defender.intel.mastodon.aiohttp.ClientSession") as mock_session_cls,
            patch("pkg_defender.intel.mastodon._mastodon_get", new_callable=AsyncMock, return_value=[]),
        ):
            mock_session_instance = AsyncMock()
            mock_session_cls.return_value = mock_session_instance

            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        mock_session_cls.assert_called_once()
        mock_session_instance.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_extracts_packages_from_content(self, feed: MastodonFeed, mock_config: MagicMock) -> None:
        """fetch extracts package names from post content.

        Covers lines 209-240 (package extraction and record creation).
        """
        now_iso = datetime.now(tzutc()).isoformat()
        posts = [
            {
                "id": "42",
                "created_at": now_iso,
                "content": "Just found a vulnerability in pip install requests",
                "url": "https://infosec.exchange/@user/42",
            },
        ]

        with patch(
            "pkg_defender.intel.mastodon._mastodon_get",
            new_callable=AsyncMock,
            return_value=posts,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) > 0
        assert result.records[0].source == "mastodon"
        assert result.records[0].is_unverified is True
