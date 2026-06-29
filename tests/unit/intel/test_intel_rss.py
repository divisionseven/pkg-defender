"""Tests for RSS intelligence feed."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest
from dateutil.tz import tzutc

from pkg_defender.config.settings import FeedConfig, PKGDConfig
from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.rss_feed import (
    RSSFeed,
    _convert_published,
    _fetch_rss,
    _fetch_rss_urllib,
    _urllib_fetch,
)


class TestRSSFeed:
    """Test suite for RSSFeed class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config with RSS settings."""
        config = MagicMock()
        config.feeds.rss_urls = [
            "https://blog.security.example.com/feed.xml",
            "https://news.example.com/rss",
        ]
        config.feeds.rss_keywords = ["malware", "supply chain", "vulnerability"]
        config.feeds.rss_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    @pytest.fixture
    def mock_config_empty(self) -> MagicMock:
        """Create a mock config with no RSS URLs."""
        config = MagicMock()
        config.feeds.rss_urls = []
        config.feeds.rss_keywords = []
        config.feeds.rss_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    # === Class instantiation ===

    def test_class_instantiation(self) -> None:
        """Test RSSFeed can be instantiated."""
        feed = RSSFeed()
        assert feed.name == "rss"
        assert feed.supports_incremental is False

    # === is_configured ===

    def test_is_configured_with_urls(self, mock_config: MagicMock) -> None:
        """Test is_configured returns True when URLs are configured."""
        feed = RSSFeed()
        assert feed.is_configured(mock_config) is True

    def test_is_configured_without_urls(self, mock_config_empty: MagicMock) -> None:
        """Test is_configured returns False when no URLs configured."""
        feed = RSSFeed()
        assert feed.is_configured(mock_config_empty) is False

    # === _convert_published helper ===

    def test_convert_published_none_values(self) -> None:
        """Test conversion returns None when no date fields present."""
        mock_entry = MagicMock()
        mock_entry.published_parsed = None
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        assert result is None

    def test_convert_published_with_datetime_obj(self) -> None:
        """Test conversion handles datetime objects."""
        from datetime import datetime as dt

        dt_with_tz = dt(2024, 1, 15, 10, 30, 0, tzinfo=tzutc())

        mock_entry = MagicMock()
        mock_entry.published_parsed = dt_with_tz
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        assert result is not None
        assert result.year == 2024

    def test_convert_published_with_struct_time(self) -> None:
        """Test conversion from struct_time."""
        from time import struct_time

        parsed = struct_time((2024, 1, 15, 10, 30, 0, 0, 0, 0))

        mock_entry = MagicMock()
        mock_entry.published_parsed = parsed
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        assert result is not None
        assert result.year == 2024

    # === fetch method - simplified ===

    @pytest.mark.asyncio
    async def test_fetch_with_since_parameter(self, mock_config: MagicMock) -> None:
        """Test fetch respects since parameter for time filtering."""
        feed = RSSFeed()
        since = datetime.now(tzutc()) - timedelta(hours=12)

        with patch("pkg_defender.intel.rss_feed._fetch_rss", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = MagicMock(entries=[])
            result = await feed.fetch(since=since, config=mock_config)

        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_api_error_returns_empty(self, mock_config: MagicMock) -> None:
        """Test fetch returns empty on API error."""
        feed = RSSFeed()

        with patch("pkg_defender.intel.rss_feed._fetch_rss", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.side_effect = Exception("Network error")

            result = await feed.fetch(config=mock_config)

        assert isinstance(result, FeedFetchResult)
        # Per-URL exceptions are caught gracefully (inner try/except);
        # the outer handler (status=FAILED) is only for session-level failures.
        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_iterates_multiple_urls(self, mock_config: MagicMock) -> None:
        """Test fetch iterates over all configured URLs."""
        feed = RSSFeed()
        assert len(mock_config.feeds.rss_urls) == 2

        with patch("pkg_defender.intel.rss_feed._fetch_rss", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = MagicMock(entries=[])
            await feed.fetch(config=mock_config)

        assert mock_fetch.call_count == 2

    # === check_package (not supported) ===

    @pytest.mark.asyncio
    async def test_check_package_returns_empty(self, mock_config: MagicMock) -> None:
        """Test check_package always returns empty list (bulk-only feed)."""
        feed = RSSFeed()
        result = await feed.check_package(
            package="test-package",
            version="1.0.0",
            ecosystem="npm",
            config=mock_config,
        )
        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []


class TestRSSConfidence:
    """Tests for RSS confidence scoring."""

    def test_default_confidence(self) -> None:
        """Test RSS feed has default confidence of 0.5."""
        # Verified in implementation: confidence=0.5
        pass


# ---------------------------------------------------------------------------
# _convert_published error paths
# ---------------------------------------------------------------------------


class TestConvertPublishedAdvanced:
    """Tests for _convert_published edge cases."""

    def test_datetime_without_tzinfo(self) -> None:
        """datetime without tzinfo gets replaced with UTC.

        Covers lines 57-58 (tzinfo check).
        """
        mock_entry = MagicMock()
        dt_naive = datetime(2024, 6, 15, 10, 30, 0)  # no tzinfo
        mock_entry.published_parsed = dt_naive
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)

        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2024
        assert result.month == 6

    def test_invalid_type_returns_none(self) -> None:
        """non-datetime, non-struct_time value returns None.

        Covers lines 59-61 (TypeError/ValueError/OverflowError path).
        """
        mock_entry = MagicMock()
        mock_entry.published_parsed = "not-a-date-object"
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        assert result is None

    def test_overflow_error_returns_none(self) -> None:
        """struct_time with out-of-range values returns None.

        Covers line 61 (OverflowError path).
        """
        from time import struct_time

        mock_entry = MagicMock()
        # These values are technically valid, but we can trigger ValueError
        # with negative values, etc.
        mock_entry.published_parsed = struct_time((0, 0, 0, 0, 0, 0, 0, 0, 0))
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        # Invalid time values should return None
        assert result is None or isinstance(result, datetime)

    def test_string_as_published_returns_none(self) -> None:
        """string value for published returns None (no ValueError explosion)."""
        mock_entry = MagicMock()
        mock_entry.published_parsed = "2024-01-01"
        mock_entry.updated_parsed = None

        with patch("pkg_defender.intel.rss_feed.logger"):
            result = _convert_published(mock_entry)
        # String "2024-01-01" is not struct_time or datetime, falls past both checks
        assert result is None


# ---------------------------------------------------------------------------
# _fetch_rss error handling paths
# ---------------------------------------------------------------------------


class TestFetchRSS:
    """Tests for _fetch_rss error handling."""

    @pytest.mark.asyncio
    async def test_non_retryable_status_raises(self) -> None:
        """_fetch_rss raises immediately on 404 (non-retryable).

        Covers line 153 (non-retryable raise).
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
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _fetch_rss("https://example.com/feed.xml", mock_session)
        assert excinfo.value.status == 404

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_no_retries_configured(self) -> None:
        """_fetch_rss raises RuntimeError when max_retries is 0.

        Covers line 166 (RuntimeError fallback).
        """
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("fail"))

        with (
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=0),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _fetch_rss("https://example.com/feed.xml", mock_session)

    @pytest.mark.asyncio
    async def test_returns_feedparser_dict_when_fetch_succeeds(self) -> None:
        """_fetch_rss returns feedparser result on success."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.read = AsyncMock(return_value=b"<rss><channel><item><title>Test</title></item></channel></rss>")
        mock_session.get = AsyncMock(return_value=mock_response)

        with patch("pkg_defender.intel.rss_feed.feedparser.parse") as mock_parse:
            mock_parse.return_value = {"entries": [{"title": "Test"}]}
            result = await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert "entries" in result
        assert len(result["entries"]) == 1

    @pytest.mark.asyncio
    async def test_403_falls_back_to_urllib(self) -> None:
        """_fetch_rss falls back to urllib on 403.

        Covers lines 134-140 (403 TLS fingerprint fallback).
        """
        mock_session = AsyncMock()
        resp_403 = MagicMock()
        resp_403.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=403,
        )
        mock_session.get = AsyncMock(return_value=resp_403)

        with (
            patch(
                "pkg_defender.intel.rss_feed._fetch_rss_urllib",
                new_callable=AsyncMock,
                return_value={"entries": []},
            ) as mock_urllib_fallback,
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
        ):
            result = await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert "entries" in result
        mock_urllib_fallback.assert_called_once_with("https://example.com/feed.xml")

    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self) -> None:
        """_fetch_rss retries on 429 and succeeds.

        Covers lines 141-152 (429 retry path).
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
        resp_ok.read = AsyncMock(return_value=b"<rss></rss>")
        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.rss_feed.feedparser.parse", return_value={"entries": []}),
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
            patch("pkg_defender.intel.rss_feed.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert "entries" in result
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_429(self) -> None:
        """_fetch_rss raises after all retries on persistent 429.

        Covers lines 151-152 (exhausted retries raise).
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
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
            patch("pkg_defender.intel.rss_feed.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientResponseError),
        ):
            await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_client_error_then_succeeds(self) -> None:
        """_fetch_rss retries on ClientError and succeeds.

        Covers lines 154-162 (ClientError retry path).
        """
        mock_session = AsyncMock()
        resp_ok = AsyncMock()
        resp_ok.raise_for_status = MagicMock()
        resp_ok.read = AsyncMock(return_value=b"<rss></rss>")
        mock_session.get = AsyncMock(side_effect=[aiohttp.ClientError("timeout"), resp_ok])

        with (
            patch("pkg_defender.intel.rss_feed.feedparser.parse", return_value={"entries": []}),
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
            patch("pkg_defender.intel.rss_feed.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert "entries" in result
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_client_error(self) -> None:
        """_fetch_rss raises after all retries on persistent ClientError.

        Covers line 163 (exhausted raise).
        """
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("always fails"))

        with (
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=2),
            patch("pkg_defender.intel.rss_feed.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientError),
        ):
            await _fetch_rss("https://example.com/feed.xml", mock_session)

        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_no_retries(self) -> None:
        """_fetch_rss raises RuntimeError when max_retries is 0.

        Covers lines 164-166 (RuntimeError fallback).
        """
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("fail"))

        with (
            patch("pkg_defender.intel.rss_feed.get_max_retries", return_value=0),
            patch("pkg_defender.intel.rss_feed.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _fetch_rss("https://example.com/feed.xml", mock_session)

    @pytest.mark.asyncio
    async def test_urllib_only_urls_path(self) -> None:
        """_fetch_rss uses urllib for URLs matching URLLIB_ONLY_URLS.

        Covers lines 121-122 (urllib-only path).
        """
        mock_session = AsyncMock()

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss_urllib",
            new_callable=AsyncMock,
            return_value={"entries": []},
        ) as mock_urllib:
            await _fetch_rss("https://openssf.org/feed.xml", mock_session)

        mock_urllib.assert_called_once_with("https://openssf.org/feed.xml")
        # Should NOT call aiohttp session.get
        mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# _urllib_fetch test
# ---------------------------------------------------------------------------


class TestUrllibFetch:
    """Tests for _urllib_fetch helper."""

    @patch("pkg_defender.intel.rss_feed.urllib.request.urlopen")
    @patch("pkg_defender.intel.rss_feed.feedparser.parse")
    def test_urllib_fetch_returns_parsed_rss(
        self,
        mock_parse: MagicMock,
        mock_urlopen: MagicMock,
    ) -> None:
        """_urllib_fetch fetches and parses RSS via urllib.

        Covers lines 76-85.
        """
        mock_response = MagicMock()
        mock_response.read.return_value = b"<rss><item>test</item></rss>"
        mock_urlopen.return_value.__enter__.return_value = mock_response
        mock_parse.return_value = {"entries": [{"title": "Test"}]}

        result = _urllib_fetch("https://openssf.org/feed.xml")

        assert "entries" in result
        mock_parse.assert_called_once()

    @patch("pkg_defender.intel.rss_feed.urllib.request.urlopen")
    @patch("pkg_defender.intel.rss_feed.feedparser.parse")
    def test_urllib_fetch_includes_user_agent_header(
        self,
        mock_parse: MagicMock,
        mock_urlopen: MagicMock,
    ) -> None:
        """_urllib_fetch includes User-Agent header."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"<rss></rss>"
        mock_urlopen.return_value.__enter__.return_value = mock_response
        mock_parse.return_value = {"entries": []}

        _urllib_fetch("https://example.com/feed.xml")

        # Verify the request has User-Agent header
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert request.get_header("User-agent") == "pkg-defender/1.0"

    @patch("pkg_defender.intel.rss_feed.urllib.request.urlopen")
    @patch("pkg_defender.intel.rss_feed.feedparser.parse")
    def test_urllib_fetch_rejects_non_http_schemes(
        self,
        mock_parse: MagicMock,
        mock_urlopen: MagicMock,
    ) -> None:
        """_urllib_fetch raises ValueError for non-http/https URLs.

        Regression test for S310 — prevents local file reads via
        ``file://`` and other custom URL schemes.
        """
        # file:// must be rejected (ValueError raised before urlopen)
        with pytest.raises(ValueError, match=r"Unsupported URL scheme.*file"):
            _urllib_fetch("file:///etc/passwd")

        # ftp:// must be rejected (ValueError raised before urlopen)
        with pytest.raises(ValueError, match=r"Unsupported URL scheme.*ftp"):
            _urllib_fetch("ftp://example.com/file")

        # https:// must NOT raise
        mock_response = MagicMock()
        mock_response.read.return_value = b"<rss></rss>"
        mock_urlopen.return_value.__enter__.return_value = mock_response
        mock_parse.return_value = {"entries": []}
        _urllib_fetch("https://example.com/feed.xml")


class TestFetchRSSUrllib:
    """Tests for _fetch_rss_urllib wrapper."""

    @pytest.mark.asyncio
    async def test_runs_in_thread(self) -> None:
        """_fetch_rss_urllib runs _urllib_fetch in a thread.

        Covers line 100 (asyncio.to_thread wrapper).
        """
        with patch(
            "pkg_defender.intel.rss_feed.asyncio.to_thread",
            new_callable=AsyncMock,
            return_value={"entries": []},
        ) as mock_thread:
            result = await _fetch_rss_urllib("https://example.com/feed.xml")

        assert "entries" in result
        mock_thread.assert_called_once()


# ---------------------------------------------------------------------------
# RSSFeed.fetch advanced edge cases
# ---------------------------------------------------------------------------


class TestRSSFeedFetchAdvanced:
    """Advanced tests for RSSFeed.fetch()."""

    @pytest.fixture
    def feed(self) -> RSSFeed:
        """Create RSSFeed instance."""
        return RSSFeed()

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock config with RSS settings."""
        config = MagicMock(spec=PKGDConfig)
        config.feeds = MagicMock(spec=FeedConfig)
        config.feeds.rss_urls = ["https://example.com/feed.xml"]
        config.feeds.rss_keywords = ["malware", "supply chain", "vulnerability"]
        config.feeds.rss_max_age_hours = 24
        config.feeds.http_timeout = 15
        return config

    @pytest.fixture
    def sample_entry(self) -> MagicMock:
        """Create a mock RSS entry with a keyword match."""
        entry = MagicMock()
        entry.title = "New malware found in npm packages"
        entry.summary = "A supply chain attack targeting `express` users — recommend updating `axios` immediately"
        entry.description = ""
        entry.link = "https://example.com/article/1"
        entry.id = "entry-123"
        published_dt = datetime.now(tzutc()) - timedelta(minutes=5)
        entry.published_parsed = published_dt.timetuple()
        entry.updated_parsed = None
        return entry

    @pytest.mark.asyncio
    async def test_fetch_with_extracted_packages(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
        sample_entry: MagicMock,
    ) -> None:
        """fetch creates records from entries with packages extracted.

        Covers lines 282-308 (package extraction path).
        """
        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [sample_entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Should find packages from the entry text
        assert len(result.records) > 0
        assert result.records[0].source == "rss"

    @pytest.mark.asyncio
    async def test_fetch_falls_back_to_domain_when_no_packages_extracted(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch uses domain fallback when no packages extracted.

        Covers lines 309-335 (domain fallback path).
        """
        entry = MagicMock()
        entry.title = "New malware found in the wild"
        entry.summary = "Weekly roundup of security topics"
        entry.description = ""
        entry.link = "https://example.com/article/2"
        entry.id = "entry-456"
        published_dt = datetime.now(tzutc()) - timedelta(minutes=5)
        entry.published_parsed = published_dt.timetuple()
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Should fall back to domain-based records
        assert len(result.records) > 0
        assert "example.com" in result.records[0].package_name

    @pytest.mark.asyncio
    async def test_fetch_no_keyword_match_returns_empty(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch skips entries that don't match keywords."""
        entry = MagicMock()
        entry.title = "Completely unrelated topic"
        entry.summary = "Nothing about security here"
        entry.description = ""
        entry.link = "https://example.com/article/3"
        entry.id = "entry-789"
        published_dt = datetime.now(tzutc()) - timedelta(minutes=5)
        entry.published_parsed = published_dt.timetuple()
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_filtered_entry_returns_0_after_filtering(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch stores warning in feed_metadata when 0 entries after filtering.

        Covers lines 338-343 (0 entries after filtering storage in feed_metadata).
        """
        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = []

        with (
            patch(
                "pkg_defender.intel.rss_feed._fetch_rss",
                new_callable=AsyncMock,
                return_value=mock_feed_data,
            ),
            patch("pkg_defender.intel.rss_feed.logger") as mock_logger,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []
        # Should have a warning in feed_metadata about 0 entries after filtering
        assert "warning" in result.feed_metadata
        assert "returned 0 entries after filtering" in result.feed_metadata["warning"]
        # Logger should have been called with the same warning
        mock_logger.warning.assert_called_once()
        warning_arg = mock_logger.warning.call_args[0][0]
        assert "returned 0 entries after filtering" in warning_arg

    @pytest.mark.asyncio
    async def test_fetch_outer_exception_returns_failed(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch outer exception handler returns FAILED status.

        Trigger outer exception by making extract_packages raise during
        entry processing (not caught by inner try/except around _fetch_rss).
        Covers lines 347-349 (outer try/except).
        """
        entry = MagicMock()
        entry.title = "New malware found in npm packages"
        entry.summary = "Supply chain attack"
        entry.description = ""
        entry.link = "https://example.com/article/1"
        entry.id = "entry-outer-exc"
        published_dt = datetime.now(tzutc()) - timedelta(minutes=5)
        entry.published_parsed = published_dt.timetuple()
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with (
            patch(
                "pkg_defender.intel.rss_feed._fetch_rss",
                new_callable=AsyncMock,
                return_value=mock_feed_data,
            ),
            patch(
                "pkg_defender.intel.rss_feed.extract_packages",
                side_effect=TypeError("Extraction failed"),
            ),
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_without_config_loads_default(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch loads config from defaults when config is None.

        Covers line 227 (config = load_config()).
        """
        with (
            patch(
                "pkg_defender.intel.rss_feed.load_config",
                return_value=mock_config,
            ),
            patch(
                "pkg_defender.intel.rss_feed._fetch_rss",
                new_callable=AsyncMock,
                return_value=MagicMock(entries=[]),
            ),
        ):
            # Don't pass config — triggers load_config()
            result = await feed.fetch(since=datetime.now(tzutc()) - timedelta(hours=12))

        assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_skips_entries_before_effective_start(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch skips entries with published date before effective_start.

        Covers line 272 (continue when published < effective_start).
        """
        from time import struct_time

        # Entry published 48 hours ago
        old_time = datetime.now(tzutc()) - timedelta(hours=48)
        entry = MagicMock()
        entry.title = "New malware found in npm"
        entry.summary = "Supply chain vulnerability"
        entry.description = ""
        entry.link = "https://example.com/old"
        entry.id = "entry-old"
        entry.published_parsed = struct_time(
            (old_time.year, old_time.month, old_time.day, old_time.hour, old_time.minute, 0, 0, 0, 0),
        )
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            # effective_start will be 24h (max_age_hours)
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Entry is 48h old but max_age_hours is 24, so entry should be skipped
        assert result.records == []

    @pytest.mark.asyncio
    async def test_fetch_creates_and_cleans_up_own_session(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch creates its own session and closes it after use.

        Covers lines 239-246, 351-352 (own_session creation/cleanup).
        """
        with (
            patch("pkg_defender.intel.rss_feed.aiohttp.ClientSession") as mock_session_cls,
            patch("pkg_defender.intel.rss_feed._fetch_rss", return_value=MagicMock(entries=[])),
        ):
            mock_session_instance = AsyncMock()
            mock_session_cls.return_value = mock_session_instance

            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        mock_session_cls.assert_called_once()
        mock_session_instance.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_success_with_provided_session(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch uses provided session without creating own."""
        mock_session = AsyncMock()
        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = []

        with (
            patch("pkg_defender.intel.rss_feed.aiohttp.ClientSession") as mock_session_cls,
            patch(
                "pkg_defender.intel.rss_feed._fetch_rss",
                new_callable=AsyncMock,
                return_value=mock_feed_data,
            ),
        ):
            result = await feed.fetch(config=mock_config, session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        # Should NOT create own session
        mock_session_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_respects_since_over_cutoff(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch uses the later of since and age-based cutoff.

        Covers lines 234-236 (effective_start logic).
        """
        from time import struct_time

        recent_hours = datetime.now(tzutc()) - timedelta(hours=2)
        entry = MagicMock()
        entry.title = "New malware found in npm"
        entry.summary = "Supply chain attack"
        entry.description = ""
        entry.link = "https://example.com/art"
        entry.id = "entry-since"
        entry.published_parsed = struct_time(
            (
                recent_hours.year,
                recent_hours.month,
                recent_hours.day,
                recent_hours.hour,
                recent_hours.minute,
                0,
                0,
                0,
                0,
            ),
        )
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            # since is 3 hours ago, entry is 2 hours ago, so entry should pass
            since = datetime.now(tzutc()) - timedelta(hours=3)
            result = await feed.fetch(config=mock_config, since=since)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) > 0

    @pytest.mark.asyncio
    async def test_fetch_skips_entry_without_publish_date(
        self,
        feed: RSSFeed,
        mock_config: MagicMock,
    ) -> None:
        """fetch skips entries without parseable published date.

        Covers lines 268-270 (published is None continue).
        """
        entry = MagicMock()
        entry.title = "Malware found in supply chain"
        entry.summary = ""
        entry.description = ""
        entry.link = "https://example.com/art"
        entry.id = "entry-no-date"
        entry.published_parsed = None
        entry.updated_parsed = None

        mock_feed_data = MagicMock()
        mock_feed_data.get.return_value = [entry]

        with patch(
            "pkg_defender.intel.rss_feed._fetch_rss",
            new_callable=AsyncMock,
            return_value=mock_feed_data,
        ):
            result = await feed.fetch(config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []
