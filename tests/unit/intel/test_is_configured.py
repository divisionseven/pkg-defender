"""Tests for the FeedSource.is_configured() implementation."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from pkg_defender.config.settings import FeedConfig, PKGDConfig
from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter
from pkg_defender.intel.base import FeedFetchResult, FeedSource
from pkg_defender.intel.ghsa import GHSAFeed
from pkg_defender.intel.mastodon import MastodonFeed
from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
from pkg_defender.intel.reddit import RedditFeed
from pkg_defender.intel.rss_feed import RSSFeed
from pkg_defender.intel.socket import SocketFeed
from pkg_defender.intel.x_twitter import XTwitterFeed


class TestFeedIsConfigured:
    """Tests for FeedSource.is_configured() implementation."""

    def test_osv_is_configured_always_true(self) -> None:
        """OSV feed is always configured (public API)."""
        feed = OSVFeedAdapter()
        config = PKGDConfig()
        assert feed.is_configured(config) is True

        # Also with empty config
        config = PKGDConfig(feeds=FeedConfig(osv_enabled=False))
        assert feed.is_configured(config) is True

    def test_ghsa_is_configured_always_true(self) -> None:
        """GHSA is always configured (public API)."""
        feed = GHSAFeed()
        config = PKGDConfig()
        assert feed.is_configured(config) is True

        # Even with explicit empty token
        config = PKGDConfig(feeds=FeedConfig(ghsa_token=""))
        assert feed.is_configured(config) is True

    def test_socket_is_configured_with_key(self) -> None:
        """Socket is configured when socket_enabled is True AND socket_api_key is set."""
        feed = SocketFeed()
        config = PKGDConfig(feeds=FeedConfig(socket_enabled=True, socket_api_key="test-key-123"))
        assert feed.is_configured(config) is True

    def test_socket_is_configured_without_key(self) -> None:
        """Socket is NOT configured when socket_api_key is empty."""
        feed = SocketFeed()
        config = PKGDConfig(feeds=FeedConfig(socket_api_key=""))
        assert feed.is_configured(config) is False

    def test_mastodon_is_configured_when_enabled(self) -> None:
        """Mastodon is configured when mastodon_enabled is True."""
        feed = MastodonFeed()
        config = PKGDConfig(feeds=FeedConfig(mastodon_enabled=True))
        assert feed.is_configured(config) is True

    def test_mastodon_is_configured_when_disabled(self) -> None:
        """Mastodon is NOT configured when mastodon_enabled is False."""
        feed = MastodonFeed()
        config = PKGDConfig(feeds=FeedConfig(mastodon_enabled=False))
        assert feed.is_configured(config) is False

    def test_reddit_is_configured_requires_byok_and_credentials(self) -> None:
        """Reddit requires BOTH reddit_enabled=True AND OAuth credentials."""
        feed = RedditFeed()

        # BYOK disabled, no credentials - not configured
        config = PKGDConfig()
        assert feed.is_configured(config) is False

        # BYOK enabled but no credentials - not configured
        config = PKGDConfig(feeds=FeedConfig(reddit_enabled=True))
        assert feed.is_configured(config) is False

        # BYOK enabled with credentials - configured
        config = PKGDConfig(
            feeds=FeedConfig(
                reddit_enabled=True,
                reddit_client_id="test_id",
                reddit_client_secret="test_secret",
            )
        )
        assert feed.is_configured(config) is True

    def test_rss_is_configured_with_urls(self) -> None:
        """RSS is configured when rss_urls is non-empty."""
        feed = RSSFeed()
        config = PKGDConfig(feeds=FeedConfig(rss_urls=["https://example.com/feed.xml"]))
        assert feed.is_configured(config) is True

    def test_rss_is_configured_without_urls(self) -> None:
        """RSS is NOT configured when rss_urls is empty."""
        feed = RSSFeed()
        config = PKGDConfig(feeds=FeedConfig(rss_urls=[]))
        assert feed.is_configured(config) is False

    def test_xtwitter_is_configured_with_token(self) -> None:
        """X/Twitter is configured when x_twitter_bearer_token is set."""
        feed = XTwitterFeed()
        config = PKGDConfig(feeds=FeedConfig(x_twitter_bearer_token="test-token-123"))
        assert feed.is_configured(config) is True

    def test_xtwitter_is_configured_without_token(self) -> None:
        """X/Twitter is NOT configured when x_twitter_bearer_token is empty."""
        feed = XTwitterFeed()
        config = PKGDConfig(feeds=FeedConfig(x_twitter_bearer_token=""))
        assert feed.is_configured(config) is False

    def test_npm_advisory_is_configured_when_enabled(self) -> None:
        """npm Advisory is configured when npm_advisory_enabled is True."""
        feed = NpmAdvisoryFeed()
        config = PKGDConfig(feeds=FeedConfig(npm_advisory_enabled=True))
        assert feed.is_configured(config) is True

    def test_npm_advisory_is_configured_when_disabled(self) -> None:
        """npm Advisory is NOT configured when npm_advisory_enabled is False."""
        feed = NpmAdvisoryFeed()
        config = PKGDConfig(feeds=FeedConfig(npm_advisory_enabled=False))
        assert feed.is_configured(config) is False


class TestFeedIsConfiguredEdgeCases:
    """Edge case tests for is_configured()."""

    def test_rss_with_default_urls_is_configured(self) -> None:
        """RSS with default (non-empty) URLs is configured."""
        feed = RSSFeed()
        config = PKGDConfig()
        # Default FeedConfig has non-empty rss_urls
        assert feed.is_configured(config) is True

    def test_socket_with_whitespace_key_is_not_configured(self) -> None:
        """Socket with whitespace-only key is NOT configured."""
        feed = SocketFeed()
        config = PKGDConfig(feeds=FeedConfig(socket_api_key="   "))
        assert feed.is_configured(config) is False

    def test_xtwitter_with_whitespace_token_is_not_configured(self) -> None:
        """X/Twitter with whitespace-only token is NOT configured."""
        feed = XTwitterFeed()
        config = PKGDConfig(feeds=FeedConfig(x_twitter_bearer_token="   \t\n  "))
        assert feed.is_configured(config) is False


class TestConstructorInjectedConfig:
    """Tests for config injection via constructor."""

    def test_aggregator_passes_config_to_feeds(self) -> None:
        """FeedAggregator passes config to feed.fetch()."""
        import sqlite3

        # Create a mock feed that records what config it receives
        received_config: list[PKGDConfig | None] = []

        class _ConfigTrackingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "test-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            def is_configured(self, config: PKGDConfig) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                assert config is not None
                received_config.append(config)
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

        # Create a temporary DB path
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = Path(tmp.name)

        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-80000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.close()  # Close so FeedAggregator can open it properly

        # Create custom config
        custom_config = PKGDConfig(feeds=FeedConfig(ghsa_token="test-token"))

        # Create aggregator with config
        feed = _ConfigTrackingFeed()
        agg = FeedAggregator([feed], db_path, config=custom_config)

        # Run sync
        asyncio.run(agg.sync_all())

        # Verify config was passed to feed
        assert len(received_config) == 1
        cfg = received_config[0]
        assert cfg is not None
        assert cfg is custom_config
        assert cfg.feeds.ghsa_token == "test-token"

        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    def test_injected_config_reaches_feed_during_sync(self) -> None:
        """When config is injected, feed uses it instead of load_config()."""
        import sqlite3

        # Create a mock feed that tracks config usage
        used_configs: list[PKGDConfig] = []

        class _ConfigCapturingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "test-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            def is_configured(self, config: PKGDConfig) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                if config is not None:
                    used_configs.append(config)
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

        # Create a temporary DB path
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            temp_db_path = Path(tmp.name)

        conn = sqlite3.connect(str(temp_db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-80000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.close()  # Close so FeedAggregator can open it properly

        # Create aggregator with injected config that differs from defaults
        injected_config = PKGDConfig()
        injected_config.feeds.socket_api_key = "injected-key"

        feed = _ConfigCapturingFeed()
        agg = FeedAggregator([feed], temp_db_path, config=injected_config)

        asyncio.run(agg.sync_all())

        # Verify injected config was used
        assert len(used_configs) == 1
        assert used_configs[0].feeds.socket_api_key == "injected-key"

        # Cleanup
        temp_db_path.unlink(missing_ok=True)


class TestNpmAsyncFix:
    """Tests for async subprocess in npm_advisory."""

    def test_fetch_invokes_npm_audit_via_async_subprocess(self) -> None:
        """fetch() uses asyncio.create_subprocess_exec, not subprocess.run."""
        from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed

        feed = NpmAdvisoryFeed()

        # Mock the subprocess call
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b'{"vulnerabilities": {}}', b""))

        async def _mock_wait_for(coro: Any, timeout: float) -> Any:
            result = await coro  # consume the coroutine to prevent orphaned warning
            return result

        with (
            patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ) as mock_subprocess,
            patch("asyncio.wait_for", side_effect=_mock_wait_for),
        ):
            asyncio.run(feed.fetch())

            # Verify async subprocess was used, not sync subprocess.run
            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args
            assert call_args is not None
            # First positional arg should be 'npm'
            assert call_args[0][0] == "npm"

    def test_npm_fetch_does_not_block_event_loop(self) -> None:
        """Multiple npm fetches can run concurrently."""

        from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed

        # Track concurrent executions
        active_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        async def mock_subprocess(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal active_count, max_concurrent
            async with lock:
                active_count += 1
                if active_count > max_concurrent:
                    max_concurrent = active_count

            # Simulate some async work
            await asyncio.sleep(0.01)

            async with lock:
                active_count -= 1

            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b'{"vulnerabilities": {}}', b""))
            return mock_proc

        async def run_test() -> tuple[tuple[FeedFetchResult, FeedFetchResult, FeedFetchResult], int]:
            with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
                feed = NpmAdvisoryFeed()

                # Run multiple fetches concurrently
                results = await asyncio.gather(
                    feed.fetch(),
                    feed.fetch(),
                    feed.fetch(),
                )

                return results, max_concurrent

        # Run the async test
        results, concurrent_count = asyncio.run(run_test())

        # All should complete without blocking
        assert len(results) == 3
        # Should have run all 3 concurrently (not sequentially)
        assert concurrent_count >= 3
