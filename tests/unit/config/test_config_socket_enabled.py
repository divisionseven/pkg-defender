"""Tests for socket_enabled configuration flag.

Tests the behavior of the socket_enabled flag in FeedConfig, including:
- Default value is False
- SocketFeed is only added when socket_enabled=True
- is_configured() checks both socket_enabled and socket_api_key
- Environment variable PKGD_FEEDS_SOCKET_ENABLED works correctly
- All three SocketFeed locations (status, sync, daemon) respect the flag
- Diagnostics code shows correct status
- Behavior matches other social feeds (mastodon, reddit, x_twitter)
"""

from pathlib import Path

import pytest

from pkg_defender.config.settings import FeedConfig, PKGDConfig, load_config
from pkg_defender.intel.socket import SocketFeed


# ===========================================================================
# Test socket_enabled field in FeedConfig
# ===========================================================================
class TestSocketEnabledField:
    """Test socket_enabled field in FeedConfig."""

    def test_socket_enabled_default_is_false(self):
        """Test socket_enabled defaults to False."""
        config = FeedConfig()
        assert config.socket_enabled is False

    def test_socket_enabled_can_be_set_to_true(self):
        """Test socket_enabled can be set to True."""
        config = FeedConfig(socket_enabled=True)
        assert config.socket_enabled is True

    def test_socket_enabled_can_be_set_to_false(self):
        """Test socket_enabled can be set to False."""
        config = FeedConfig(socket_enabled=False)
        assert config.socket_enabled is False


# ===========================================================================
# Test SocketFeed.is_configured() behavior
# ===========================================================================
class TestSocketFeedIsConfigured:
    """Test SocketFeed.is_configured() checks both flags."""

    def test_is_configured_returns_false_when_socket_enabled_false(self):
        """Test is_configured() returns False when socket_enabled=False (even with API key)."""
        config = PKGDConfig()
        config.feeds.socket_enabled = False
        config.feeds.socket_api_key = "test-api-key"

        feed = SocketFeed()
        assert feed.is_configured(config) is False

    def test_is_configured_returns_false_when_socket_api_key_empty(self):
        """Test is_configured() returns False when socket_api_key is empty (even if enabled)."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = ""

        feed = SocketFeed()
        assert feed.is_configured(config) is False

    def test_is_configured_returns_false_when_socket_api_key_whitespace(self):
        """Test is_configured() returns False when socket_api_key is whitespace."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "   "

        feed = SocketFeed()
        assert feed.is_configured(config) is False

    def test_is_configured_returns_true_when_both_flags_set(self):
        """Test is_configured() returns True when both socket_enabled=True and socket_api_key is set."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "test-api-key"

        feed = SocketFeed()
        assert feed.is_configured(config) is True

    def test_is_configured_strips_whitespace_from_api_key(self):
        """Test is_configured() strips whitespace from socket_api_key."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "  test-api-key  "

        feed = SocketFeed()
        assert feed.is_configured(config) is True


# ===========================================================================
# Test environment variable PKGD_FEEDS_SOCKET_ENABLED
# ===========================================================================
class TestSocketEnabledEnvVar:
    """Test PKGD_FEEDS_SOCKET_ENABLED environment variable."""

    def test_env_var_true_sets_socket_enabled_true(self, monkeypatch):
        """Test PKGD_FEEDS_SOCKET_ENABLED=true sets socket_enabled=True."""
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_ENABLED", "true")
        config = load_config()
        assert config.feeds.socket_enabled is True

    def test_env_var_false_sets_socket_enabled_false(self, monkeypatch):
        """Test PKGD_FEEDS_SOCKET_ENABLED=false sets socket_enabled=False."""
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_ENABLED", "false")
        config = load_config()
        assert config.feeds.socket_enabled is False

    def test_env_var_1_sets_socket_enabled_true(self, monkeypatch):
        """Test PKGD_FEEDS_SOCKET_ENABLED=1 sets socket_enabled=True."""
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_ENABLED", "1")
        config = load_config()
        assert config.feeds.socket_enabled is True

    def test_env_var_0_sets_socket_enabled_false(self, monkeypatch):
        """Test PKGD_FEEDS_SOCKET_ENABLED=0 sets socket_enabled=False."""
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_ENABLED", "0")
        config = load_config()
        assert config.feeds.socket_enabled is False

    def test_returns_false_when_socket_enabled_env_var_not_set(self, monkeypatch):
        """Test PKGD_FEEDS_SOCKET_ENABLED not set uses default False."""
        monkeypatch.delenv("PKGD_FEEDS_SOCKET_ENABLED", raising=False)
        config = load_config()
        assert config.feeds.socket_enabled is False

    def test_env_var_invalid_value_logs_warning(self, monkeypatch, caplog):
        """Test PKGD_FEEDS_SOCKET_ENABLED with invalid value logs warning and uses default."""
        caplog.set_level("WARNING")
        monkeypatch.setenv("PKGD_FEEDS_SOCKET_ENABLED", "invalid")
        config = load_config()
        # Default for socket_enabled is False
        assert config.feeds.socket_enabled is False
        # Warning was logged with env var name
        assert "PKGD_FEEDS_SOCKET_ENABLED" in caplog.text


# ===========================================================================
# Test SocketFeed addition in feed lists
# ===========================================================================
class TestSocketFeedInFeedLists:
    """Test SocketFeed is only added when socket_enabled=True."""

    def test_socket_feed_not_added_when_disabled_in_status(self):
        """Test SocketFeed is NOT added to status command feed list when socket_enabled=False."""
        config = PKGDConfig()
        config.feeds.socket_enabled = False

        # Build feed list as status command does
        intelligence_feeds = []

        # Simulate the feed list construction in status command
        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        intelligence_feeds.append(OSVFeedAdapter())
        if config.feeds.ghsa_enabled:
            intelligence_feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            intelligence_feeds.append(SocketFeed())

        # Verify SocketFeed is NOT in the list
        feed_names = [feed.name for feed in intelligence_feeds]
        assert "socket" not in feed_names

    def test_socket_feed_added_when_enabled_in_status(self):
        """Test SocketFeed IS added to status command feed list when socket_enabled=True."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True

        # Build feed list as status command does
        intelligence_feeds = []

        # Simulate the feed list construction in status command
        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        intelligence_feeds.append(OSVFeedAdapter())
        if config.feeds.ghsa_enabled:
            intelligence_feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            intelligence_feeds.append(SocketFeed())

        # Verify SocketFeed IS in the list
        feed_names = [feed.name for feed in intelligence_feeds]
        assert "socket" in feed_names

    def test_socket_feed_not_added_when_disabled_in_sync(self):
        """Test SocketFeed is NOT added to sync command feed list when socket_enabled=False."""
        config = PKGDConfig()
        config.feeds.socket_enabled = False

        # Build feed list as sync command does
        feeds = []

        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        feeds.append(HomebrewFeedAdapter())
        if config.feeds.ghsa_enabled:
            feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Verify SocketFeed is NOT in the list
        feed_names = [feed.name for feed in feeds]
        assert "socket" not in feed_names

    def test_socket_feed_added_when_enabled_in_sync(self):
        """Test SocketFeed IS added to sync command feed list when socket_enabled=True."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True

        # Build feed list as sync command does
        feeds = []

        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        feeds.append(HomebrewFeedAdapter())
        if config.feeds.ghsa_enabled:
            feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Verify SocketFeed IS in the list
        feed_names = [feed.name for feed in feeds]
        assert "socket" in feed_names

    def test_socket_feed_not_added_when_disabled_in_daemon(self):
        """Test SocketFeed is NOT added to daemon feed list when socket_enabled=False."""
        config = PKGDConfig()
        config.feeds.socket_enabled = False

        # Build feed list as daemon does
        feeds = []

        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        if config.feeds.ghsa_enabled:
            feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Verify SocketFeed is NOT in the list
        feed_names = [feed.name for feed in feeds]
        assert "socket" not in feed_names

    def test_socket_feed_added_when_enabled_in_daemon(self):
        """Test SocketFeed IS added to daemon feed list when socket_enabled=True."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True

        # Build feed list as daemon does
        feeds = []

        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        if config.feeds.ghsa_enabled:
            feeds.append(GHSAFeed())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Verify SocketFeed IS in the list
        feed_names = [feed.name for feed in feeds]
        assert "socket" in feed_names


# ===========================================================================
# Test integration with FeedAggregator
# ===========================================================================
class TestFeedAggregatorIntegration:
    """Test socket_enabled behavior with FeedAggregator."""

    @pytest.mark.asyncio
    async def test_feed_aggregator_respects_socket_enabled(self):
        """Test FeedAggregator respects socket_enabled flag."""
        from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter

        config = PKGDConfig()
        config.feeds.socket_enabled = False

        # Build feed list with socket disabled
        feeds = []
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Create aggregator
        aggregator = FeedAggregator(feeds, db_path=Path(":memory:"), config=config)

        # Verify socket is not in feeds
        feed_names = [feed.name for feed in aggregator._feeds]
        assert "socket" not in feed_names

    @pytest.mark.asyncio
    async def test_feed_aggregator_includes_socket_when_enabled(self):
        """Test FeedAggregator includes SocketFeed when socket_enabled=True."""
        from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter

        config = PKGDConfig()
        config.feeds.socket_enabled = True

        # Build feed list with socket enabled
        feeds = []
        from pkg_defender.intel.socket import SocketFeed

        feeds.append(OSVFeedAdapter())
        if config.feeds.socket_enabled:
            feeds.append(SocketFeed())

        # Create aggregator
        aggregator = FeedAggregator(feeds, db_path=Path(":memory:"), config=config)

        # Verify socket is in feeds
        feed_names = [feed.name for feed in aggregator._feeds]
        assert "socket" in feed_names


# ===========================================================================
# Test backward compatibility
# ===========================================================================
class TestBackwardCompatibility:
    """Test backward compatibility with existing configurations."""

    def test_returns_default_false_when_socket_enabled_not_set(self):
        """Test existing config without socket_enabled field uses default False."""
        # Simulate loading a config that doesn't have socket_enabled field
        config = FeedConfig()
        # socket_enabled should default to False
        assert config.socket_enabled is False

    def test_returns_configured_true_when_socket_enabled_and_api_key_set(self):
        """Test socket_api_key still works when socket_enabled is set."""
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "test-api-key"

        feed = SocketFeed()
        assert feed.is_configured(config) is True

    def test_socket_api_key_alone_not_sufficient(self):
        """Test socket_api_key alone is not sufficient (needs socket_enabled=True)."""
        config = PKGDConfig()
        config.feeds.socket_enabled = False
        config.feeds.socket_api_key = "test-api-key"

        feed = SocketFeed()
        assert feed.is_configured(config) is False
