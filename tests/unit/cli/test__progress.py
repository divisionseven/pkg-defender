"""Tests for format_feed_message and feed status message descriptors.

Targets: _progress.FEED_DESCRIPTIVE_MESSAGES, _progress.format_feed_message

Coverage goals:
  - All 10 feeds: N>0 and N==0 paths (at least 5 representative ones)
  - Unknown feed fallback: N>0 singular, N>0 plural, N==0
  - Display name mapping (x_twitter → twitter, npm_advisory → npm)
  - OSV with N=1 (singular in numeric formatting)
"""

from __future__ import annotations

import pytest

from pkg_defender.cli._progress import FEED_DESCRIPTIVE_MESSAGES, format_feed_message


class TestFormatFeedMessage:
    """Tests for format_feed_message()."""

    # ------------------------------------------------------------------
    # Known feeds — N > 0
    # ------------------------------------------------------------------

    def test_osv_with_records(self) -> None:
        """OSV with N>0: shows comma-formatted count."""
        result = format_feed_message("osv", 1234)
        expected = "osv: 1,234 vulnerabilities loaded"
        assert result == expected

    def test_osv_single_record(self) -> None:
        """OSV with N=1: uses 'vulnerabilities loaded' (no singular variation)."""
        result = format_feed_message("osv", 1)
        expected = "osv: 1 vulnerabilities loaded"
        assert result == expected

    def test_ossf_malicious_with_records(self) -> None:
        """ossf_malicious with N>0: shows count."""
        result = format_feed_message("ossf_malicious", 5)
        assert result == "ossf_malicious: 5 malicious package records loaded"

    def test_ghsa_with_records(self) -> None:
        """ghsa with N>0: shows advisories."""
        result = format_feed_message("ghsa", 42)
        assert result == "ghsa: 42 advisories updated since last sync"

    def test_homebrew_vulnerable(self) -> None:
        """homebrew with N>0: shows VULNERABILITIES FOUND."""
        result = format_feed_message("homebrew", 3)
        assert result == "homebrew: 3 VULNERABILITIES FOUND in installed packages"

    def test_rss_with_records(self) -> None:
        """rss with N>0: shows entries matched."""
        result = format_feed_message("rss", 10)
        assert result == "rss: 10 entries matched keywords"

    def test_mastodon_with_records(self) -> None:
        """mastodon with N>0: shows posts mentioning packages."""
        result = format_feed_message("mastodon", 2)
        assert result == "mastodon: 2 posts mentioning packages"

    def test_reddit_with_records(self) -> None:
        """reddit with N>0: shows posts matching keywords."""
        result = format_feed_message("reddit", 7)
        assert result == "reddit: 7 posts matching keywords"

    def test_socket_with_records(self) -> None:
        """socket with N>0: bulk fetch not supported message."""
        result = format_feed_message("socket", 99)
        assert result == "socket: bulk fetch not supported"

    # ------------------------------------------------------------------
    # Known feeds — N == 0
    # ------------------------------------------------------------------

    def test_osv_zero_records(self) -> None:
        """OSV with N==0: shows up-to-date message."""
        result = format_feed_message("osv", 0)
        assert result == "osv: database unchanged \u2014 already up to date"

    def test_ossf_malicious_zero_records(self) -> None:
        """ossf_malicious with N==0: data unchanged."""
        result = format_feed_message("ossf_malicious", 0)
        assert result == "ossf_malicious: data unchanged \u2014 already up to date"

    def test_ghsa_zero_records(self) -> None:
        """ghsa with N==0: no advisories updated."""
        result = format_feed_message("ghsa", 0)
        assert result == "ghsa: no advisories updated since last sync"

    def test_homebrew_clean(self) -> None:
        """homebrew with N==0: no vulnerabilities."""
        result = format_feed_message("homebrew", 0)
        assert result == "homebrew: no vulnerabilities found in installed packages"

    def test_rss_zero_records(self) -> None:
        """rss with N==0: no entries matched."""
        result = format_feed_message("rss", 0)
        assert result == "rss: no entries matched keywords"

    def test_mastodon_zero_records(self) -> None:
        """mastodon with N==0: no package mentions."""
        result = format_feed_message("mastodon", 0)
        assert result == "mastodon: no package mentions found"

    def test_reddit_zero_records(self) -> None:
        """reddit with N==0: no posts matching."""
        result = format_feed_message("reddit", 0)
        assert result == "reddit: no posts matching keywords"

    def test_socket_zero_records(self) -> None:
        """socket with N==0: bulk fetch not supported message."""
        result = format_feed_message("socket", 0)
        assert result == "socket: bulk fetch not supported"

    # ------------------------------------------------------------------
    # Display name mapping
    # ------------------------------------------------------------------

    def test_x_twitter_display_name_with_records(self) -> None:
        """x_twitter displays as 'twitter' in output."""
        result = format_feed_message("x_twitter", 5)
        assert result == "twitter: 5 tweets mentioning packages"

    def test_x_twitter_display_name_zero_records(self) -> None:
        """x_twitter with N==0 displays as 'twitter'."""
        result = format_feed_message("x_twitter", 0)
        assert result == "twitter: no matching tweets found"

    def test_npm_advisory_display_name_with_records(self) -> None:
        """npm_advisory displays as 'npm' in output."""
        result = format_feed_message("npm_advisory", 3)
        assert result == "npm: 3 advisories found"

    def test_npm_advisory_display_name_zero_records(self) -> None:
        """npm_advisory with N==0 displays as 'npm'."""
        result = format_feed_message("npm_advisory", 0)
        assert result == "npm: no advisories found"

    # ------------------------------------------------------------------
    # Unknown feed fallback
    # ------------------------------------------------------------------

    def test_unknown_feed_singular(self) -> None:
        """Unknown feed with N=1: '1 record' (singular)."""
        result = format_feed_message("custom_feed", 1)
        assert result == "custom_feed: 1 record"

    def test_unknown_feed_plural(self) -> None:
        """Unknown feed with N>1: 'N records' (plural)."""
        result = format_feed_message("custom_feed", 3)
        assert result == "custom_feed: 3 records"

    def test_unknown_feed_large_count(self) -> None:
        """Unknown feed with large N: comma-formatted count."""
        result = format_feed_message("custom_feed", 1500)
        assert result == "custom_feed: 1,500 records"

    def test_unknown_feed_zero_records(self) -> None:
        """Unknown feed with N=0: '0 records'."""
        result = format_feed_message("custom_feed", 0)
        assert result == "custom_feed: 0 records"

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_negative_count(self) -> None:
        """Negative count follows fallback path with plural (technically >0)."""
        result = format_feed_message("custom", -5)
        # N=-5 is not >0, so it takes the N==0 path
        assert result == "custom: 0 records"

    def test_empty_feed_name(self) -> None:
        """Empty string as feed name."""
        result = format_feed_message("", 5)
        assert result == ": 5 records"

    @pytest.mark.parametrize("feed_name", list(FEED_DESCRIPTIVE_MESSAGES.keys()))
    def test_all_feeds_at_least_render_with_count(self, feed_name: str) -> None:
        """Every known feed renders without error at N=1."""
        result = format_feed_message(feed_name, 1)
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.parametrize("feed_name", list(FEED_DESCRIPTIVE_MESSAGES.keys()))
    def test_all_feeds_at_least_render_at_zero(self, feed_name: str) -> None:
        """Every known feed renders without error at N=0."""
        result = format_feed_message(feed_name, 0)
        assert isinstance(result, str)
        assert len(result) > 0
