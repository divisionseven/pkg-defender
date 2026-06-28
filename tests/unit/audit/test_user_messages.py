"""Tests for user_messages module — informational source label.

Verifies that:
1. informational_source_label returns ' (informational)' for social feeds
2. informational_source_label returns '' for blocking sources
3. Each source in INFORMATIONAL_ONLY_SOURCES is labeled correctly
4. Empty string input returns ''
"""

from __future__ import annotations

from pkg_defender.audit.user_messages import (
    INFORMATIONAL_ONLY_SOURCES,
    informational_source_label,
)


class TestInformationalSourceLabel:
    """Tests for informational_source_label()."""

    def test_mastodon_returns_informational(self) -> None:
        """Mastodon source should be labeled informational."""
        assert informational_source_label("mastodon") == " (informational)"

    def test_reddit_returns_informational(self) -> None:
        """Reddit source should be labeled informational."""
        assert informational_source_label("reddit") == " (informational)"

    def test_rss_returns_informational(self) -> None:
        """RSS source should be labeled informational."""
        assert informational_source_label("rss") == " (informational)"

    def test_x_twitter_returns_informational(self) -> None:
        """X/Twitter source should be labeled informational."""
        assert informational_source_label("x_twitter") == " (informational)"

    def test_osv_returns_empty(self) -> None:
        """OSV source should NOT be labeled informational (it can block)."""
        assert informational_source_label("osv") == ""

    def test_ghsa_returns_empty(self) -> None:
        """GHSA source should NOT be labeled informational (it can block)."""
        assert informational_source_label("ghsa") == ""

    def test_ossf_malicious_returns_empty(self) -> None:
        """ossf_malicious source should NOT be labeled informational (it CAN block)."""
        assert informational_source_label("ossf_malicious") == ""

    def test_empty_string_returns_empty(self) -> None:
        """Empty string source should return empty label."""
        assert informational_source_label("") == ""

    def test_unknown_source_returns_empty(self) -> None:
        """Unknown source should return empty label."""
        assert informational_source_label("nonexistent_feed") == ""

    def test_all_informational_sources_in_frozenset(self) -> None:
        """Every source in INFORMATIONAL_ONLY_SOURCES should return the label."""
        for source in INFORMATIONAL_ONLY_SOURCES:
            assert informational_source_label(source) == " (informational)", (
                f"Source '{source}' is in INFORMATIONAL_ONLY_SOURCES but label returned empty"
            )

    def test_frozenset_has_expected_members(self) -> None:
        """INFORMATIONAL_ONLY_SOURCES should contain exactly the 4 social feeds."""
        assert frozenset({"mastodon", "reddit", "rss", "x_twitter"}) == INFORMATIONAL_ONLY_SOURCES
