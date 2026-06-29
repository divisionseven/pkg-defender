"""Fixed tests to push intel/ coverage higher."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# =============================================================================
# Tests for intel/ source functions
# =============================================================================


class TestHomebrewNormalizeVersion:
    """Test _normalize_brew_version function."""

    @pytest.mark.parametrize(
        "input_version,expected",
        [
            ("1.9.2_1", "1.9.2"),
            ("1.5.7_2", "1.5.7"),
            ("3.0.0", "3.0.0"),
            ("1.0.0_10", "1.0.0"),
            ("_1", "_1"),  # Only underscore, no version before it
            ("1.0", "1.0"),
            ("2.0_0", "2.0"),
        ],
        ids=lambda x: f"version-{x[0]}" if isinstance(x, tuple) else f"version-{x}",
    )
    def test_normalize_brew_version(self, input_version: str, expected: str) -> None:
        """AAA: Test version normalization for Homebrew versions."""
        from pkg_defender.intel.feeds.homebrew import _normalize_brew_version

        result = _normalize_brew_version(input_version)
        assert result == expected


class TestHomebrewGetInstalledFormulae:
    """Test get_installed_formulae function."""

    @patch("pkg_defender.intel.feeds.homebrew.shutil.which")
    def test_brew_not_installed(self, mock_which: MagicMock) -> None:
        """AAA: Raise BrewNotInstalledError when brew not found."""
        from pkg_defender.intel.feeds.homebrew import BrewNotInstalledError, get_installed_formulae

        mock_which.return_value = None
        with pytest.raises(BrewNotInstalledError):
            get_installed_formulae()


class TestHomebrewParseFormula:
    """Test _parse_brew_formula function."""

    def test_parse_valid_formula(self) -> None:
        """AAA: Parse valid formula with all fields."""
        from pkg_defender.intel.feeds.homebrew import _parse_brew_formula

        formula = {
            "name": "git",
            "installed": [{"version": "2.39.0"}],
            "homepage": "https://git-scm.com",
            "tap": "homebrew/core",
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        name, repo_url, version = result
        assert name == "git"
        assert "http" in repo_url
        assert version == "2.39.0"


class TestHomebrewFeedAdapter:
    """Test HomebrewFeedAdapter class."""

    def test_feed_adapter_name(self) -> None:
        """AAA: Check feed adapter name."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        assert adapter.name == "homebrew"

    def test_feed_adapter_supports_incremental(self) -> None:
        """AAA: Check supports_incremental returns False."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        assert adapter.supports_incremental is False


class TestXTwitterBuildSearchQuery:
    """Test _build_search_query function."""

    def test_build_search_query(self) -> None:
        """AAA: Build search query from keywords."""
        from pkg_defender.intel.x_twitter import _build_search_query

        result = _build_search_query(["supply chain"])
        assert "OR" in result or "supply chain" in result
        assert "lang:en" in result
        assert "-is:retweet" in result


class TestRssFeedConvertPublished:
    """Test _convert_published function."""

    def test_convert_no_date(self) -> None:
        """AAA: Return None when no date available."""
        from pkg_defender.intel.rss_feed import _convert_published

        mock_entry = MagicMock()
        mock_entry.published_parsed = None
        mock_entry.updated_parsed = None

        result = _convert_published(mock_entry)
        assert result is None


class TestGhsaParseAdvisory:
    """Test _parse_advisory function."""

    def test_parse_advisory_with_vulns(self) -> None:
        """AAA: Parse advisory with vulnerabilities."""
        from pkg_defender.intel.ghsa import _parse_advisory

        advisory = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "summary": "Test vulnerability",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
            "published_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-16T10:30:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "axios", "ecosystem": "npm"},
                    "vulnerable_version_range": "<1.6.0",
                    "first_patched_version": "1.6.0",
                }
            ],
        }

        result = _parse_advisory(advisory)
        assert isinstance(result, list)


class TestGhsaGetSeverity:
    """Test _get_severity function."""

    @pytest.mark.parametrize(
        "input_severity,expected",
        [
            ("critical", "CRITICAL"),
            ("high", "HIGH"),
            ("medium", "MEDIUM"),
            ("low", "LOW"),
            ("unknown", "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
        ids=lambda x: f"sev-{x[0]}" if isinstance(x, tuple) else f"sev-{x}",
    )
    def test_get_severity(self, input_severity: str | None, expected: str) -> None:
        """AAA: Map GHSA severity to internal severity."""
        from pkg_defender.intel.ghsa import _get_severity

        result = _get_severity(input_severity)
        assert result == expected


class TestOsvParseVuln:
    """Test _parse_osv_vuln function."""

    def test_parse_vuln_basic(self) -> None:
        """AAA: Parse basic OSV vulnerability."""
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        vuln = {
            "id": "OSV-2023-1234",
            "summary": "Test vulnerability",
            "published": "2024-01-15T10:30:00Z",
            "modified": "2024-01-16T10:30:00Z",
            "affected": [
                {
                    "package": {"name": "axios", "ecosystem": "npm"},
                    "versions": ["1.0.0", "1.5.0"],
                }
            ],
        }

        result = _parse_osv_vuln(vuln, ecosystem="npm", package="axios")
        assert result.id == "osv:OSV-2023-1234:npm"
        assert result.package_name == "axios"


class TestOsvCvssToSeverity:
    """Test cvss_to_severity function."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (9.5, "CRITICAL"),
            (7.5, "HIGH"),
            (5.0, "MEDIUM"),
            (1.0, "LOW"),
            (0.0, "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
        ids=lambda x: f"cvss-{x[0]}" if isinstance(x, tuple) else f"cvss-{x}",
    )
    def test_cvss_to_severity(self, score: float | None, expected: str) -> None:
        """AAA: Map CVSS score to severity."""
        from pkg_defender.intel.feeds._osv_parser import cvss_to_severity

        result = cvss_to_severity(score)
        assert result == expected


class TestSocketScoreToSeverity:
    """Test _score_to_severity function."""

    @pytest.mark.parametrize(
        "supply_chain_risk,malware,expected",
        [
            (0.5, 0.9, "CRITICAL"),  # malware >= 0.8
            (0.95, 0.3, "HIGH"),  # supply_chain >= 0.9
            (0.8, 0.3, "MEDIUM"),  # supply_chain >= 0.7
            (0.5, 0.3, "UNKNOWN"),  # below thresholds
        ],
        ids=lambda x: f"score-{x[0]}-{x[1]}" if isinstance(x, tuple) else f"score-{x}",
    )
    def test_score_to_severity(self, supply_chain_risk: float, malware: float, expected: str) -> None:
        """AAA: Map Socket scores to severity."""
        from pkg_defender.intel.socket import _score_to_severity

        result = _score_to_severity(supply_chain_risk, malware)
        assert result == expected


# Async tests with proper mocking


class TestHomebrewCheckPackage:
    """Test check_brew_package function."""

    @pytest.mark.asyncio
    async def test_check_package_success(self) -> None:
        """AAA: Successfully check a brew package."""
        from pkg_defender.intel.feeds.homebrew import check_brew_package

        mock_session = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={"vulns": []})
        # Must use MagicMock for session.post — AsyncMock returns a coroutine
        # when called, but ``async with`` expects an async context manager
        # (not a coroutine).  The per-instance __aenter__ override IS
        # respected by MagicMock (unlike AsyncMock), so ``async with resp
        # as r: r is resp`` holds and all configured attrs are visible.
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        mock_session.post = MagicMock(return_value=mock_resp)

        result = await check_brew_package("git", "2.39.0", "https://github.com/git/git", mock_session)
        assert isinstance(result, list)


class TestXTwitterApiGet:
    """Test _api_get function."""

    @pytest.mark.asyncio
    async def test_api_get_success(self) -> None:
        """AAA: Successfully GET from Twitter API."""
        from pkg_defender.intel.x_twitter import _api_get

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={"data": []})
        mock_session.get = AsyncMock(return_value=mock_resp)

        result = await _api_get("https://api.twitter.com/2/tweets/search/recent", {}, "fake_token", mock_session)
        assert isinstance(result, dict)


class TestRssFeedFetchRss:
    """Test _fetch_rss function."""

    @pytest.mark.asyncio
    async def test_fetch_rss_success(self) -> None:
        """AAA: Successfully fetch RSS with aiohttp."""
        from pkg_defender.intel.rss_feed import _fetch_rss

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.read = AsyncMock(return_value=b"<rss><channel><item><title>Test</title></item></channel></rss>")
        mock_session.get = AsyncMock(return_value=mock_resp)

        result = await _fetch_rss("https://example.com/feed.xml", mock_session)
        assert isinstance(result, dict)


class TestOsvFetch:
    """Test _osv_fetch function."""

    @pytest.mark.asyncio
    async def test_osv_fetch_success(self) -> None:
        """AAA: Successfully fetch from OSV API."""
        from pkg_defender.intel.feeds.osv import _osv_fetch

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={"vulns": []})
        mock_session.post = AsyncMock(return_value=mock_resp)

        result = await _osv_fetch(
            "https://api.osv.dev/v1/query",
            method="POST",
            json_body={"package": {"name": "axios"}},
            session=mock_session,
        )
        assert isinstance(result, dict)


# Test Reddit functions


class TestRedditComputeEngagement:
    """Test _compute_engagement_confidence function."""

    def test_high_engagement(self) -> None:
        """AAA: Boost confidence for high engagement."""
        from pkg_defender.intel.reddit import _compute_engagement_confidence

        post = {"ups": 300, "num_comments": 100}
        result = _compute_engagement_confidence(post)
        assert result > 0.45  # Should be boosted

    def test_low_engagement(self) -> None:
        """AAA: Normal confidence for low engagement."""
        from pkg_defender.intel.reddit import _compute_engagement_confidence

        post = {"ups": 5, "num_comments": 2}
        result = _compute_engagement_confidence(post)
        assert result == 0.45


# Test NPM advisory feed


class TestNpmAdvisoryFeed:
    """Test NpmAdvisoryFeed class."""

    def test_feed_name(self) -> None:
        """AAA: Check feed name."""
        from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed

        feed = NpmAdvisoryFeed()
        assert feed.name == "npm_advisory"

    def test_feed_supports_incremental(self) -> None:
        """AAA: Check supports_incremental."""
        from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed

        feed = NpmAdvisoryFeed()
        assert feed.supports_incremental is True


# Test Mastodon functions


class TestMastodonGet:
    """Test _mastodon_get function."""

    @pytest.mark.asyncio
    async def test_mastodon_get_success(self) -> None:
        """AAA: Successfully GET from Mastodon API."""
        from pkg_defender.intel.mastodon import _mastodon_get

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value=[])
        mock_session.get = AsyncMock(return_value=mock_resp)

        result = await _mastodon_get("https://instance.com/api/v1/timelines/tag/test", mock_session)
        assert isinstance(result, (dict, list))


# =============================================================================
# Manager adapter tests
# =============================================================================


class TestUnifiedManagerAdapters:
    """Test unified manager adapters."""

    def test_npm_unified_adapter_name(self) -> None:
        """AAA: Check NpmUnifiedAdapter ecosystem."""
        from pkg_defender.registry.npm_unified import NpmUnifiedAdapter

        adapter = NpmUnifiedAdapter()
        assert adapter.ecosystem == "npm"

    def test_brew_unified_adapter_name(self) -> None:
        """AAA: Check BrewUnifiedAdapter ecosystem."""
        from pkg_defender.registry.brew_unified import BrewUnifiedAdapter

        adapter = BrewUnifiedAdapter()
        assert adapter.ecosystem == "homebrew"

    def test_pip_unified_adapter_name(self) -> None:
        """AAA: Check PyPIUnifiedAdapter ecosystem."""
        from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter

        adapter = PyPIUnifiedAdapter()
        assert adapter.ecosystem == "pypi"


class TestUnifiedManagerFetchReleaseDate:
    """Test fetch_release_date() methods on unified adapters."""

    @pytest.mark.asyncio
    async def test_npm_unified_fetch_release_date_http_error(self) -> None:
        """AAA: Return None on HTTP error."""
        from pkg_defender.registry.npm_unified import NpmUnifiedAdapter

        adapter = NpmUnifiedAdapter()
        mock_session = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={})
        # The code uses sess.request() internally (via _http.py), not sess.get().
        # MagicMock for session.request — AsyncMock returns a coroutine, but
        # ``async with`` expects an async context manager, not a coroutine.
        # MagicMock's per-instance __aenter__ override IS respected (unlike
        # AsyncMock), so the configured attrs (raise_for_status, json, status)
        # are visible inside the ``async with`` block.
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(return_value=mock_resp)

        result = await adapter.fetch_release_date("nonexistent", "1.0.0", mock_session)
        assert result is None


# =============================================================================
# Adapter tests
# =============================================================================


class TestAdapters:
    """Test registry adapters."""

    def test_pypi_adapter_ecosystem(self) -> None:
        """AAA: Check registry PyPI adapter ecosystem."""
        from pkg_defender.registry.pypi import PyPIAdapter as RegistryPyPIAdapter

        adapter = RegistryPyPIAdapter()
        assert adapter.ecosystem == "pypi"

    def test_npm_adapter_ecosystem(self) -> None:
        """AAA: Check NPM unified adapter ecosystem."""
        from pkg_defender.registry.npm_unified import NpmUnifiedAdapter

        adapter = NpmUnifiedAdapter()
        assert adapter.ecosystem == "npm"


class TestAdapterResolveLatestVersion:
    """Test resolve_latest_version() error handling."""

    @pytest.mark.asyncio
    async def test_pypi_resolve_latest_version_none_response(self) -> None:
        """AAA: Return None when HTTPMixin._fetch_json raises."""
        from pkg_defender.registry.pypi import PyPIAdapter as RegistryPyPIAdapter

        adapter = RegistryPyPIAdapter()

        with patch(
            "pkg_defender.registry.base.HTTPMixin._fetch_json",
            new=AsyncMock(side_effect=TimeoutError("timeout")),
        ):
            result = await adapter.get_latest_version("requests")
            assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
