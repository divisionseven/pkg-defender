"""Tests for the GitHub Security Advisory (GHSA) feed."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from pkg_defender.intel.base import FetchStatus
from pkg_defender.intel.ghsa import (
    GHSA_REST_URL,
    GHSAFeed,
    _get_severity,
    _parse_advisory,
    _parse_link_header,
    _rest_fetch_with_link,
)

# ---------------------------------------------------------------------------
# Fixtures / test data
# ---------------------------------------------------------------------------

# REST API format samples
SAMPLE_ADVISORY = {
    "ghsa_id": "GHSA-abcd-efgh-ijkl",
    "summary": "Remote code execution in example-package",
    "severity": "critical",
    "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
    "published_at": "2025-06-15T10:00:00Z",
    "updated_at": "2025-06-16T14:30:00Z",
    "vulnerabilities": [
        {
            "package": {"name": "example-package", "ecosystem": "npm"},
            "vulnerable_version_range": ">= 1.0.0, < 1.2.0",
            "first_patched_version": "1.2.0",
        }
    ],
}

SAMPLE_ADVISORY_MULTI_VULN = {
    "ghsa_id": "GHSA-1111-2222-3333",
    "summary": "Multiple package vulnerability",
    "severity": "high",
    "html_url": "https://github.com/advisories/GHSA-1111-2222-3333",
    "published_at": "2025-07-01T00:00:00Z",
    "updated_at": "2025-07-02T12:00:00Z",
    "vulnerabilities": [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "vulnerable_version_range": "< 4.17.21",
            "first_patched_version": "4.17.21",
        },
        {
            "package": {"name": "django", "ecosystem": "pip"},
            "vulnerable_version_range": "< 4.2.7",
            "first_patched_version": "4.2.7",
        },
    ],
}

SAMPLE_ADVISORY_MODERATE = {
    "ghsa_id": "GHSA-moderate-0000-0000",
    "summary": "Moderate severity advisory",
    "severity": "medium",
    "html_url": "https://github.com/advisories/GHSA-moderate-0000-0000",
    "published_at": "2025-08-01T00:00:00Z",
    "updated_at": "2025-08-02T00:00:00Z",
    "vulnerabilities": [
        {
            "package": {"name": "axios", "ecosystem": "npm"},
            "vulnerable_version_range": "< 1.6.0",
            "first_patched_version": "1.6.0",
        }
    ],
}

SAMPLE_ADVISORY_NO_VULNS = {
    "ghsa_id": "GHSA-empty-0000-0000",
    "summary": "Advisory with no affected packages",
    "severity": "low",
    "html_url": "https://github.com/advisories/GHSA-empty-0000-0000",
    "published_at": "2025-09-01T00:00:00Z",
    "updated_at": "2025-09-01T00:00:00Z",
    "vulnerabilities": [],
}

SAMPLE_ADVISORY_UNKNOWN_ECOSYSTEM = {
    "ghsa_id": "GHSA-unknown-eco-0000",
    "summary": "Advisory in unknown ecosystem",
    "severity": "high",
    "html_url": "https://github.com/advisories/GHSA-unknown-eco-0000",
    "published_at": "2025-10-01T00:00:00Z",
    "updated_at": "2025-10-01T00:00:00Z",
    "vulnerabilities": [
        {
            "package": {"name": "some-package", "ecosystem": "unknown-eco"},
            "vulnerable_version_range": "< 1.0.0",
            "first_patched_version": None,
        }
    ],
}


# ---------------------------------------------------------------------------
# Tests for _get_severity (REST API format)
# ---------------------------------------------------------------------------


class TestGetSeverity:
    """Tests for the severity mapping function."""

    @pytest.mark.parametrize(
        "input_severity,expected",
        [
            ("critical", "CRITICAL"),
            ("high", "HIGH"),
            ("medium", "MEDIUM"),
            ("low", "LOW"),
            ("unknown", "UNKNOWN"),
            (None, "UNKNOWN"),
            ("", "UNKNOWN"),
            # REST API uses lowercase, so uppercase is not recognized
        ],
    )
    def test_severity_mapping(self, input_severity: str | None, expected: str) -> None:
        """Test severity strings are correctly mapped."""
        result = _get_severity(input_severity)
        assert result == expected


# ---------------------------------------------------------------------------
# Tests for _parse_advisory
# ---------------------------------------------------------------------------


class TestParseAdvisory:
    """Tests for parsing GHSA advisories into ThreatRecords."""

    def test_parse_single_advisory(self) -> None:
        """Test parsing a single advisory with one vulnerability."""
        records = _parse_advisory(SAMPLE_ADVISORY)

        assert len(records) == 1
        rec = records[0]
        assert rec.id == "ghsa:GHSA-abcd-efgh-ijkl:example-package"
        assert rec.ecosystem == "npm"
        assert rec.package_name == "example-package"
        assert rec.severity == "CRITICAL"
        assert rec.source_id == "GHSA-abcd-efgh-ijkl"
        # Check that version ranges are present (both range and patched version)
        assert len(rec.affected_ranges) == 2
        assert ">= 1.0.0, < 1.2.0" in rec.affected_ranges
        assert "<1.2.0" in rec.affected_ranges

    def test_parse_multi_vuln_advisory(self) -> None:
        """Test parsing an advisory with multiple packages."""
        records = _parse_advisory(SAMPLE_ADVISORY_MULTI_VULN)

        assert len(records) == 2
        assert records[0].package_name == "lodash"
        assert records[0].ecosystem == "npm"
        assert records[1].package_name == "django"
        assert records[1].ecosystem == "pypi"

    def test_parse_moderate_severity(self) -> None:
        """Test that MODERATE severity maps to MEDIUM."""
        records = _parse_advisory(SAMPLE_ADVISORY_MODERATE)

        assert len(records) == 1
        assert records[0].severity == "MEDIUM"

    def test_parse_empty_vulnerabilities(self) -> None:
        """Test parsing advisory with no vulnerabilities produces no records."""
        records = _parse_advisory(SAMPLE_ADVISORY_NO_VULNS)

        assert len(records) == 0

    def test_parse_with_ecosystem_filter(self) -> None:
        """Test that ecosystem filter works."""
        records = _parse_advisory(SAMPLE_ADVISORY_MULTI_VULN, ecosystems=["npm"])

        assert len(records) == 1
        assert records[0].package_name == "lodash"

    def test_parse_unknown_ecosystem_skipped(self) -> None:
        """Test that unknown ecosystems are skipped."""
        records = _parse_advisory(SAMPLE_ADVISORY_UNKNOWN_ECOSYSTEM)

        # Unknown ecosystem should be filtered out
        assert len(records) == 0


# ---------------------------------------------------------------------------
# Tests for GHSAFeed.fetch (REST API)
# ---------------------------------------------------------------------------


class TestGHSAFeedFetch:
    """Tests for the GHSAFeed.fetch method using REST API."""

    @pytest.fixture
    def feed(self) -> GHSAFeed:
        """Create a GHSAFeed instance."""
        return GHSAFeed()

    @pytest.mark.asyncio
    async def test_fetch_basic(self, feed: GHSAFeed) -> None:
        """Test basic fetch returns records."""
        since = datetime(2025, 6, 1, tzinfo=UTC)

        # Build the exact URL that will be requested
        from urllib.parse import urlencode

        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[SAMPLE_ADVISORY])

            result = await feed.fetch(since=since)

            assert len(result.records) == 1
            assert result.records[0].source == "ghsa"
            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_with_ecosystem_filter(self, feed: GHSAFeed) -> None:
        """Test fetch with ecosystem filter."""
        since = datetime(2025, 6, 1, tzinfo=UTC)

        # Build the exact URL that will be requested
        from urllib.parse import urlencode

        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "ecosystem": "npm",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[SAMPLE_ADVISORY_MULTI_VULN])

            result = await feed.fetch(since=since, ecosystems=["npm"])

            assert len(result.records) == 1
            assert result.records[0].ecosystem == "npm"
            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_default_since(self, feed: GHSAFeed) -> None:
        """Test fetch uses default 24h since when not provided."""
        mock_session = AsyncMock()
        with patch(
            "pkg_defender.intel.ghsa._rest_fetch_with_link",
            return_value=([], None),
        ):
            result = await feed.fetch(session=mock_session)
            assert result.records == []
            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_fetch_empty_response(self, feed: GHSAFeed) -> None:
        """Test fetch handles empty response."""
        since = datetime(2025, 6, 1, tzinfo=UTC)

        from urllib.parse import urlencode

        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[])

            result = await feed.fetch(since=since)

            assert result.records == []
            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_ghsa_fetch_propagates_exception(self, feed: GHSAFeed) -> None:
        """Mock _rest_fetch_with_link to raise; exception propagates, not caught as []."""
        with (
            patch(
                "pkg_defender.intel.ghsa._rest_fetch_with_link",
                side_effect=aiohttp.ClientError("GHSA API unavailable"),
            ),
            pytest.raises(aiohttp.ClientError, match="GHSA API unavailable"),
        ):
            await feed.fetch(session=MagicMock())


# ---------------------------------------------------------------------------
# Tests for ecosystem translation (Plan A: 422 fix)
# ---------------------------------------------------------------------------


class TestGHSAFeedEcosystemTranslation:
    """Tests for internal→GitHub ecosystem name translation in fetch().

    GitHub's REST API accepts only a fixed set of ecosystem filter values
    (rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions,
    pub, other, swift). The internal ecosystem names used by pkg-defender's
    adapters do not always match (e.g., "pypi"→"pip", "cargo"→"rust"), and
    five internal ecosystems have no GitHub equivalent at all (homebrew,
    apt, yum, dnf, conda). These tests verify the translation, the
    filtering of unsupported values, and the empty-mapped-list fallback.
    """

    @pytest.fixture
    def feed(self) -> GHSAFeed:
        """Create a GHSAFeed instance."""
        return GHSAFeed()

    @pytest.mark.asyncio
    async def test_pypi_ecosystem_translates_to_pip(self, feed: GHSAFeed) -> None:
        """Internal 'pypi' must be translated to GitHub's 'pip' filter value.

        Regression test for the 422 error: passing ecosystem=pypi to GitHub's
        /advisories endpoint returns 422 because 'pypi' is not in the
        accepted enum. The reverse map (INTERNAL_TO_GITHUB_ECOSYSTEM) must
        translate 'pypi' → 'pip' before building the query string.
        """
        since = datetime(2025, 6, 1, tzinfo=UTC)

        from urllib.parse import urlencode

        # Expected URL uses GitHub's 'pip' name, not the internal 'pypi'.
        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "ecosystem": "pip",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[SAMPLE_ADVISORY_MULTI_VULN])

            result = await feed.fetch(since=since, ecosystems=["pypi"])

            assert result.status == FetchStatus.SUCCESS
            assert len(result.records) == 1

    @pytest.mark.asyncio
    async def test_cargo_ecosystem_translates_to_rust(self, feed: GHSAFeed) -> None:
        """Internal 'cargo' must be translated to GitHub's 'rust' filter value.

        GitHub's accepted enum uses 'rust' (the language) for crates; the
        internal name is 'cargo' (the build tool). The reverse map must
        translate 'cargo' → 'rust'.
        """
        since = datetime(2025, 6, 1, tzinfo=UTC)

        from urllib.parse import urlencode

        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "ecosystem": "rust",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[])

            result = await feed.fetch(since=since, ecosystems=["cargo"])

            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_unsupported_ecosystem_omits_filter(self, feed: GHSAFeed) -> None:
        """Ecosystems not supported by GitHub must NOT appear in the filter.

        For input like ecosystems=['homebrew'], the mapped list is empty.
        The new code must omit the 'ecosystem' param entirely (so GitHub
        does not 422) and log a debug message. The post-fetch ecosystem
        filter (lines 119-120 of ghsa.py) still applies the caller's
        original list to the returned records.
        """
        since = datetime(2025, 6, 1, tzinfo=UTC)

        from urllib.parse import urlencode

        # Expected URL has NO 'ecosystem' param — the input ecosystem
        # is not in GitHub's accepted enum, so the param is omitted.
        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[])

            result = await feed.fetch(since=since, ecosystems=["homebrew"])

            assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_mixed_ecosystems_filter_unsupported(self, feed: GHSAFeed) -> None:
        """Mixed list with supported and unsupported ecosystems filters correctly.

        For input ['pypi', 'homebrew'], the 'pypi' is translated to 'pip'
        and the 'homebrew' is dropped. The query string has 'ecosystem=pip'.
        """
        since = datetime(2025, 6, 1, tzinfo=UTC)

        from urllib.parse import urlencode

        params = {
            "per_page": "100",
            "sort": "updated",
            "direction": "desc",
            "updated": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "ecosystem": "pip",
        }
        full_url = f"{GHSA_REST_URL}?{urlencode(params)}"

        with aioresponses() as mocked:
            mocked.get(full_url, payload=[])

            result = await feed.fetch(since=since, ecosystems=["pypi", "homebrew"])

            assert result.status == FetchStatus.SUCCESS

    def test_reverse_map_only_contains_supported_ecosystems(self) -> None:
        """The reverse map must not include ecosystems GitHub does not support.

        This is a structural test that guards against accidentally adding
        a reverse-map entry for an unsupported ecosystem (e.g., 'homebrew',
        'apt', 'yum', 'dnf', 'conda'). Such an entry would either be a
        no-op (if the value is None) or a 422 (if the value is wrong).
        """
        from pkg_defender.intel.ghsa import INTERNAL_TO_GITHUB_ECOSYSTEM

        unsupported = {"homebrew", "apt", "yum", "dnf", "conda"}
        leaked = unsupported & set(INTERNAL_TO_GITHUB_ECOSYSTEM.keys())
        assert not leaked, f"INTERNAL_TO_GITHUB_ECOSYSTEM must not contain unsupported ecosystems, but found: {leaked}"

    def test_reverse_map_values_are_github_accepted(self) -> None:
        """All values in the reverse map must be in GitHub's accepted enum.

        GitHub's REST API /advisories ecosystem filter accepts:
        rubygems, npm, pip, maven, nuget, composer, go, rust, erlang,
        actions, pub, other, swift.
        """
        from pkg_defender.intel.ghsa import INTERNAL_TO_GITHUB_ECOSYSTEM

        github_accepted = {
            "rubygems",
            "npm",
            "pip",
            "maven",
            "nuget",
            "composer",
            "go",
            "rust",
            "erlang",
            "actions",
            "pub",
            "other",
            "swift",
        }
        leaked = set(INTERNAL_TO_GITHUB_ECOSYSTEM.values()) - github_accepted
        assert not leaked, f"INTERNAL_TO_GITHUB_ECOSYSTEM values must be in GitHub's accepted enum, but found: {leaked}"


# ---------------------------------------------------------------------------
# Tests for GHSAFeed.check_package
# ---------------------------------------------------------------------------


class TestGHSAFeedCheckPackage:
    """Tests for GHSAFeed.check_package (not supported)."""

    @pytest.fixture
    def feed(self) -> GHSAFeed:
        """Create a GHSAFeed instance."""
        return GHSAFeed()

    @pytest.mark.asyncio
    async def test_check_package_returns_empty(self, feed: GHSAFeed) -> None:
        """GHSA does not support point queries."""
        result = await feed.check_package("lodash", "4.17.20", "npm")
        assert result.records == []
        assert result.status == FetchStatus.FAILED


# ---------------------------------------------------------------------------
# Tests for FeedSource interface
# ---------------------------------------------------------------------------


class TestGHSAFeedInterface:
    """Tests for GHSAFeed FeedSource interface compliance."""

    def test_name_property(self) -> None:
        """Test the feed name."""
        feed = GHSAFeed()
        assert feed.name == "ghsa"

    def test_supports_incremental(self) -> None:
        """Test incremental support."""
        feed = GHSAFeed()
        assert feed.supports_incremental is True


# ---------------------------------------------------------------------------
# _parse_advisory advanced edge cases
# ---------------------------------------------------------------------------


class TestParseAdvisoryAdvanced:
    """Tests for _parse_advisory edge cases."""

    def test_missing_published_at(self) -> None:
        """Advisory without published_at uses current time.

        Covers lines 91-93 (missing published_at).
        """
        advisory = {
            "ghsa_id": "GHSA-no-pub-0001",
            "summary": "No publish date",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-no-pub-0001",
            "vulnerabilities": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        # first_seen should be set to now (not crash)
        assert records[0].first_seen is not None

    def test_missing_updated_at(self) -> None:
        """Advisory without updated_at uses current time for last_seen.

        Covers lines 97-99 (missing updated_at).
        """
        advisory = {
            "ghsa_id": "GHSA-no-upd-0002",
            "summary": "No update date",
            "severity": "medium",
            "html_url": "https://github.com/advisories/GHSA-no-upd-0002",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "pip"},
                    "vulnerable_version_range": "< 2.0.0",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        assert records[0].last_seen is not None

    def test_empty_package_name_skipped(self) -> None:
        """Advisory vulnerability without package name is skipped.

        Covers lines 108-109 (empty package name check).
        """
        advisory = {
            "ghsa_id": "GHSA-no-name-0003",
            "summary": "No package name",
            "severity": "low",
            "html_url": "https://github.com/advisories/GHSA-no-name-0003",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert records == []

    def test_all_vulns_have_empty_names_skipped(self) -> None:
        """Advisory with all empty vuln names returns empty list."""
        advisory = {
            "ghsa_id": "GHSA-all-empty-0004",
            "summary": "All vulns empty",
            "severity": "critical",
            "html_url": "https://github.com/advisories/GHSA-all-empty-0004",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                },
                {
                    "package": {"name": None, "ecosystem": "pip"},
                    "vulnerable_version_range": "< 2.0.0",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert records == []

    def test_patched_version_as_string(self) -> None:
        """Advisory with patched version as string adds range.

        Covers lines 130-131 (patched version string check).
        """
        advisory = {
            "ghsa_id": "GHSA-patched-0005",
            "summary": "With patched version",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-patched-0005",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "fixed-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                    "first_patched_version": "0.9.9",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        assert "<0.9.9" in records[0].affected_ranges

    def test_patched_version_is_none(self) -> None:
        """Advisory with patched version as None skips range addition.

        Covers lines 129-131 (empty patched check).
        """
        advisory = {
            "ghsa_id": "GHSA-none-patch-0006",
            "summary": "No patched version",
            "severity": "medium",
            "html_url": "https://github.com/advisories/GHSA-none-patch-0006",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "vuln-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                    "first_patched_version": None,
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        # Should only have the vulnerable_version_range, not a patched version
        assert len(records[0].affected_ranges) == 1

    def test_no_version_range(self) -> None:
        """Advisory without version range has empty affected_ranges.

        Covers lines 124-126 (empty version range).
        """
        advisory = {
            "ghsa_id": "GHSA-no-range-0007",
            "summary": "No version range",
            "severity": "low",
            "html_url": "https://github.com/advisories/GHSA-no-range-0007",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "unversioned", "ecosystem": "npm"},
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        assert records[0].affected_ranges == []

    def test_vulnerabilities_is_none(self) -> None:
        """Advisory with null vulnerabilities handles gracefully.

        Covers line 103 (vuln_nodes fallback to []).
        """
        advisory = {
            "ghsa_id": "GHSA-null-vuln-0008",
            "summary": "Null vulns",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-null-vuln-0008",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": None,
        }
        records = _parse_advisory(advisory)
        assert records == []

    def test_invalid_published_at_format(self) -> None:
        """Advisory with invalid published_at format doesn't crash.

        Covers lines 91-93 (suppress ValueError/TypeError).
        """
        advisory = {
            "ghsa_id": "GHSA-bad-pub-0009",
            "summary": "Bad publish date format",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-bad-pub-0009",
            "published_at": "not-a-valid-date-format",
            "vulnerabilities": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                },
            ],
        }
        records = _parse_advisory(advisory)
        assert len(records) == 1
        # Should default to now
        assert records[0].published_at is not None


# ---------------------------------------------------------------------------
# Tests for _parse_link_header
# ---------------------------------------------------------------------------


class TestParseLinkHeader:
    """Tests for parsing Link header pagination."""

    def test_no_link_header(self) -> None:
        """No Link header returns None.

        Covers lines 402-404 (no link header path).
        """
        mock_response = MagicMock()
        mock_response.headers = {}
        result = _parse_link_header(mock_response)
        assert result is None

    def test_link_with_next_and_after(self) -> None:
        """Link header with next rel and after param returns cursor.

        Covers lines 406-419.
        """
        mock_response = MagicMock()
        mock_response.headers = {
            "Link": (
                '<https://api.github.com/advisories?per_page=100&after=cursor_abc>; rel="next",'
                ' <https://api.github.com/advisories?per_page=100>; rel="last"'
            ),
        }
        result = _parse_link_header(mock_response)
        assert result == "cursor_abc"

    def test_link_without_next(self) -> None:
        """Link header without next rel returns None."""
        mock_response = MagicMock()
        mock_response.headers = {
            "Link": '<https://api.github.com/advisories?per_page=100>; rel="last"',
        }
        result = _parse_link_header(mock_response)
        assert result is None

    def test_link_next_without_after_param(self) -> None:
        """Link header with next rel but no after param returns None.

        Covers lines 416-418 (after param extraction with empty result).
        """
        mock_response = MagicMock()
        mock_response.headers = {
            "Link": '<https://api.github.com/advisories?per_page=100&page=2>; rel="next"',
        }
        result = _parse_link_header(mock_response)
        assert result is None

    def test_link_header_not_well_formed(self) -> None:
        """Malformed Link header doesn't crash."""
        mock_response = MagicMock()
        mock_response.headers = {
            "Link": "this is not a valid link header",
        }
        result = _parse_link_header(mock_response)
        assert result is None


# ---------------------------------------------------------------------------
# Tests for _rest_fetch_with_link - error paths
# ---------------------------------------------------------------------------


class TestRestFetchWithLink:
    """Tests for _rest_fetch_with_link error handling."""

    @pytest.mark.asyncio
    async def test_returns_data_and_cursor_when_fetch_succeeds(self) -> None:
        """Successful fetch returns data and cursor from Link header."""
        mock_session = AsyncMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value=[{"ghsa_id": "GHSA-test-0001"}])
        mock_response.headers = {}
        mock_session.get = AsyncMock(return_value=mock_response)

        mock_config = MagicMock()
        mock_config.feeds.ghsa_token = ""

        data, cursor = await _rest_fetch_with_link(
            {"per_page": "100"},
            mock_session,
            mock_config,
        )
        assert len(data) == 1
        assert cursor is None

    @pytest.mark.asyncio
    async def test_with_auth_token(self) -> None:
        """Request includes Bearer token when configured.

        Covers line 312 (auth token header).
        """
        mock_session = AsyncMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value=[])
        mock_response.headers = {}
        mock_session.get = AsyncMock(return_value=mock_response)

        mock_config = MagicMock()
        mock_config.feeds.ghsa_token = "ghp_test_token"

        with patch("pkg_defender.intel.ghsa.get_max_retries", return_value=1):
            await _rest_fetch_with_link({"per_page": "100"}, mock_session, mock_config)

        call_kwargs = mock_session.get.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer ghp_test_token"

    @pytest.mark.asyncio
    async def test_rate_limiting_retry_then_succeeds(self) -> None:
        """429 rate limit retries and succeeds on second attempt.

        Covers lines 325-347 (rate limiting path).
        """
        mock_session = AsyncMock()

        # First call returns 429
        resp_429 = MagicMock()
        resp_429.status = 429
        resp_429.headers = {"Retry-After": "1"}
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_429.request_info = Mock()

        # Second call succeeds
        resp_ok = MagicMock()
        resp_ok.status = 200
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[{"ghsa_id": "GHSA-ratelimit-0001"}])
        resp_ok.headers = {}

        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
        ):
            data, cursor = await _rest_fetch_with_link(
                {"per_page": "100"},
                mock_session,
                MagicMock(),
            )

        assert len(data) == 1
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_rate_limiting_exhausts_retries(self) -> None:
        """429 rate limit exhausts retries and raises.

        Covers lines 347 (raise after exhausted rate limit retries).
        """
        mock_session = AsyncMock()
        resp_429 = MagicMock()
        resp_429.status = 429
        resp_429.headers = {"Retry-After": "60"}
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_429.request_info = Mock()
        mock_session.get = AsyncMock(return_value=resp_429)

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _rest_fetch_with_link({"per_page": "100"}, mock_session, MagicMock())
        assert excinfo.value.status == 429

    @pytest.mark.asyncio
    async def test_rate_limiting_retry_after_not_int(self) -> None:
        """429 rate limit handles non-integer Retry-After header.

        Covers lines 336-338 (ValueError handling for Retry-After).
        """
        mock_session = AsyncMock()

        resp_429 = MagicMock()
        resp_429.status = 429
        resp_429.headers = {"Retry-After": "not-an-integer"}
        resp_429.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=429,
        )
        resp_429.request_info = Mock()

        resp_ok = MagicMock()
        resp_ok.status = 200
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[])
        resp_ok.headers = {}

        mock_session.get = AsyncMock(side_effect=[resp_429, resp_ok])

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
        ):
            data, cursor = await _rest_fetch_with_link(
                {"per_page": "100"},
                mock_session,
                MagicMock(),
            )

        assert data is not None
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_5xx_then_succeeds(self) -> None:
        """5xx server errors retry and can succeed.

        Covers lines 354-370 (5xx retry path).
        """
        mock_session = AsyncMock()
        resp_500 = MagicMock()
        resp_500.status = 500
        resp_500.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=500,
        )
        resp_500.request_info = Mock()

        resp_ok = MagicMock()
        resp_ok.status = 200
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[])
        resp_ok.headers = {}

        mock_session.get = AsyncMock(side_effect=[resp_500, resp_ok])

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
        ):
            data, cursor = await _rest_fetch_with_link(
                {"per_page": "100"},
                mock_session,
                MagicMock(),
            )

        assert data == []
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_5xx(self) -> None:
        """5xx server errors exhaust retries and raise.

        Covers lines 368-369 (exhausted 5xx raise).
        """
        mock_session = AsyncMock()
        resp_500 = MagicMock()
        resp_500.status = 500
        resp_500.raise_for_status.side_effect = aiohttp.ClientResponseError(
            Mock(),
            Mock(),
            status=500,
        )
        resp_500.request_info = Mock()
        mock_session.get = AsyncMock(return_value=resp_500)

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientResponseError) as excinfo,
        ):
            await _rest_fetch_with_link({"per_page": "100"}, mock_session, MagicMock())
        assert excinfo.value.status == 500

    @pytest.mark.asyncio
    async def test_retries_on_client_error_then_succeeds(self) -> None:
        """ClientError/TimeoutError retries and succeeds.

        Covers lines 372-384 (ClientError retry path).
        """
        mock_session = AsyncMock()
        resp_ok = MagicMock()
        resp_ok.status = 200
        resp_ok.raise_for_status = MagicMock()
        resp_ok.json = AsyncMock(return_value=[])
        resp_ok.headers = {}
        mock_session.get = AsyncMock(side_effect=[aiohttp.ClientError("timeout"), resp_ok])

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
        ):
            data, cursor = await _rest_fetch_with_link(
                {"per_page": "100"},
                mock_session,
                MagicMock(),
            )

        assert data == []
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries_on_persistent_client_error(self) -> None:
        """ClientError exhausts retries and raises.

        Covers lines 385-386 (exhausted ClientError raise).
        """
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("always fails"))

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=2),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
            pytest.raises(aiohttp.ClientError),
        ):
            await _rest_fetch_with_link({"per_page": "100"}, mock_session, MagicMock())

        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_no_retries(self) -> None:
        """RuntimeError when max_retries is 0.

        Covers lines 388-390 (RuntimeError fallback).
        """
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("fail"))

        with (
            patch("pkg_defender.intel.ghsa.get_max_retries", return_value=0),
            patch("pkg_defender.intel.ghsa._asyncio_sleep", new_callable=AsyncMock),
            pytest.raises(RuntimeError, match="Failed to fetch GHSA after retries"),
        ):
            await _rest_fetch_with_link({"per_page": "100"}, mock_session, MagicMock())


# ---------------------------------------------------------------------------
# GHSAFeed.fetch pagination
# ---------------------------------------------------------------------------


class TestGHSAFeedFetchPagination:
    """Tests for GHSAFeed.fetch pagination."""

    @pytest.mark.asyncio
    async def test_fetch_paginates_when_cursor_returned(self) -> None:
        """fetch follows pagination when cursor is returned.

        Covers lines 252-257 (pagination loop).
        """
        feed = GHSAFeed()
        advisory_page_1 = {
            "ghsa_id": "GHSA-page1-0001",
            "summary": "First page advisory",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-page1-0001",
            "published_at": "2025-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "pkg1", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.0.0",
                },
            ],
        }
        advisory_page_2 = {
            "ghsa_id": "GHSA-page2-0002",
            "summary": "Second page advisory",
            "severity": "medium",
            "html_url": "https://github.com/advisories/GHSA-page2-0002",
            "published_at": "2025-06-02T00:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "pkg2", "ecosystem": "pip"},
                    "vulnerable_version_range": "< 2.0.0",
                },
            ],
        }

        # First call returns page 1 with cursor, second returns page 2 with None
        mock_calls = [
            ([advisory_page_1], "cursor_page2"),
            ([advisory_page_2], None),
        ]

        with patch(
            "pkg_defender.intel.ghsa._rest_fetch_with_link",
            side_effect=mock_calls,
        ):
            result = await feed.fetch(
                since=datetime(2025, 6, 1, tzinfo=UTC),
                session=MagicMock(),
            )

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 2
        assert result.records[0].package_name == "pkg1"
        assert result.records[1].package_name == "pkg2"
