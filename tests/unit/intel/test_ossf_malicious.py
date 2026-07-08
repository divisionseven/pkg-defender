"""Tests for the OSSF Malicious Packages feed source.

Tests the OSSFMaliciousFeed class and the OSV record parser.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.intel.base import FetchStatus
from pkg_defender.intel.ossf_malicious import (
    CODELOAD_TARBALL_URL,
    ECOSYSTEM_PATH_MAP,
    GITHUB_COMMIT_URL,
    OSV_ECOSYSTEM_MAP,
    OSV_PATH_PREFIX,
    PROGRESS_REPORT_INTERVAL,
    RETRYABLE_STATUSES,
    WITHDRAWN_PATH_PREFIX,
    OSSFMaliciousFeed,
    _determine_ecosystem_from_path,
    _determine_package_from_path,
    _get_github_headers,
    _parse_osv_record,
    _parse_ranges,
)

# ---------------------------------------------------------------------------
# Fixtures — realistic OSV JSON data
# ---------------------------------------------------------------------------


def _npm_record() -> dict[str, Any]:
    """Standard npm OSV record (schema 1.7.4)."""
    return {
        "id": "MAL-2025-1234",
        "summary": "Malicious code in evil-pkg (npm)",
        "published": "2025-03-15T10:00:00Z",
        "modified": "2025-03-16T12:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "evil-pkg"},
                "versions": ["1.0.0", "1.0.1"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.2"}],
                    }
                ],
            }
        ],
        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
    }


def _git_record() -> dict[str, Any]:
    """Git ecosystem OSV record (no package object)."""
    return {
        "id": "MAL-2025-5678",
        "summary": "Malicious code in evil-repo (Git)",
        "published": "2025-04-01T08:00:00Z",
        "modified": "2025-04-01T08:00:00Z",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "0", "fixed": "abc123def456"}],
                    }
                ],
            }
        ],
    }


def _go_record() -> dict[str, Any]:
    """Go ecosystem OSV record (schema 1.5.0)."""
    return {
        "id": "MAL-2024-9999",
        "summary": "Malicious code in evil-module (Go)",
        "published": "2024-12-01T00:00:00Z",
        "modified": "2024-12-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "evil-module"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0", "fixed": "1.2.3"}],
                    }
                ],
            }
        ],
    }


def _crates_record() -> dict[str, Any]:
    """crates.io ecosystem OSV record."""
    return {
        "id": "MAL-2025-1111",
        "summary": "Malicious code in evil-crate (crates.io)",
        "published": "2025-05-01T00:00:00Z",
        "modified": "2025-05-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "evil-crate"},
                "versions": ["0.1.0"],
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0", "fixed": "0.1.1"}],
                    }
                ],
            }
        ],
    }


def _maven_record() -> dict[str, Any]:
    """Maven ecosystem OSV record."""
    return {
        "id": "MAL-2025-2222",
        "summary": "Malicious code in evil-maven (Maven)",
        "published": "2025-06-01T00:00:00Z",
        "modified": "2025-06-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "evil-maven"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}],
                    }
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Helper: tarball construction for feed tests
# ---------------------------------------------------------------------------


def _make_tarball(
    files: list[tuple[str, dict[str, Any]]],
    commit_sha: str = "test_sha_123",
) -> bytes:
    """Create an in-memory gzip tarball mimicking codeload output.

    Args:
        files: List of (internal_path, osv_data_dict) tuples. The internal_path
               should be like "osv/malicious/npm/evil-pkg/MAL-2025-1234.json".
        commit_sha: The commit SHA used as the archive top-level directory name.

    Returns:
        Raw gzip tarball bytes ready to return from a mocked HTTP response.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, data in files:
            content = json.dumps(data).encode("utf-8")
            tar_path = f"malicious-packages-{commit_sha}/{path}"
            info = tarfile.TarInfo(name=tar_path)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Test: _parse_osv_record
# ---------------------------------------------------------------------------


class TestParseOsvRecord:
    """Tests for _parse_osv_record()."""

    def test_standard_npm_record(self) -> None:
        """Full field mapping for a standard npm record."""
        data = _npm_record()
        records = _parse_osv_record(data, file_path="osv/malicious/npm/evil-pkg/MAL-2025-1234.json")

        assert len(records) == 1
        r = records[0]
        assert r.id == "ossf_malicious:npm:evil-pkg"
        assert r.ecosystem == "npm"
        assert r.package_name == "evil-pkg"
        assert r.source_id == "MAL-2025-1234"
        assert r.summary == "Malicious code in evil-pkg (npm)"
        assert r.affected_versions == ["1.0.0", "1.0.1"]
        assert r.affected_ranges == [">=0 <1.0.2"]
        assert r.severity == "CRITICAL"
        assert r.confidence == 1.0
        assert r.source == "ossf_malicious"
        assert r.is_malicious is True
        assert r.is_unverified is False
        assert r.cvss_score is None
        assert r.detail_url == "https://example.com/advisory"
        assert r.first_seen.year == 2025
        assert r.first_seen.month == 3
        assert r.published_at is not None

    def test_git_ecosystem_no_package(self) -> None:
        """Git ecosystem: no package object, package extracted from path."""
        data = _git_record()
        records = _parse_osv_record(data, file_path="osv/malicious/Git/evil-repo/MAL-2025-5678.json")

        assert len(records) == 1
        r = records[0]
        assert r.ecosystem == "unknown"
        assert r.package_name == "evil-repo"
        assert r.affected_ranges == [">=0 <abc123def456"]

    def test_go_ecosystem_semver_range(self) -> None:
        """Go ecosystem with SEMVER range type."""
        data = _go_record()
        records = _parse_osv_record(data, file_path="osv/malicious/Go/evil-module/MAL-2024-9999.json")

        assert len(records) == 1
        r = records[0]
        assert r.ecosystem == "go"
        assert r.package_name == "evil-module"
        assert r.affected_ranges == [">=0 <1.2.3"]

    def test_crates_io_ecosystem(self) -> None:
        """crates.io ecosystem maps to cargo."""
        data = _crates_record()
        records = _parse_osv_record(data, file_path="osv/malicious/crates.io/evil-crate/MAL-2025-1111.json")

        assert len(records) == 1
        assert records[0].ecosystem == "cargo"

    def test_maven_ecosystem(self) -> None:
        """Maven ecosystem mapping."""
        data = _maven_record()
        records = _parse_osv_record(data, file_path="osv/malicious/Maven/evil-maven/MAL-2025-2222.json")

        assert len(records) == 1
        assert records[0].ecosystem == "maven"

    def test_missing_summary_fallback(self) -> None:
        """Missing summary uses fallback string."""
        data = _npm_record()
        del data["summary"]
        records = _parse_osv_record(data, file_path="osv/malicious/npm/evil-pkg/MAL-2025-1234.json")

        assert len(records) == 1
        assert records[0].summary == "Malicious code in evil-pkg (npm)"

    def test_missing_references_fallback(self) -> None:
        """Missing references uses fallback URL."""
        data = _npm_record()
        del data["references"]
        records = _parse_osv_record(data, file_path="osv/malicious/npm/evil-pkg/MAL-2025-1234.json")

        assert len(records) == 1
        assert records[0].detail_url == "https://github.com/ossf/malicious-packages"

    def test_missing_versions_empty_list(self) -> None:
        """Missing versions field produces empty list."""
        data = _npm_record()
        del data["affected"][0]["versions"]
        records = _parse_osv_record(data, file_path="osv/malicious/npm/evil-pkg/MAL-2025-1234.json")

        assert len(records) == 1
        assert records[0].affected_versions == []

    def test_empty_affected_skips_record(self) -> None:
        """Empty affected array results in empty list."""
        data = {"id": "MAL-2025-0000", "affected": []}
        records = _parse_osv_record(data)
        assert records == []

    def test_missing_affected_skips_record(self) -> None:
        """Missing affected key results in empty list."""
        data = {"id": "MAL-2025-0000"}
        records = _parse_osv_record(data)
        assert records == []

    def test_schema_version_1_5_0(self) -> None:
        """Works with OSV schema 1.5.0 (older format)."""
        data = _go_record()  # Uses schema 1.5.0 structure
        records = _parse_osv_record(data, file_path="osv/malicious/Go/evil-module/MAL-2024-9999.json")
        assert len(records) == 1
        assert records[0].ecosystem == "go"

    def test_schema_version_1_7_4(self) -> None:
        """Works with OSV schema 1.7.4 (newer format)."""
        data = _npm_record()  # Uses schema 1.7.4 structure
        records = _parse_osv_record(data, file_path="osv/malicious/npm/evil-pkg/MAL-2025-1234.json")
        assert len(records) == 1
        assert records[0].ecosystem == "npm"


# ---------------------------------------------------------------------------
# Test: _parse_ranges
# ---------------------------------------------------------------------------


class TestParseRanges:
    """Tests for _parse_ranges()."""

    def test_semver_range_with_fixed(self) -> None:
        """Standard introduced + fixed pair."""
        ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        assert _parse_ranges(ranges) == [">=0 <1.2.3"]

    def test_ecosystem_range_introduced_only(self) -> None:
        """Introduced only — no fixed."""
        ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}]
        assert _parse_ranges(ranges) == [">=1.0.0"]

    def test_git_range(self) -> None:
        """GIT range type with fixed commit hash."""
        ranges = [{"type": "GIT", "events": [{"introduced": "0", "fixed": "abc123"}]}]
        assert _parse_ranges(ranges) == [">=0 <abc123"]

    def test_empty_events(self) -> None:
        """Empty events list produces empty ranges."""
        ranges = [{"type": "SEMVER", "events": []}]
        assert _parse_ranges(ranges) == []

    def test_multiple_ranges(self) -> None:
        """Multiple range objects are combined."""
        ranges = [
            {"type": "SEMVER", "events": [{"introduced": "0", "fixed": "1.0.0"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}]},
        ]
        assert _parse_ranges(ranges) == [">=0 <1.0.0", ">=2.0.0"]

    def test_fixed_only(self) -> None:
        """Fixed without introduced."""
        ranges = [{"type": "SEMVER", "events": [{"fixed": "2.0.0"}]}]
        assert _parse_ranges(ranges) == ["<2.0.0"]


# ---------------------------------------------------------------------------
# Test: helper functions
# ---------------------------------------------------------------------------


class TestGetGithubHeaders:
    """Tests for _get_github_headers()."""

    def test_no_config(self) -> None:
        """No config returns headers without auth."""
        headers = _get_github_headers()
        assert "Accept" in headers
        assert "Authorization" not in headers

    def test_with_token(self) -> None:
        """Config with ghsa_token includes Authorization header."""
        mock_config = MagicMock()
        mock_config.feeds.ghsa_token = "ghp_test_token_12345"
        headers = _get_github_headers(mock_config)
        assert headers["Authorization"] == "Bearer ghp_test_token_12345"

    def test_without_token(self) -> None:
        """Config without ghsa_token omits Authorization header."""
        mock_config = MagicMock()
        mock_config.feeds.ghsa_token = ""
        headers = _get_github_headers(mock_config)
        assert "Authorization" not in headers


class TestDetermineEcosystemFromPath:
    """Tests for _determine_ecosystem_from_path()."""

    def test_npm_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/npm/pkg/file.json") == "npm"

    def test_go_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/Go/pkg/file.json") == "go"

    def test_crates_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/crates.io/pkg/file.json") == "cargo"

    def test_maven_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/Maven/pkg/file.json") == "maven"

    def test_git_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/Git/pkg/file.json") == "unknown"

    def test_short_path(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious") is None

    def test_unknown_ecosystem(self) -> None:
        assert _determine_ecosystem_from_path("osv/malicious/FakeLang/pkg/file.json") is None

    def test_case_insensitive_lookup(self) -> None:
        """Path-based lookup works regardless of directory casing."""
        # Lowercase directory names (actual repo format) resolve correctly
        assert _determine_ecosystem_from_path("osv/malicious/go/pkg/file.json") == "go"
        assert _determine_ecosystem_from_path("osv/malicious/maven/pkg/file.json") == "maven"
        assert _determine_ecosystem_from_path("osv/malicious/git/pkg/file.json") == "unknown"
        # Canonical OSV casing also resolves
        assert _determine_ecosystem_from_path("osv/malicious/Go/pkg/file.json") == "go"
        assert _determine_ecosystem_from_path("osv/malicious/Maven/pkg/file.json") == "maven"
        assert _determine_ecosystem_from_path("osv/malicious/Git/pkg/file.json") == "unknown"

    def test_rubygems_path(self) -> None:
        """RubyGems ecosystem resolves via case-insensitive lookup."""
        assert _determine_ecosystem_from_path("osv/malicious/RubyGems/pkg/file.json") == "rubygems"

    def test_pypi_path(self) -> None:
        """PyPI ecosystem resolves via case-insensitive lookup."""
        assert _determine_ecosystem_from_path("osv/malicious/PyPI/pkg/file.json") == "pypi"


class TestDeterminePackageFromPath:
    """Tests for _determine_package_from_path()."""

    def test_standard_path(self) -> None:
        assert _determine_package_from_path("osv/malicious/npm/evil-pkg/file.json") == "evil-pkg"

    def test_short_path(self) -> None:
        assert _determine_package_from_path("osv/malicious/npm") is None


# ---------------------------------------------------------------------------
# Test: OSSFMaliciousFeed properties
# ---------------------------------------------------------------------------


class TestOSSFMaliciousFeedProperties:
    """Tests for OSSFMaliciousFeed properties."""

    def test_name(self) -> None:
        assert OSSFMaliciousFeed().name == "ossf_malicious"

    def test_supports_incremental(self) -> None:
        assert OSSFMaliciousFeed().supports_incremental is False

    def test_is_configured(self) -> None:
        mock_config = MagicMock()
        assert OSSFMaliciousFeed().is_configured(mock_config) is True

    @pytest.mark.asyncio
    async def test_check_package_returns_failed(self) -> None:
        feed = OSSFMaliciousFeed()
        result = await feed.check_package("pkg", "1.0", "npm")
        assert result.status == FetchStatus.FAILED
        assert result.records == []


# ---------------------------------------------------------------------------
# Test: OSSFMaliciousFeed.fetch — full pipeline
# ---------------------------------------------------------------------------


class TestOSSFMaliciousFeedFetch:
    """Tests for OSSFMaliciousFeed.fetch() pipeline (2-phase: commit SHA + tarball)."""

    # ------------------------------------------------------------------
    # Test 1: Full success
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_full_success(self) -> None:
        """Full pipeline: SHA check, cache miss, download, extract, SUCCESS."""
        feed = OSSFMaliciousFeed()
        commit_sha = "abc123def456"

        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = AsyncMock(side_effect=mock_get)

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].package_name == "evil-pkg"
        assert result.records[0].is_malicious is True
        assert result.feed_metadata.get("commit_sha_hit") is None
        assert mock_session.get.call_count == 2  # commit SHA + tarball

    # ------------------------------------------------------------------
    # Test 2: Cache hit
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_cache_hit(self, tmp_path: Path) -> None:
        """Cached SHA matches → Phase 2 skipped."""
        from pkg_defender.db.schema import init_db, set_metadata

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        set_metadata(conn, "ossf_malicious_commit_sha", "cached_sha_123")
        conn.close()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": "cached_sha_123"})
        commit_resp.headers = {}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=commit_resp)

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []
        assert result.feed_metadata.get("commit_sha_hit") is True
        assert result.feed_metadata.get("commit_sha") == "cached_sha_123"
        assert mock_session.get.call_count == 1  # only commit SHA check

    # ------------------------------------------------------------------
    # Test 3: Ecosystem filter npm
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_with_ecosystem_filter_npm(self) -> None:
        """Ecosystem filter restricts which records are kept."""
        feed = OSSFMaliciousFeed()
        commit_sha = "sha_for_ecosystem_test"

        tarball = _make_tarball(
            [
                ("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record()),
                ("osv/malicious/Go/evil-module/MAL-2024-9999.json", _go_record()),
            ],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session, ecosystems=["npm"])

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].ecosystem == "npm"

    # ------------------------------------------------------------------
    # Test 4: Ecosystem filter empty
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_with_ecosystem_filter_empty(self) -> None:
        """Filter for non-existent ecosystem returns empty."""
        feed = OSSFMaliciousFeed()
        commit_sha = "sha_empty_filter"

        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session, ecosystems=["nonexistent"])

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 5: Commit SHA 404
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_commit_sha_404(self) -> None:
        """404 on commit SHA lookup returns FAILED."""
        feed = OSSFMaliciousFeed()

        commit_resp = AsyncMock()
        commit_resp.status = 404
        commit_resp.headers = {}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=commit_resp)

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 6: Commit SHA retry 429 then 200
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_commit_sha_retry_429_then_200(self) -> None:
        """429 on commit SHA check → retry → success."""
        feed = OSSFMaliciousFeed()
        commit_sha = "retry_sha"

        rate_limited = AsyncMock()
        rate_limited.status = 429
        rate_limited.headers = {"Retry-After": "0"}

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        call_count = 0

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            nonlocal call_count
            if "commits/main" in url:
                call_count += 1
                if call_count == 1:
                    return rate_limited
                return commit_resp
            empty_tarball = _make_tarball([], commit_sha=commit_sha)
            tarball_resp = AsyncMock()
            tarball_resp.status = 200
            tarball_resp.read = AsyncMock(return_value=empty_tarball)
            tarball_resp.headers = {}
            return tarball_resp

        mock_session = AsyncMock()
        mock_session.get = mock_get

        with patch("pkg_defender.intel.ossf_malicious.asyncio.sleep", new_callable=AsyncMock):
            result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 0  # empty tarball
        assert call_count == 2

    # ------------------------------------------------------------------
    # Test 7: Commit SHA network error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_commit_sha_network_error(self) -> None:
        """Network error during commit SHA check → retries → FAILED."""
        feed = OSSFMaliciousFeed()

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("connection failed"))

        with patch("pkg_defender.intel.ossf_malicious.asyncio.sleep", new_callable=AsyncMock):
            result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 8: Tarball download 404
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_tarball_download_404(self) -> None:
        """404 on tarball download returns FAILED."""
        feed = OSSFMaliciousFeed()
        commit_sha = "sha_for_404"

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 404
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 9: Tarball retry 503 then 200
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_tarball_retry(self) -> None:
        """503 on tarball → retry → success."""
        feed = OSSFMaliciousFeed()
        commit_sha = "retry_tarball_sha"

        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        rate_limited = AsyncMock()
        rate_limited.status = 503
        rate_limited.headers = {"Retry-After": "0"}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        tarball_call_count = 0

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            nonlocal tarball_call_count
            if "commits/main" in url:
                return commit_resp
            tarball_call_count += 1
            if tarball_call_count == 1:
                return rate_limited
            return tarball_resp

        mock_session = AsyncMock()
        mock_session.get = mock_get

        with patch("pkg_defender.intel.ossf_malicious.asyncio.sleep", new_callable=AsyncMock):
            result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert tarball_call_count == 2

    # ------------------------------------------------------------------
    # Test 10: Tarball network error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_tarball_network_error(self) -> None:
        """Network error during tarball download → FAILED."""
        feed = OSSFMaliciousFeed()
        commit_sha = "net_err_sha"

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            raise aiohttp.ClientError("tarball download failed")

        mock_session.get = mock_get

        with patch("pkg_defender.intel.ossf_malicious.asyncio.sleep", new_callable=AsyncMock):
            result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 11: Partial failure
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_partial_failure(self) -> None:
        """Some records parse OK, some fail → PARTIAL."""
        feed = OSSFMaliciousFeed()
        commit_sha = "partial_sha"

        # Manually add a corrupt file to the tarball
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            content = json.dumps(_npm_record()).encode("utf-8")
            good_path = f"malicious-packages-{commit_sha}/osv/malicious/npm/good-pkg/MAL-2025-0001.json"
            good_info = tarfile.TarInfo(name=good_path)
            good_info.size = len(content)
            tar.addfile(good_info, io.BytesIO(content))

            bad_path = f"malicious-packages-{commit_sha}/osv/malicious/npm/bad-pkg/MAL-2025-0002.json"
            bad_content = b"not valid json {{{"
            bad_info = tarfile.TarInfo(name=bad_path)
            bad_info.size = len(bad_content)
            tar.addfile(bad_info, io.BytesIO(bad_content))
        tarball = buf.getvalue()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.PARTIAL
        assert len(result.records) >= 1
        assert result.feed_metadata.get("fail_count", 0) >= 1

    # ------------------------------------------------------------------
    # Test 12: Withdrawn skipped
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_withdrawn_skipped(self) -> None:
        """osv/withdrawn/ paths are excluded from extraction."""
        feed = OSSFMaliciousFeed()
        commit_sha = "withdrawn_sha"

        tarball = _make_tarball(
            [
                ("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record()),
                ("osv/withdrawn/npm/old-pkg/MAL-2024-0001.json", _npm_record()),
            ],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1  # only the non-withdrawn record

    # ------------------------------------------------------------------
    # Test 13: JSON parse error skips file
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_json_parse_error_skips_file(self) -> None:
        """Malformed JSON in tarball → skip file, increment fail_count."""
        feed = OSSFMaliciousFeed()
        commit_sha = "bad_json_sha"

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            path = f"malicious-packages-{commit_sha}/osv/malicious/npm/evil-pkg/MAL-2025-1234.json"
            content = b"not valid json {{{"
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        tarball = buf.getvalue()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []
        assert result.feed_metadata["fail_count"] == 1

    # ------------------------------------------------------------------
    # Test 14: Uses provided session (doesn't close it)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_uses_provided_session(self) -> None:
        """Provided session is used and NOT closed."""
        feed = OSSFMaliciousFeed()
        commit_sha = "session_sha"

        tarball = _make_tarball([], commit_sha=commit_sha)

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        mock_session.close.assert_not_called()

    # ------------------------------------------------------------------
    # Test 15: Creates own session
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_creates_own_session(self) -> None:
        """Creates own session when none provided, closes it."""
        feed = OSSFMaliciousFeed()
        commit_sha = "own_session_sha"

        tarball = _make_tarball([], commit_sha=commit_sha)

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        with patch("pkg_defender.intel.ossf_malicious.aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()

            async def mock_get(url: str, headers: Any = None) -> AsyncMock:
                if "commits/main" in url:
                    return commit_resp
                return tarball_resp

            mock_session.get = mock_get
            mock_session_cls.return_value = mock_session

            result = await feed.fetch()

            assert result.status == FetchStatus.SUCCESS
            mock_session.close.assert_called_once()

    # ------------------------------------------------------------------
    # Test 16: Auth token
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_with_auth_token(self) -> None:
        """Config with ghsa_token includes Authorization header in requests."""
        feed = OSSFMaliciousFeed()
        commit_sha = "auth_sha"

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=_make_tarball([], commit_sha=commit_sha))
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = AsyncMock(side_effect=mock_get)

        mock_config = MagicMock()
        mock_config.feeds.ghsa_token = "ghp_test_token"

        result = await feed.fetch(session=mock_session, config=mock_config)

        assert result.status == FetchStatus.SUCCESS
        # Verify Authorization header was passed to at least the commit call
        commit_call_args = mock_session.get.call_args_list[0]
        assert commit_call_args[1]["headers"]["Authorization"] == "Bearer ghp_test_token"

    # ------------------------------------------------------------------
    # Test 17: Empty archive
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_empty_archive(self) -> None:
        """Empty tarball returns SUCCESS with 0 records."""
        feed = OSSFMaliciousFeed()
        commit_sha = "empty_sha"

        tarball = _make_tarball([], commit_sha=commit_sha)  # no files

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []

    # ------------------------------------------------------------------
    # Test 18: Non-OSV files skipped
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_non_osv_files_skipped(self) -> None:
        """Non-JSON and non-osv/malicious files in tarball are skipped."""
        feed = OSSFMaliciousFeed()
        commit_sha = "filter_sha"

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Valid OSV file
            good = json.dumps(_npm_record()).encode("utf-8")
            info = tarfile.TarInfo(
                name=f"malicious-packages-{commit_sha}/osv/malicious/npm/evil-pkg/MAL-2025-1234.json",
            )
            info.size = len(good)
            tar.addfile(info, io.BytesIO(good))

            # .md file (not .json) — should be skipped
            readme = b"# readme"
            info2 = tarfile.TarInfo(name=f"malicious-packages-{commit_sha}/README.md")
            info2.size = len(readme)
            tar.addfile(info2, io.BytesIO(readme))

            # .json outside osv/malicious — should be skipped
            other = b"{}"
            info3 = tarfile.TarInfo(name=f"malicious-packages-{commit_sha}/some/other/file.json")
            info3.size = len(other)
            tar.addfile(info3, io.BytesIO(other))
        tarball = buf.getvalue()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1  # only the OSV JSON file parsed

    # ------------------------------------------------------------------
    # Test 19: Commit SHA None
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_fetch_commit_sha_none_returns_failed(self) -> None:
        """Commit SHA lookup returns None → FAILED."""
        feed = OSSFMaliciousFeed()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={})  # no "sha" key
        commit_resp.headers = {}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=commit_resp)

        result = await feed.fetch(session=mock_session)

        assert result.status == FetchStatus.FAILED
        assert result.records == []


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for module constants."""

    def test_commit_url(self) -> None:
        assert GITHUB_COMMIT_URL == ("https://api.github.com/repos/ossf/malicious-packages/commits/main")

    def test_codeload_url_template(self) -> None:
        assert CODELOAD_TARBALL_URL == ("https://codeload.github.com/ossf/malicious-packages/tar.gz/{ref}")

    def test_osv_path_prefix(self) -> None:
        assert OSV_PATH_PREFIX == "osv/malicious/"

    def test_withdrawn_path_prefix(self) -> None:
        assert WITHDRAWN_PATH_PREFIX == "osv/withdrawn/"

    def test_progress_report_interval(self) -> None:
        assert PROGRESS_REPORT_INTERVAL == 500

    def test_retryable_statuses(self) -> None:
        assert RETRYABLE_STATUSES == (429, 500, 502, 503, 504)

    def test_ecosystem_path_map(self) -> None:
        assert ECOSYSTEM_PATH_MAP["npm"] == "npm"
        assert ECOSYSTEM_PATH_MAP["go"] == "go"
        assert ECOSYSTEM_PATH_MAP["cargo"] == "crates.io"
        assert ECOSYSTEM_PATH_MAP["pypi"] == "pypi"
        assert ECOSYSTEM_PATH_MAP["maven"] == "maven"
        assert ECOSYSTEM_PATH_MAP["nuget"] == "nuget"
        assert ECOSYSTEM_PATH_MAP["rubygems"] == "rubygems"
        assert ECOSYSTEM_PATH_MAP["packagist"] == "packagist"
        assert ECOSYSTEM_PATH_MAP["vscode"] == "vscode"
        assert ECOSYSTEM_PATH_MAP["git"] == "git"

    def test_osv_ecosystem_map(self) -> None:
        assert "npm" in OSV_ECOSYSTEM_MAP
        assert "Go" in OSV_ECOSYSTEM_MAP
        assert "crates.io" in OSV_ECOSYSTEM_MAP
        assert "Maven" in OSV_ECOSYSTEM_MAP
        assert "PyPI" in OSV_ECOSYSTEM_MAP
        assert "NuGet" in OSV_ECOSYSTEM_MAP
        assert "RubyGems" in OSV_ECOSYSTEM_MAP
        assert "Packagist" in OSV_ECOSYSTEM_MAP
        assert "Vscode" in OSV_ECOSYSTEM_MAP
        assert "Git" in OSV_ECOSYSTEM_MAP


# ---------------------------------------------------------------------------
# Test: Commit SHA caching
# ---------------------------------------------------------------------------


class TestCommitSHACaching:
    """Tests for commit SHA change detection and caching."""

    @pytest.mark.asyncio
    async def test_cache_hit_skips_phase2(self, tmp_path: Path) -> None:
        """Stored commit SHA matches → Phase 2 skipped."""
        from pkg_defender.db.schema import init_db, set_metadata

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        set_metadata(conn, "ossf_malicious_commit_sha", "cached_sha_123")
        conn.close()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": "cached_sha_123"})
        commit_resp.headers = {}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=commit_resp)

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.status == FetchStatus.SUCCESS
        assert result.records == []
        assert result.feed_metadata.get("commit_sha_hit") is True
        assert mock_session.get.call_count == 1  # only commit SHA check

    @pytest.mark.asyncio
    async def test_cache_miss_proceeds_with_phase2(self, tmp_path: Path) -> None:
        """Stored commit SHA differs → Phase 2 runs normally."""
        from pkg_defender.db.schema import init_db, set_metadata

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        set_metadata(conn, "ossf_malicious_commit_sha", "old_sha_abc")
        conn.close()

        commit_sha = "new_sha_xyz"
        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = AsyncMock(side_effect=mock_get)

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.feed_metadata.get("commit_sha_hit") is None
        assert mock_session.get.call_count == 2  # commit SHA + tarball

    @pytest.mark.asyncio
    async def test_cache_hit_returns_empty_records(self, tmp_path: Path) -> None:
        """Cache hit returns empty records with commit_sha_hit=True."""
        from pkg_defender.db.schema import init_db, set_metadata

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        set_metadata(conn, "ossf_malicious_commit_sha", "cached_sha")
        conn.close()

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": "cached_sha"})
        commit_resp.headers = {}

        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=commit_resp)

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.records == []
        assert result.feed_metadata["commit_sha_hit"] is True
        assert result.feed_metadata["commit_sha"] == "cached_sha"
        assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_no_stored_sha_first_sync(self, tmp_path: Path) -> None:
        """No stored SHA (first sync) proceeds normally."""
        from pkg_defender.db.schema import init_db

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        init_db(db_path).close()  # initialize DB but don't set any metadata

        commit_sha = "first_sha_abc"
        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = AsyncMock(side_effect=mock_get)

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.feed_metadata.get("commit_sha_hit") is None
        assert mock_session.get.call_count == 2

    @pytest.mark.asyncio
    async def test_sha_stored_after_successful_sync(self, tmp_path: Path) -> None:
        """Commit SHA is persisted after successful Phase 2 completion."""
        from pkg_defender.db.schema import get_connection, get_metadata, init_db

        feed = OSSFMaliciousFeed()
        db_path = tmp_path / "test.db"
        init_db(db_path).close()  # initialize DB

        commit_sha = "new_sha_to_store"
        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = mock_get

        result = await feed.fetch(session=mock_session, db_path=db_path)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1

        # Verify SHA was stored
        conn = get_connection(db_path)
        try:
            stored = get_metadata(conn, "ossf_malicious_commit_sha")
        finally:
            conn.close()
        assert stored == commit_sha

    @pytest.mark.asyncio
    async def test_no_db_path_bypasses_cache(self) -> None:
        """When db_path is None, caching is skipped entirely."""
        feed = OSSFMaliciousFeed()
        commit_sha = "no_cache_sha"
        tarball = _make_tarball(
            [("osv/malicious/npm/evil-pkg/MAL-2025-1234.json", _npm_record())],
            commit_sha=commit_sha,
        )

        commit_resp = AsyncMock()
        commit_resp.status = 200
        commit_resp.json = AsyncMock(return_value={"sha": commit_sha})
        commit_resp.headers = {}

        tarball_resp = AsyncMock()
        tarball_resp.status = 200
        tarball_resp.read = AsyncMock(return_value=tarball)
        tarball_resp.headers = {}

        mock_session = AsyncMock()

        async def mock_get(url: str, headers: Any = None) -> AsyncMock:
            if "commits/main" in url:
                return commit_resp
            return tarball_resp

        mock_session.get = AsyncMock(side_effect=mock_get)

        # db_path=None → caching entirely bypassed
        result = await feed.fetch(session=mock_session, db_path=None)

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.feed_metadata.get("commit_sha_hit") is None
        assert mock_session.get.call_count == 2
