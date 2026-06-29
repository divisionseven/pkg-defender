"""Tests for the OSV.dev feed."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import zipfile
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from pkg_defender.intel.base import FetchStatus
from pkg_defender.intel.feeds._osv_parser import (
    _extract_cvss_score,
    _parse_osv_vuln,
)
from pkg_defender.intel.feeds.osv import (
    OSV_API_BASE,
    OSV_DUMP_BASE,
    _cvss_to_severity,
    _map_ecosystem,
    _map_severity,
    check_package,
    download_ecosystem_dump,
    fetch_from_dump,
    get_vuln,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SINGLE_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Remote code execution in example-package",
            "details": "A critical vulnerability allows remote code execution...",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [
                {
                    "package": {"name": "example-package", "ecosystem": "npm"},
                    "versions": ["1.0.0", "1.0.1", "1.1.0"],
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.2.0"},
                            ],
                        }
                    ],
                }
            ],
            "published": "2025-06-15T10:00:00Z",
            "modified": "2025-06-16T14:30:00Z",
        }
    ]
}

EMPTY_RESPONSE: dict[str, Any] = {"vulns": []}

SINGLE_VULN_GHSA = {
    "id": "GHSA-abcd-efgh-ijkl",
    "summary": "XSS in lodash",
    "severity": [{"type": "CVSS_V3", "score": "6.1"}],
    "affected": [
        {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "versions": ["4.17.20"],
        }
    ],
    "published": "2025-03-01T00:00:00Z",
    "modified": "2025-03-02T00:00:00Z",
}

RECENT_VULNS_RESPONSE = {
    "vulns": [
        {
            "id": "PYSEC-2025-001",
            "summary": "SQL injection in django",
            "affected": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "versions": ["3.2.0"],
                }
            ],
            "published": "2025-06-01T00:00:00Z",
            "modified": "2025-06-02T00:00:00Z",
        },
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Prototype pollution in axios",
            "affected": [
                {
                    "package": {"name": "axios", "ecosystem": "npm"},
                    "versions": ["0.21.0"],
                }
            ],
            "published": "2025-06-03T00:00:00Z",
            "modified": "2025-06-04T00:00:00Z",
        },
    ]
}


# ---------------------------------------------------------------------------
# _map_ecosystem
# ---------------------------------------------------------------------------


class TestMapEcosystem:
    def test_npm_maps_to_npm(self) -> None:
        assert _map_ecosystem("npm") == "npm"

    def test_pypi_maps_to_pypi(self) -> None:
        assert _map_ecosystem("pypi") == "PyPI"

    def test_unknown_ecosystem_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown ecosystem"):
            _map_ecosystem("invalid-ecosystem-xyz")


# ---------------------------------------------------------------------------
# _cvss_to_severity
# ---------------------------------------------------------------------------


class TestCvssToSeverity:
    def test_critical_9_or_above(self) -> None:
        assert _cvss_to_severity(9.8) == "CRITICAL"
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_high_7_to_9(self) -> None:
        assert _cvss_to_severity(7.0) == "HIGH"
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_medium_4_to_7(self) -> None:
        assert _cvss_to_severity(4.0) == "MEDIUM"
        assert _cvss_to_severity(6.9) == "MEDIUM"

    def test_low_above_0_to_4(self) -> None:
        assert _cvss_to_severity(0.1) == "LOW"
        assert _cvss_to_severity(3.9) == "LOW"

    def test_zero_is_unknown(self) -> None:
        assert _cvss_to_severity(0.0) == "UNKNOWN"


# ---------------------------------------------------------------------------
# _extract_cvss_score
# ---------------------------------------------------------------------------


class TestExtractCvssScore:
    def test_plain_numeric(self) -> None:
        assert _extract_cvss_score("9.8") == 9.8

    def test_empty_string(self) -> None:
        assert _extract_cvss_score("") is None

    def test_out_of_range(self) -> None:
        assert _extract_cvss_score("15.0") is None

    def test_cvss_vector_returns_none(self) -> None:
        # Full vector strings can't be parsed without a calculator
        result = _extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result is None


# ---------------------------------------------------------------------------
# _map_severity
# ---------------------------------------------------------------------------


class TestMapSeverity:
    def test_cvss_score_critical(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert _map_severity(vuln) == "CRITICAL"

    def test_cvss_score_high(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert _map_severity(vuln) == "HIGH"

    def test_cvss_score_medium(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        assert _map_severity(vuln) == "MEDIUM"

    def test_cvss_score_low(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.1"}]}
        assert _map_severity(vuln) == "LOW"

    def test_database_specific_severity(self) -> None:
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert _map_severity(vuln) == "HIGH"

    def test_database_specific_lowercase(self) -> None:
        vuln = {"database_specific": {"severity": "critical"}}
        assert _map_severity(vuln) == "CRITICAL"

    def test_no_severity_returns_unknown(self) -> None:
        assert _map_severity({}) == "UNKNOWN"

    def test_cvss_vector_falls_back_to_db_specific(self) -> None:
        vuln = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "HIGH"},
        }
        assert _map_severity(vuln) == "HIGH"

    def test_empty_severity_list_returns_unknown(self) -> None:
        vuln: dict[str, Any] = {"severity": []}
        assert _map_severity(vuln) == "UNKNOWN"


# ---------------------------------------------------------------------------
# _parse_osv_vuln
# ---------------------------------------------------------------------------


class TestParseOsvVuln:
    def test_returns_threat_record_when_given_valid_vuln_data(self) -> None:
        record = _parse_osv_vuln(SINGLE_VULN_RESPONSE["vulns"][0], ecosystem="npm", package="example-package")
        assert record.id == "osv:GHSA-xxxx-yyyy-zzzz:npm"
        assert record.ecosystem == "npm"
        assert record.package_name == "example-package"
        assert record.severity == "CRITICAL"
        assert record.confidence == 0.9
        assert record.source == "osv"
        assert record.source_id == "GHSA-xxxx-yyyy-zzzz"
        assert record.summary == "Remote code execution in example-package"
        assert record.detail_url == "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
        assert "1.0.0" in record.affected_versions
        assert "1.0.1" in record.affected_versions
        assert "1.1.0" in record.affected_versions
        assert len(record.affected_ranges) > 0
        assert record.first_seen == datetime(2025, 6, 15, 10, 0, 0, tzinfo=UTC)
        assert record.last_seen == datetime(2025, 6, 16, 14, 30, 0, tzinfo=UTC)

    def test_summary_falls_back_to_details(self) -> None:
        vuln = {
            "id": "TEST-001",
            "details": "A" * 300,
            "affected": [],
        }
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="test")
        assert record.summary == "A" * 200

    def test_no_package_infers_from_affected(self) -> None:
        record = _parse_osv_vuln(SINGLE_VULN_RESPONSE["vulns"][0], ecosystem="npm", package=None)
        assert record.package_name == "example-package"

    def test_returns_non_none_timestamps_when_vuln_has_no_timestamps(self) -> None:
        vuln = {"id": "TEST-002", "affected": []}
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="pkg")
        # Should not raise; timestamps should be set to roughly now
        assert record.first_seen is not None
        assert record.last_seen is not None

    def test_cvss_score_extracted(self) -> None:
        vuln = {"id": "TEST-003", "affected": [], "severity": [{"score": "9.8"}]}
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="pkg")
        assert record.cvss_score == 9.8
        assert record.severity == "CRITICAL"

    def test_affected_ranges_no_prefix(self) -> None:
        """OSV ranges must not contain the [SEMVER] prefix."""
        record = _parse_osv_vuln(SINGLE_VULN_RESPONSE["vulns"][0], ecosystem="npm", package="example-package")
        assert len(record.affected_ranges) > 0
        # The range should start with a valid operator, not a bracketed prefix
        for r in record.affected_ranges:
            assert not r.startswith("["), f"Range '{r}' should not start with bracket prefix"
            # Also verify the range starts with an operator prefix from _OPERATORS
            assert any(r.startswith(op) for op in [">=", "<=", "!=", "==", ">", "<"]), (
                f"Range '{r}' should start with a valid operator"
            )

    def test_affected_ranges_clean_content(self) -> None:
        """OSV range strings should be clean operator-prefixed conditions."""
        record = _parse_osv_vuln(SINGLE_VULN_RESPONSE["vulns"][0], ecosystem="npm", package="example-package")
        # The expected range is >=1.0.0, <1.2.0 (comma-space separator from ", ".join)
        assert any(">=1.0.0, <1.2.0" in r for r in record.affected_ranges), (
            f"Expected clean range in {record.affected_ranges}"
        )

    def test_git_range_is_skipped(self) -> None:
        """GIT ranges with commit hashes must be skipped, not included in affected_ranges."""
        vuln = {
            "id": "GIT-SKIP-001",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/test/test",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "abc123def456abc123def456abc123def456abc1"},
                            ],
                        }
                    ],
                }
            ],
        }
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="test-pkg")
        # GIT range should produce NO affected_ranges entries
        assert len(record.affected_ranges) == 0, f"Expected no ranges, got {record.affected_ranges}"

    def test_git_and_ecosystem_range_keeps_ecosystem_only(self) -> None:
        """When both GIT and ECOSYSTEM ranges exist, only ECOSYSTEM should be kept."""
        vuln = {
            "id": "MIXED-001",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/test/test",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "abc123def456abc123def456abc123def456abc1"},
                            ],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        },
                    ],
                }
            ],
        }
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="test-pkg")
        # Only ECOSYSTEM range should remain
        assert len(record.affected_ranges) == 1, f"Expected 1 range, got {record.affected_ranges}"
        assert ">=1.0.0" in record.affected_ranges[0]
        assert "<2.0.0" in record.affected_ranges[0]
        # No commit hash should appear
        assert "abc123" not in record.affected_ranges[0]


# ---------------------------------------------------------------------------
# check_package
# ---------------------------------------------------------------------------


class TestCheckPackage:
    @pytest.mark.asyncio
    async def test_returns_threats_on_match(self) -> None:
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            m.post(url, payload=SINGLE_VULN_RESPONSE)
            results = await check_package("npm", "example-package", "1.0.1")

        assert len(results) == 1
        assert results[0].id == "osv:GHSA-xxxx-yyyy-zzzz:npm"
        assert results[0].package_name == "example-package"
        assert results[0].source == "osv"
        assert results[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_returns_empty_on_no_vulns(self) -> None:
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            m.post(url, payload=EMPTY_RESPONSE)
            results = await check_package("npm", "safe-package", "2.0.0")

        assert results == []

    @pytest.mark.asyncio
    async def test_returns_threats_when_session_provided(self) -> None:
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            m.post(url, payload=SINGLE_VULN_RESPONSE)
            async with aiohttp.ClientSession() as session:
                results = await check_package("npm", "example-package", "1.0.1", session=session)

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_propagates_on_network_error(self) -> None:
        """After removing the except Exception block, network errors propagate."""
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            # All 3 retries fail with connection error
            for _ in range(3):
                m.post(url, exception=aiohttp.ClientError("Connection refused"))
            with pytest.raises(aiohttp.ClientError):
                await check_package("npm", "example-package", "1.0.1")

    @pytest.mark.asyncio
    async def test_check_package_propagates_api_exception(self) -> None:
        """Mock _osv_fetch to raise; exception propagates, not caught and returned as []."""
        with (
            patch(
                "pkg_defender.intel.feeds.osv._osv_fetch",
                side_effect=aiohttp.ClientError("API unavailable"),
            ),
            pytest.raises(aiohttp.ClientError, match="API unavailable"),
        ):
            await check_package(
                "npm",
                "example-package",
                "1.0.1",
                session=MagicMock(),
            )


# ---------------------------------------------------------------------------
# get_vuln
# ---------------------------------------------------------------------------


class TestGetVuln:
    @pytest.mark.asyncio
    async def test_returns_threat_record(self) -> None:
        vuln_data = SINGLE_VULN_RESPONSE["vulns"][0]
        url = f"{OSV_API_BASE}/vulns/GHSA-xxxx-yyyy-zzzz"
        with aioresponses() as m:
            m.get(url, payload=vuln_data)
            result = await get_vuln("GHSA-xxxx-yyyy-zzzz")

        assert result is not None
        assert result.id == "osv:GHSA-xxxx-yyyy-zzzz:npm"
        assert result.source == "osv"

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self) -> None:
        """404 responses still return None (the aiohttp.ClientResponseError 404 handler is preserved)."""
        with patch(
            "pkg_defender.intel.feeds.osv._osv_fetch",
            side_effect=aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=404,
                message="Not Found",
            ),
        ):
            result = await get_vuln("NONEXISTENT-001", session=MagicMock())
            assert result is None

    @pytest.mark.asyncio
    async def test_propagates_on_network_error(self) -> None:
        """After removing the except Exception block, network errors propagate."""
        url = f"{OSV_API_BASE}/vulns/GHSA-xxxx-yyyy-zzzz"
        with aioresponses() as m:
            for _ in range(3):
                m.get(url, exception=aiohttp.ClientError("dns fail"))
            with pytest.raises(aiohttp.ClientError):
                await get_vuln("GHSA-xxxx-yyyy-zzzz")

    @pytest.mark.asyncio
    async def test_get_vuln_propagates_non_404_exception(self) -> None:
        """Non-404 exceptions (e.g. timeout) propagate; not caught and returned as None."""
        with (
            patch(
                "pkg_defender.intel.feeds.osv._osv_fetch",
                side_effect=TimeoutError("Request timed out"),
            ),
            pytest.raises(asyncio.TimeoutError, match="Request timed out"),
        ):
            await get_vuln("GHSA-xxxx-yyyy-zzzz", session=MagicMock())


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


class TestRetry:
    @pytest.mark.asyncio
    async def test_retry_on_500_then_succeed(self) -> None:
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            m.post(url, status=500)
            m.post(url, payload=SINGLE_VULN_RESPONSE)
            results = await check_package("npm", "example-package", "1.0.1")

        assert len(results) == 1
        assert results[0].id == "osv:GHSA-xxxx-yyyy-zzzz:npm"

    @pytest.mark.asyncio
    async def test_retry_on_503_then_succeed(self) -> None:
        url = f"{OSV_API_BASE}/vulns/TEST-RETRY"
        with aioresponses() as m:
            m.get(url, status=503)
            m.get(url, payload=SINGLE_VULN_GHSA)
            result = await get_vuln("TEST-RETRY")

        assert result is not None
        assert result.source_id == "GHSA-abcd-efgh-ijkl"

    @pytest.mark.asyncio
    async def test_retry_on_429_then_succeed(self) -> None:
        url = f"{OSV_API_BASE}/query"
        with (
            aioresponses() as m,
            patch("pkg_defender.intel.feeds.osv._asyncio_sleep", new_callable=AsyncMock),
        ):
            m.post(url, status=429)
            m.post(url, payload=SINGLE_VULN_RESPONSE)
            results = await check_package("npm", "example-package", "1.0.1")

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_no_retry_on_400_propagates(self) -> None:
        """400 Bad Request should not be retried; exception propagates."""
        with (
            patch(
                "pkg_defender.intel.feeds.osv._osv_fetch",
                side_effect=aiohttp.ClientResponseError(
                    request_info=MagicMock(),
                    history=(),
                    status=400,
                    message="Bad Request",
                ),
            ),
            pytest.raises(aiohttp.ClientResponseError, match="Bad Request"),
        ):
            await check_package(
                "npm",
                "example-package",
                "1.0.1",
                session=MagicMock(),
            )

    @pytest.mark.asyncio
    async def test_three_retries_exhausted_propagates(self) -> None:
        """After removing the except Exception block, retry exhaustion propagates."""
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            for _ in range(3):
                m.post(url, status=503)
            with pytest.raises(aiohttp.ClientResponseError):
                await check_package("npm", "example-package", "1.0.1")

    @pytest.mark.asyncio
    async def test_no_retry_on_400_immediate_raise(self) -> None:
        """400 raises ClientResponseError immediately (no retries).

        Regression test for P1.5: the _osv_fetch() non-retryable HTTP
        fallthrough fix. Before the fix, non-retryable statuses like 400
        would fall through to the generic ClientError handler and retry up
        to 3 times. After the fix, they raise immediately at line 364 of
        osv.py. This test exercises the real _osv_fetch code path via
        aioresponses (unlike the mock-based test_no_retry_on_400_propagates).
        """
        url = f"{OSV_API_BASE}/query"
        with aioresponses() as m:
            m.post(url, status=400)
            with pytest.raises(aiohttp.ClientResponseError, match="400"):
                await check_package("npm", "example-package", "1.0.1")


# ---------------------------------------------------------------------------
# Severity mapping from various OSV response formats
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_cvss_numeric_score_9_8(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert _map_severity(vuln) == "CRITICAL"

    def test_cvss_numeric_score_7_5(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert _map_severity(vuln) == "HIGH"

    def test_cvss_numeric_score_5_3(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.3"}]}
        assert _map_severity(vuln) == "MEDIUM"

    def test_cvss_numeric_score_3_1(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "3.1"}]}
        assert _map_severity(vuln) == "LOW"

    def test_database_specific_critical(self) -> None:
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert _map_severity(vuln) == "CRITICAL"

    def test_no_severity_data(self) -> None:
        assert _map_severity({}) == "UNKNOWN"


# ---------------------------------------------------------------------------
# DUMP_ECOSYSTEM_MAP — OSV bulk dump URL construction
# ---------------------------------------------------------------------------


class TestDumpEcosystemMap:
    """Test the ecosystem mapping used for OSV bulk data dump downloads."""

    def test_cargo_maps_to_crates_io(self) -> None:
        """Regression test: cargo must map to crates.io bucket, not 'Cargo'.

        The OSV dump URLs use bucket names like 'crates.io', not 'Cargo'.
        Previously the mapping was incorrectly set to '"cargo": "Cargo"'.
        """
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        assert DUMP_ECOSYSTEM_MAP["cargo"] == "crates.io"

    def test_npm_maps_to_npm(self) -> None:
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        assert DUMP_ECOSYSTEM_MAP["npm"] == "npm"

    def test_pypi_maps_to_pypi(self) -> None:
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        assert DUMP_ECOSYSTEM_MAP["pypi"] == "PyPI"

    def test_all_ecosystems_have_mappings(self) -> None:
        """Verify all expected ecosystems are present in the dump map."""
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        expected = {
            "npm",
            "pypi",
            "go",
            "cargo",
            "rubygems",
            "maven",
            "nuget",
            "packagist",
            "apt",
            "yum",
            "dnf",
        }
        assert set(DUMP_ECOSYSTEM_MAP.keys()) == expected

    @pytest.mark.asyncio
    async def test_download_url_construction_for_cargo(self) -> None:
        """Verify cargo ecosystem constructs correct OSV dump URL.

        The URL should be: https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip
        NOT: https://storage.googleapis.com/osv-vulnerabilities/Cargo/all.zip
        """
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        osv_eco = DUMP_ECOSYSTEM_MAP["cargo"]
        expected_url = f"{OSV_DUMP_BASE}/{osv_eco}/all.zip"
        assert expected_url == "https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip"


# ---------------------------------------------------------------------------
# fetch_from_dump — dedup logic for ecosystems sharing a dump key
# ---------------------------------------------------------------------------


class TestFetchFromDumpDedup:
    """Test that fetch_from_dump groups ecosystems by dump key.

    When multiple ecosystems (e.g., ``"yum"`` and ``"dnf"``) map to the same
    OSV dump bucket (e.g., ``"Linux"``), the dump should be downloaded only
    once and records should be produced for all mapped ecosystems.
    """

    SAMPLE_VULN: dict[str, Any] = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Test vulnerability",
        "affected": [
            {
                "package": {"name": "test-package", "ecosystem": "linux"},
                "versions": ["1.0.0"],
            }
        ],
        "published": "2025-06-15T10:00:00Z",
        "modified": "2025-06-16T14:30:00Z",
    }

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_yum_dnf_dedup_single_download(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """Verify that yum and dnf share one download instead of two."""
        mock_download.return_value = [self.SAMPLE_VULN]

        result = await fetch_from_dump(ecosystems=["yum", "dnf"])

        # One download call for the shared "Linux" dump key
        mock_download.assert_awaited_once()

        # Both ecosystems appear in the metadata
        eco_results = result.feed_metadata["ecosystem_results"]
        eco_names = [e["ecosystem"] for e in eco_results]
        assert "yum" in eco_names
        assert "dnf" in eco_names

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_yum_dnf_produces_both_ecosystem_records(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """Verify both yum and dnf records are produced from one download."""
        mock_download.return_value = [self.SAMPLE_VULN]

        result = await fetch_from_dump(ecosystems=["yum", "dnf"])

        records = result.records
        yum_records = [r for r in records if r.ecosystem == "yum"]
        dnf_records = [r for r in records if r.ecosystem == "dnf"]

        assert len(yum_records) >= 1
        assert len(dnf_records) >= 1

        # Same vulnerability, same source_id, but different ecosystem labels
        assert yum_records[0].source_id == dnf_records[0].source_id
        assert yum_records[0].id != dnf_records[0].id
        assert yum_records[0].id.endswith(":yum")
        assert dnf_records[0].id.endswith(":dnf")

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_dedup_does_not_affect_distinct_ecosystems(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """Verify ecosystems with different dump keys are downloaded separately."""
        mock_download.return_value = [self.SAMPLE_VULN]

        result = await fetch_from_dump(ecosystems=["npm", "pypi"])

        # Two separate download calls: one for npm, one for PyPI
        assert mock_download.await_count == 2

        eco_results = result.feed_metadata["ecosystem_results"]
        assert len(eco_results) == 2

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_dedup_with_explicit_ecosystems(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """Verify single ecosystem still works correctly."""
        mock_download.return_value = [self.SAMPLE_VULN]

        result = await fetch_from_dump(ecosystems=["dnf"])

        mock_download.assert_awaited_once()

        records = result.records
        assert all(r.ecosystem == "dnf" for r in records)

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_all_ecosystems_no_duplicate_downloads(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """Verify that with all ecosystems, downloads are fewer than total ecosystems."""
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        mock_download.return_value = [self.SAMPLE_VULN]

        result = await fetch_from_dump(ecosystems=None)

        unique_dump_keys = len(set(DUMP_ECOSYSTEM_MAP.values()))
        total_ecosystems = len(DUMP_ECOSYSTEM_MAP)

        # Downloads match unique dump keys (yum+dnf → one "Linux" key)
        assert mock_download.await_count == unique_dump_keys

        # This proves dedup reduces downloads
        assert total_ecosystems > unique_dump_keys

        # All ecosystems still get results
        eco_results = result.feed_metadata["ecosystem_results"]
        assert len(eco_results) == total_ecosystems

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump", new_callable=AsyncMock)
    async def test_fetch_from_dump_passes_progress_callback(
        self,
        mock_download: AsyncMock,
    ) -> None:
        """progress_callback is forwarded to download_ecosystem_dump."""
        callback = MagicMock()
        mock_download.return_value = [self.SAMPLE_VULN]

        await fetch_from_dump(ecosystems=["npm"], progress_callback=callback)

        mock_download.assert_awaited_once()
        assert mock_download.call_args[1]["progress_callback"] is callback


# ---------------------------------------------------------------------------
# Tempfile streaming for download_ecosystem_dump
# ---------------------------------------------------------------------------


class TestDownloadEcosystemDumpStreaming:
    """Integration-style tests for the tempfile streaming path.

    These tests exercise the actual streaming-to-tempfile logic in
    ``download_ecosystem_dump`` (not mocked at the function level).
    """

    @pytest.mark.asyncio
    async def test_streams_to_tempfile_and_parses_zip(self) -> None:
        """Verify streaming to tempfile correctly parses zip and cleans up."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "vuln1.json",
                json.dumps({"id": "GHSA-1111-2222-3333", "affected": []}),
            )
            zf.writestr(
                "vuln2.json",
                json.dumps({"id": "GHSA-4444-5555-6666", "affected": []}),
            )
        zip_bytes = buf.getvalue()

        async def _iter_chunks() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (zip_bytes, False)
            yield (b"", True)

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks

        session = AsyncMock()
        session.get.return_value = resp

        with patch("pkg_defender.intel.feeds.osv.os.unlink") as mock_unlink:
            result = await download_ecosystem_dump("npm", session=session)

        assert len(result) == 2
        assert result[0]["id"] == "GHSA-1111-2222-3333"
        assert result[1]["id"] == "GHSA-4444-5555-6666"
        mock_unlink.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleans_up_tempfile_on_failure(self) -> None:
        """Verify tempfile is cleaned up when streaming fails mid-way."""

        async def _iter_chunks_fail() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (b"partial data", False)
            raise aiohttp.ClientError("Connection lost during streaming")

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks_fail

        session = AsyncMock()
        session.get.return_value = resp

        with (
            patch("pkg_defender.intel.feeds.osv.get_max_retries", return_value=1),
            patch("pkg_defender.intel.feeds.osv.os.unlink") as mock_unlink,
            pytest.raises(aiohttp.ClientError),
        ):
            await download_ecosystem_dump("npm", session=session)

        assert mock_unlink.called

    @pytest.mark.asyncio
    async def test_rejects_invalid_zip_cleanly(self) -> None:
        """Verify BadZipFile is raised and tempfile is cleaned up."""

        async def _iter_chunks_garbage() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (b"not a valid zip file at all", False)
            yield (b"", True)

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks_garbage

        session = AsyncMock()
        session.get.return_value = resp

        with (
            patch("pkg_defender.intel.feeds.osv.get_max_retries", return_value=1),
            patch("pkg_defender.intel.feeds.osv.os.unlink") as mock_unlink,
            pytest.raises(zipfile.BadZipFile),
        ):
            await download_ecosystem_dump("npm", session=session)

        assert mock_unlink.called

    @pytest.mark.asyncio
    async def test_download_with_progress_callback(self) -> None:
        """Progress callback is called with chunk sizes during download."""
        vuln_data = {"id": "GHSA-test-0001", "summary": "Test", "affected": []}
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.json", json.dumps(vuln_data))
        zip_bytes = zip_buffer.getvalue()

        progress_callback = MagicMock()

        with patch("pkg_defender.intel.feeds.osv.get_max_retries", return_value=3), aioresponses() as mocked:
            mocked.get(
                f"{OSV_DUMP_BASE}/npm/all.zip",
                body=zip_bytes,
                status=200,
                headers={"ETag": '"abc123"'},
                repeat=True,
            )
            result = await download_ecosystem_dump(
                "npm",
                progress_callback=progress_callback,
            )

        progress_callback.assert_called()
        call_args = progress_callback.call_args[0]
        assert isinstance(call_args[0], int)  # first arg is chunk size (int)
        # Verify content_length was passed (second arg is int or None)
        assert len(call_args) >= 2
        assert isinstance(call_args[1], int) or call_args[1] is None
        assert len(result) == 1
        assert result[0]["id"] == "GHSA-test-0001"


# ---------------------------------------------------------------------------
# ETag conditional caching for download_ecosystem_dump
# ---------------------------------------------------------------------------


class TestEtagCaching:
    """ETag-based conditional download caching."""

    @staticmethod
    def _create_metadata_db(tmp_path: Path) -> Path:
        """Create a minimal SQLite DB with the db_metadata table."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS db_metadata ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
        conn.commit()
        conn.close()
        return db_path

    # ------------------------------------------------------------------
    # 304 Not Modified — returns empty list
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_304_returns_empty_list(self) -> None:
        """Verify 304 response returns empty list without parsing."""
        resp = MagicMock()
        resp.status = 304

        session = AsyncMock()
        session.get.return_value = resp

        result = await download_ecosystem_dump("npm", session=session)
        assert result == []

    # ------------------------------------------------------------------
    # If-None-Match header sent when ETag cached
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_etag_header_sent_when_cached(self, tmp_path: Path) -> None:
        """Verify If-None-Match header is sent when ETag is cached."""
        from pkg_defender.db.schema import get_connection, set_metadata

        # Setup temp DB with a stored ETag
        db_path = self._create_metadata_db(tmp_path)
        conn = get_connection(db_path)
        set_metadata(conn, "osv_etag:npm", '"test-etag-123"')
        conn.close()

        # Mock session to return 304 (no body)
        resp = MagicMock()
        resp.status = 304

        session = AsyncMock()
        session.get.return_value = resp

        from pkg_defender.config.settings import DatabaseConfig

        config = MagicMock()
        config.database = DatabaseConfig()

        with patch("pkg_defender.intel.feeds.osv.get_db_path", return_value=db_path):
            result = await download_ecosystem_dump("npm", session=session, config=config)

        assert result == []

        # Verify header was sent
        _, call_kwargs = session.get.call_args
        assert call_kwargs.get("headers", {}).get("If-None-Match") == '"test-etag-123"'

    # ------------------------------------------------------------------
    # New ETag stored on successful 200 response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_etag_stored_on_200(self, tmp_path: Path) -> None:
        """Verify new ETag is stored on successful 200 response."""
        from pkg_defender.db.schema import get_connection

        db_path = self._create_metadata_db(tmp_path)

        # Build a valid zip for the response
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("vuln.json", json.dumps({"id": "GHSA-0001", "affected": []}))
        zip_bytes = buf.getvalue()

        async def _iter_chunks() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (zip_bytes, False)
            yield (b"", True)

        resp = MagicMock()
        resp.status = 200
        resp.raise_for_status = MagicMock()
        resp.headers = {"ETag": '"new-etag-456"'}
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks

        session = AsyncMock()
        session.get.return_value = resp

        from pkg_defender.config.settings import DatabaseConfig

        config = MagicMock()
        config.database = DatabaseConfig()

        with (
            patch("pkg_defender.intel.feeds.osv.get_db_path", return_value=db_path),
            patch("pkg_defender.intel.feeds.osv.os.unlink"),
        ):
            result = await download_ecosystem_dump("npm", session=session, config=config)

        assert len(result) == 1

        # Verify ETag was stored
        conn = get_connection(db_path)
        stored = conn.execute("SELECT value FROM db_metadata WHERE key = 'osv_etag:npm'").fetchone()
        assert stored is not None
        assert stored[0] == '"new-etag-456"'
        conn.close()

    # ------------------------------------------------------------------
    # No ETag header when config is None (backward compat)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_no_etag_when_config_none(self) -> None:
        """Verify no If-None-Match header when config is None."""
        # Build an empty zip for the streaming path
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED):
            pass  # Empty zip
        zip_bytes = buf.getvalue()

        async def _iter_chunks() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (zip_bytes, False)
            yield (b"", True)

        resp = MagicMock()
        resp.status = 200
        resp.raise_for_status = MagicMock()
        resp.headers = {}
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks

        session = AsyncMock()
        session.get.return_value = resp

        with patch("pkg_defender.intel.feeds.osv.os.unlink"):
            result = await download_ecosystem_dump("npm", session=session)

        assert result == []

        # Verify no If-None-Match header was sent
        _, call_kwargs = session.get.call_args
        assert "headers" not in call_kwargs or "If-None-Match" not in call_kwargs.get("headers", {})

    # ------------------------------------------------------------------
    # ETag lookup failure degrades gracefully
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_etag_lookup_failure_degrades_gracefully(self) -> None:
        """Verify ETag lookup failure falls back to full download."""
        # Build an empty zip for the streaming path
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED):
            pass  # Empty zip
        zip_bytes = buf.getvalue()

        async def _iter_chunks() -> AsyncGenerator[tuple[bytes, bool], None]:
            yield (zip_bytes, False)
            yield (b"", True)

        resp = MagicMock()
        resp.status = 200
        resp.raise_for_status = MagicMock()
        resp.headers = {}
        resp.content = MagicMock()
        resp.content.iter_chunks = _iter_chunks

        session = AsyncMock()
        session.get.return_value = resp

        config = MagicMock()
        with (
            patch(
                "pkg_defender.intel.feeds.osv.get_db_path",
                side_effect=RuntimeError("DB unavailable"),
            ),
            patch("pkg_defender.intel.feeds.osv.os.unlink"),
        ):
            result = await download_ecosystem_dump("npm", session=session, config=config)

        # Falls back to full download (empty zip = empty result)
        assert result == []


# ---------------------------------------------------------------------------
# fetch_from_dump — FetchStatus computation
# ---------------------------------------------------------------------------


class TestFetchFromDumpStatus:
    """Regression: P0.3 — fetch_from_dump must return correct FetchStatus."""

    async def test_partial_when_some_ecosystems_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PARTIAL when some ecosystems succeed and some fail."""
        call_count = 0

        async def mock_download(eco: str, **kw: Any) -> list[Any]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            raise RuntimeError("Download failed")

        monkeypatch.setattr("pkg_defender.intel.feeds.osv.download_ecosystem_dump", mock_download)
        result = await fetch_from_dump(ecosystems=["pypi", "npm"])
        assert result.status == FetchStatus.PARTIAL, f"Expected PARTIAL, got {result.status}"
        assert len(result.records) == 0

    async def test_failed_when_all_ecosystems_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FAILED when all ecosystems fail."""

        async def mock_download(eco: str, **kw: Any) -> list[Any]:
            raise RuntimeError("Download failed")

        monkeypatch.setattr("pkg_defender.intel.feeds.osv.download_ecosystem_dump", mock_download)
        result = await fetch_from_dump(ecosystems=["pypi", "npm"])
        assert result.status == FetchStatus.FAILED, f"Expected FAILED, got {result.status}"
        assert len(result.records) == 0

    async def test_returns_success_status_when_all_ecosystems_succeed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SUCCESS when all ecosystems succeed (no regression)."""

        async def mock_download(eco: str, **kw: Any) -> list[Any]:
            return []

        monkeypatch.setattr("pkg_defender.intel.feeds.osv.download_ecosystem_dump", mock_download)
        result = await fetch_from_dump(ecosystems=["pypi"])
        assert result.status == FetchStatus.SUCCESS, f"Expected SUCCESS, got {result.status}"
        assert len(result.records) == 0

    async def test_returns_success_status_when_ecosystems_list_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SUCCESS when ecosystems list is empty."""
        result = await fetch_from_dump(ecosystems=[])
        assert result.status == FetchStatus.SUCCESS, f"Expected SUCCESS, got {result.status}"
