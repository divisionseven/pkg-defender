"""Tests for the pre-install checker."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from pkg_defender.core.checker import (
    BLOCK_SCORE_THRESHOLD,
    _parse_version,
    _safe_fromisoformat,
    check_package,
    check_packages_batch,
)
from pkg_defender.db.schema import insert_threat
from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln
from pkg_defender.models import ThreatRecord
from pkg_defender.version import _check_range, _check_single_condition, _compare_versions, _version_matches

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_threat(
    *,
    id: str = "osv:TEST-001",
    ecosystem: str = "npm",
    package_name: str = "lodash",
    affected_versions: list[str] | None = None,
    affected_ranges: list[str] | None = None,
    severity: str = "HIGH",
    confidence: float = 0.85,
    source: str = "osv",
    source_id: str | None = "TEST-001",
    summary: str = "test threat",
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> ThreatRecord:
    """Helper to build a ThreatRecord with sane defaults."""
    return ThreatRecord(
        id=id,
        ecosystem=ecosystem,
        package_name=package_name,
        affected_versions=affected_versions if affected_versions is not None else [],
        affected_ranges=affected_ranges if affected_ranges is not None else [],
        severity=severity,
        confidence=confidence,
        source=source,
        source_id=source_id,
        summary=summary,
        detail_url=None,
        first_seen=first_seen or datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=last_seen or datetime(2024, 6, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Version parsing tests
# ---------------------------------------------------------------------------


class TestParseVersion:
    """Tests for _parse_version."""

    def test_simple_version(self) -> None:
        """'1.2.3' -> (1, 2, 3)."""
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_prerelease_suffix(self) -> None:
        """'1.2.3-beta.1' -> release tuple (1, 2, 3)."""
        assert _parse_version("1.2.3-beta.1") == (1, 2, 3)

    def test_prerelease_alpha(self) -> None:
        """'2.0.0-alpha.2' -> release tuple (2, 0, 0)."""
        assert _parse_version("2.0.0-alpha.2") == (2, 0, 0)

    def test_v_prefix(self) -> None:
        """'v1.2.3' -> (1, 2, 3)."""
        assert _parse_version("v1.2.3") == (1, 2, 3)

    def test_v_prefix_upper(self) -> None:
        """'V2.0.0' -> (2, 0, 0)."""
        assert _parse_version("V2.0.0") == (2, 0, 0)

    def test_single_component(self) -> None:
        """'5' -> (5,)."""
        assert _parse_version("5") == (5,)

    def test_two_components(self) -> None:
        """'10.20' -> (10, 20)."""
        assert _parse_version("10.20") == (10, 20)

    def test_build_metadata(self) -> None:
        """'1.0.0+build.123' -> (1, 0, 0)."""
        assert _parse_version("1.0.0+build.123") == (1, 0, 0)


# ---------------------------------------------------------------------------
# Version comparison tests
# ---------------------------------------------------------------------------


class TestCompareVersions:
    """Tests for _compare_versions."""

    def test_equal(self) -> None:
        assert _compare_versions("1.2.3", "1.2.3") == 0

    def test_less_than(self) -> None:
        assert _compare_versions("1.2.3", "1.2.4") == -1

    def test_greater_than(self) -> None:
        assert _compare_versions("2.0.0", "1.9.9") == 1

    def test_different_lengths(self) -> None:
        assert _compare_versions("1.2", "1.2.3") == -1

    def test_prerelease_vs_release(self) -> None:
        """Pre-release is less than release per PEP 440."""
        assert _compare_versions("1.2.3-beta", "1.2.3") == -1


# ---------------------------------------------------------------------------
# Version matching tests
# ---------------------------------------------------------------------------


class TestVersionMatches:
    """Tests for _version_matches."""

    def test_exact_match(self) -> None:
        result = _version_matches("4.17.20", ["4.17.20", "4.17.19"], [">=4.0.0"])
        assert result == "exact"

    def test_no_match(self) -> None:
        result = _version_matches("4.18.0", ["4.17.20"], [])
        assert result is None

    def test_range_match_gte(self) -> None:
        result = _version_matches("1.2.0", [], [">=1.0.0"])
        assert result == "range"

    def test_range_match_exact_boundary(self) -> None:
        result = _version_matches("1.0.0", [], [">=1.0.0"])
        assert result == "range"

    def test_range_no_match_below(self) -> None:
        result = _version_matches("0.9.0", [], [">=1.0.0"])
        assert result is None

    def test_exact_takes_priority_over_range(self) -> None:
        """Exact match is checked first."""
        result = _version_matches("1.0.0", ["1.0.0"], [">=1.0.0"])
        assert result == "exact"

    def test_empty_lists(self) -> None:
        result = _version_matches("1.0.0", [], [])
        assert result is None

    def test_ecosystem_wide_no_versions(self) -> None:
        """Threat with no affected versions/ranges returns None."""
        result = _version_matches("1.0.0", [], [])
        assert result is None


# ---------------------------------------------------------------------------
# check_package integration tests
# ---------------------------------------------------------------------------


class TestCheckPackage:
    """Tests for the main check_package function."""

    def test_exact_version_match_blocked(self, db_conn: sqlite3.Connection) -> None:
        """Version in affected_versions -> blocked."""
        threat = _make_threat(
            id="osv:EXACT-1",
            affected_versions=["1.2.3", "1.2.4"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.2.3")
        assert result.blocked is True
        assert len(result.threats) == 1
        assert result.threats[0].version_match_type == "exact"

    def test_version_not_in_affected_not_blocked(self, db_conn: sqlite3.Connection) -> None:
        """Version not in affected_versions and not in range -> not blocked."""
        threat = _make_threat(
            id="osv:NOT-1",
            affected_versions=["1.2.3"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.2.4")
        assert result.blocked is False
        assert len(result.threats) == 0

    def test_range_match_blocks(self, db_conn: sqlite3.Connection) -> None:
        """Version >=1.0.0 in range '>=1.0.0' -> blocked."""
        threat = _make_threat(
            id="osv:RANGE-1",
            affected_versions=[],
            affected_ranges=[">=1.0.0"],
            severity="HIGH",
            confidence=0.85,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.2.0")
        assert result.blocked is True
        assert result.threats[0].version_match_type == "range"

    def test_range_no_match_below(self, db_conn: sqlite3.Connection) -> None:
        """Version 0.9.0 below range '>=1.0.0' -> not blocked."""
        threat = _make_threat(
            id="osv:RANGE-2",
            affected_versions=[],
            affected_ranges=[">=1.0.0"],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "0.9.0")
        assert result.blocked is False

    def test_ecosystem_wide_threat_with_range(self, db_conn: sqlite3.Connection) -> None:
        """package=None threat with matching range -> blocked."""
        threat = _make_threat(
            id="osv:ECO-1",
            package_name="unknown",
            affected_versions=[],
            affected_ranges=[">=2.0.0"],
            severity="HIGH",
            confidence=0.8,
            first_seen=datetime(2026, 4, 1, tzinfo=UTC),
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "any-package", "3.0.0")
        assert result.blocked is True
        assert result.threats[0].version_match_type == "range"

    def test_ecosystem_wide_threat_no_version_match(self, db_conn: sqlite3.Connection) -> None:
        """package=None threat with no matching range -> not blocked."""
        threat = _make_threat(
            id="osv:ECO-2",
            package_name="unknown",
            affected_versions=[],
            affected_ranges=[">=5.0.0"],
            severity="LOW",
            confidence=0.5,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "some-pkg", "1.0.0")
        assert result.blocked is False

    def test_no_threats_found(self, db_conn: sqlite3.Connection) -> None:
        """Empty DB -> not blocked, no threats."""
        result = check_package(db_conn, "npm", "lodash", "4.17.21")
        assert result.blocked is False
        assert result.threats == []
        assert result.highest_score == 0.0
        assert result.highest_severity == "UNKNOWN"

    def test_multiple_threats_highest_score(self, db_conn: sqlite3.Connection) -> None:
        """Multiple matching threats -> blocked, highest score and severity used."""
        now = datetime(2026, 4, 2, tzinfo=UTC)
        t_low = _make_threat(
            id="osv:LOW-1",
            affected_versions=["2.0.0"],
            severity="LOW",
            source="osv",
            first_seen=now,
        )
        t_critical = _make_threat(
            id="osv:CRIT-1",
            affected_versions=["2.0.0"],
            severity="CRITICAL",
            source="osv",
            first_seen=now,
        )
        insert_threat(db_conn, t_low)
        insert_threat(db_conn, t_critical)

        result = check_package(db_conn, "npm", "lodash", "2.0.0", now=now)
        assert result.blocked is True
        assert len(result.threats) == 2
        # CRITICAL * osv_confidence(0.9) = 0.9
        # (no corroboration — checker calls score_threat individually)
        assert result.highest_score == pytest.approx(0.9)
        assert result.highest_severity == "CRITICAL"

    def test_different_ecosystem_ignored(self, db_conn: sqlite3.Connection) -> None:
        """Threat for 'pypi' should not match 'npm' check."""
        threat = _make_threat(
            id="osv:PYPI-1",
            ecosystem="pypi",
            package_name="requests",
            affected_versions=["2.31.0"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "requests", "2.31.0")
        assert result.blocked is False

    def test_different_package_ignored(self, db_conn: sqlite3.Connection) -> None:
        """Threat for 'axios' should not match 'lodash' check."""
        threat = _make_threat(
            id="osv:AXIOS-1",
            package_name="axios",
            affected_versions=["1.0.0"],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.0.0")
        assert result.blocked is False

    def test_social_source_below_threshold_not_blocked(self, db_conn: sqlite3.Connection) -> None:
        """Social source UNKNOWN severity scores below BLOCK_SCORE_THRESHOLD -> not blocked."""
        # UNKNOWN (0.1) * mastodon (0.4) * decay(~1.0) = ~0.04, well below 0.3.
        # Board mandate: social feeds are informational only.
        threat = _make_threat(
            id="osv:ZERO-1",
            affected_versions=["1.0.0"],
            severity="UNKNOWN",
            confidence=0.0,
            source="mastodon",
            first_seen=datetime(2026, 3, 25, tzinfo=UTC),
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.0.0")
        assert result.blocked is False
        assert result.highest_score < BLOCK_SCORE_THRESHOLD

    def test_safe_version_is_none(self, db_conn: sqlite3.Connection) -> None:
        """safe_version should always be None (cooldown engine provides it)."""
        threat = _make_threat(
            id="osv:SAFE-1",
            affected_versions=["1.0.0"],
            severity="HIGH",
            confidence=1.0,
        )
        insert_threat(db_conn, threat)
        result = check_package(db_conn, "npm", "lodash", "1.0.0")
        assert result.safe_version is None

    def test_osv_parsed_range_blocks_version(self, db_conn: sqlite3.Connection) -> None:
        """OSV-parsed range data must block a version within the range."""
        vuln = {
            "id": "OSV-PIPELINE-1",
            "summary": "Test pipeline",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-02T00:00:00Z",
        }
        record = _parse_osv_vuln(vuln, ecosystem="npm", package="test-pkg")

        # Insert into DB
        insert_threat(db_conn, record)

        # Verify that a version within range is blocked
        result = check_package(db_conn, "npm", "test-pkg", "1.5.0")
        assert result.blocked is True
        assert len(result.threats) == 1
        assert result.threats[0].version_match_type == "range"

        # Verify that a version outside range is NOT blocked
        result2 = check_package(db_conn, "npm", "test-pkg", "3.0.0")
        assert result2.blocked is False

    def test_malformed_timestamp_skipped(self, db_conn: sqlite3.Connection, caplog: pytest.LogCaptureFixture) -> None:
        """Malformed ISO timestamp in threat row is handled gracefully in check_package()."""
        import logging

        caplog.set_level(logging.WARNING)

        # Insert a threat with bad timestamps directly (bypass insert_threat validation)
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, affected_versions, "
            "affected_ranges, severity, confidence, source, first_seen, last_seen, "
            "published_at, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "TEST-BAD-TS-1",
                "npm",
                "test-pkg",
                '["1.0.0"]',
                "[]",
                "HIGH",
                0.85,
                "osv",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
            ),
        )

        # Should not raise ValueError
        result = check_package(db_conn, "npm", "test-pkg", "1.0.0")
        assert result is not None
        assert any("Malformed ISO timestamp" in msg for msg in caplog.messages)


# ---------------------------------------------------------------------------
# check_packages_batch tests
# ---------------------------------------------------------------------------


class TestCheckPackagesBatch:
    """Tests for the batch threat checker (check_packages_batch)."""

    def test_multi_ecosystem_threat_check(self, db_conn: sqlite3.Connection) -> None:
        """Both ecosystems' threats detected — regression test for indentation bug.

        On the buggy code, only the last ecosystem's threats were populated
        because the ``for row in rows:`` loop was outside the ``for eco`` loop.
        """
        # Insert threat for pip package
        pip_threat = _make_threat(
            id="osv:REG-PIP-1",
            ecosystem="pip",
            package_name="requests",
            affected_versions=["1.0.0"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, pip_threat)

        # Insert threat for npm package (different ecosystem)
        npm_threat = _make_threat(
            id="osv:REG-NPM-1",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, npm_threat)

        packages = [("pip", "requests", "1.0.0"), ("npm", "lodash", "4.17.20")]
        results = check_packages_batch(db_conn, packages)

        # Both packages must have results with blocked=True
        pip_key = ("pip", "requests", "1.0.0")
        npm_key = ("npm", "lodash", "4.17.20")

        assert pip_key in results, f"Expected pip result in {list(results.keys())}"
        assert npm_key in results, f"Expected npm result in {list(results.keys())}"
        assert results[pip_key].blocked is True, "pip requests should be blocked"
        assert results[npm_key].blocked is True, "npm lodash should be blocked"

    def test_batch_single_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """Single-ecosystem batch works correctly (happy path)."""
        threat = _make_threat(
            id="osv:SINGLE-1",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, threat)

        packages = [("npm", "lodash", "4.17.20"), ("npm", "lodash", "4.17.21")]
        results = check_packages_batch(db_conn, packages)

        key_affected = ("npm", "lodash", "4.17.20")
        key_safe = ("npm", "lodash", "4.17.21")

        assert key_affected in results
        assert key_safe in results
        assert results[key_affected].blocked is True
        assert results[key_safe].blocked is False

    def test_batch_empty_packages(self, db_conn: sqlite3.Connection) -> None:
        """Empty package list returns empty dict."""
        results = check_packages_batch(db_conn, [])
        assert results == {}

    def test_batch_with_ecosystem_wide_threats(self, db_conn: sqlite3.Connection) -> None:
        """Ecosystem-wide threats apply to all packages in their ecosystem.

        Verifies that ``get_ecosystem_null_threats`` runs correctly per ecosystem.
        """
        # Ecosystem-wide threat for pip (applies to ALL pip packages)
        eco_pip = _make_threat(
            id="osv:ECOPIP-1",
            ecosystem="pip",
            package_name="unknown",
            affected_versions=[],
            affected_ranges=[">=0.0.0"],
            severity="HIGH",
            confidence=0.8,
        )
        insert_threat(db_conn, eco_pip)

        # Package-specific threat for npm
        pkg_npm = _make_threat(
            id="osv:ECONPM-1",
            ecosystem="npm",
            package_name="express",
            affected_versions=["4.0.0"],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, pkg_npm)

        packages = [
            ("pip", "any-pip-pkg", "1.0.0"),
            ("npm", "express", "4.0.0"),
        ]
        results = check_packages_batch(db_conn, packages)

        pip_key = ("pip", "any-pip-pkg", "1.0.0")
        npm_key = ("npm", "express", "4.0.0")

        assert pip_key in results
        assert npm_key in results
        # Pip package should be blocked by ecosystem-wide threat
        assert results[pip_key].blocked is True
        # Npm package should be blocked by package-specific threat
        assert results[npm_key].blocked is True

    def test_batch_no_threats_multi_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """Multi-ecosystem batch with no threats in DB — all packages return safe results.

        Ensures that even with zero threats, every package gets a proper
        CheckResult and no keys are missing or silently dropped.
        """
        packages = [
            ("pip", "flask", "2.0.0"),
            ("pip", "django", "4.0.0"),
            ("npm", "react", "18.0.0"),
            ("rubygems", "rails", "7.0.0"),
        ]
        results = check_packages_batch(db_conn, packages)

        # Every package must appear in results
        for pkg_key in packages:
            assert pkg_key in results, f"Missing result for {pkg_key}"
            assert results[pkg_key].blocked is False
            assert results[pkg_key].threats == []
            assert results[pkg_key].highest_score == 0.0
            assert results[pkg_key].highest_severity == "UNKNOWN"

    def test_malformed_timestamp_batch(self, db_conn: sqlite3.Connection, caplog: pytest.LogCaptureFixture) -> None:
        """Malformed ISO timestamp in threat row is handled gracefully in batch path."""
        import logging

        caplog.set_level(logging.WARNING)

        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, affected_versions, "
            "affected_ranges, severity, confidence, source, first_seen, last_seen, "
            "published_at, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "TEST-BAD-TS-BATCH-1",
                "npm",
                "test-pkg",
                '["1.0.0"]',
                "[]",
                "HIGH",
                0.85,
                "osv",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
                "not-a-valid-timestamp",
            ),
        )

        results = check_packages_batch(db_conn, [("npm", "test-pkg", "1.0.0")])
        assert ("npm", "test-pkg", "1.0.0") in results
        assert any("Malformed ISO timestamp" in msg for msg in caplog.messages)

    def test_malformed_json_logs_warning(self, db_conn: sqlite3.Connection, caplog: pytest.LogCaptureFixture) -> None:
        """Malformed affected_versions in batch path logs warning instead of silent skip."""
        import logging

        caplog.set_level(logging.WARNING)

        # Insert a threat with malformed JSON in affected_versions (valid timestamps)
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, affected_versions, "
            "affected_ranges, severity, confidence, source, first_seen, last_seen, "
            "published_at, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "TEST-BAD-JSON-1",
                "npm",
                "test-pkg",
                "{malformed json}",
                "[]",
                "HIGH",
                0.85,
                "osv",
                "2024-01-01T00:00:00",
                "2024-06-01T00:00:00",
                "2024-01-01T00:00:00",
                "2024-06-01T12:00:00",
            ),
        )
        # Insert a clean threat for the same package
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, affected_versions, "
            "affected_ranges, severity, confidence, source, first_seen, last_seen, "
            "published_at, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "TEST-CLEAN-1",
                "npm",
                "test-pkg",
                '["1.0.0"]',
                "[]",
                "HIGH",
                0.85,
                "osv",
                "2024-01-01T00:00:00",
                "2024-06-01T00:00:00",
                "2024-01-01T00:00:00",
                "2024-06-01T12:00:00",
            ),
        )

        results = check_packages_batch(db_conn, [("npm", "test-pkg", "1.0.0")])
        assert ("npm", "test-pkg", "1.0.0") in results
        assert any("Malformed JSON" in msg for msg in caplog.messages)


class TestCheckSingleCondition:
    """Tests for _check_single_condition (regression for DS-001)."""

    def test_clean_range_matches(self) -> None:
        """Clean condition '>=1.0.0' should match version 1.2.0."""
        assert _check_single_condition("1.2.0", ">=1.0.0") is True

    def test_prefixed_range_rejected(self) -> None:
        """Prefixed condition '[SEMVER] >=1.0.0' should NOT match (regression check)."""
        # This is the exact format the bug produced — it MUST not match
        assert _check_single_condition("1.2.0", "[SEMVER] >=1.0.0") is False

    def test_clean_range_no_match(self) -> None:
        """Clean condition '>=2.0.0' should NOT match version 1.0.0."""
        assert _check_single_condition("1.0.0", ">=2.0.0") is False

    def test_clean_compound_range_split(self) -> None:
        """After split, each condition in compound range works independently."""
        # '>=1.0.0,<2.0.0' splits into ['>=1.0.0', '<2.0.0'] — both should pass
        assert _check_range("1.5.0", ">=1.0.0,<2.0.0") is True
        assert _check_range("0.5.0", ">=1.0.0,<2.0.0") is False
        assert _check_range("2.5.0", ">=1.0.0,<2.0.0") is False

    def test_prefixed_compound_range_rejected(self) -> None:
        """Compound range with '[SEMVER]' prefix must NOT match either condition."""
        # '[SEMVER] >=1.0.0,<2.0.0' splits into ['[SEMVER] >=1.0.0', '<2.0.0']
        # First condition fails startswith check, falls to exact match — fails
        # Second condition '<2.0.0' works, but first condition must also pass (AND)
        assert _check_range("1.5.0", "[SEMVER] >=1.0.0,<2.0.0") is False


class TestSafeFromIsoFormat:
    """Tests for _safe_fromisoformat helper."""

    def test_safe_fromisoformat_valid(self) -> None:
        """Valid ISO timestamp returns parsed datetime."""
        result = _safe_fromisoformat("2024-01-15T10:30:00+00:00", datetime.now(UTC))
        assert result == datetime(2024, 1, 15, 10, 30, tzinfo=UTC)

    def test_safe_fromisoformat_none(self) -> None:
        """None value returns default."""
        default = datetime.now(UTC)
        result = _safe_fromisoformat(None, default)
        assert result == default

    def test_safe_fromisoformat_invalid(self, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid ISO timestamp returns default and logs warning."""
        import logging

        caplog.set_level(logging.WARNING)
        default = datetime(2024, 1, 1, tzinfo=UTC)
        result = _safe_fromisoformat("not-a-timestamp", default)
        assert result == default
        assert any("Malformed ISO timestamp" in msg for msg in caplog.messages)
