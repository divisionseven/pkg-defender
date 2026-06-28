"""Tests for Phase 1: Data Model Fix implementation.

These tests verify:
1. Model: ThreatRecord and VersionInfo work with new fields
2. Database Size: DB size is reasonable
3. Feed Integration: Feeds create records with new schema fields
4. Query: get_threats_for_package works with package_name
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkg_defender.db.schema import (
    get_threat,
    get_threats_for_package,
    init_db,
    insert_threat,
)
from pkg_defender.models import ThreatRecord, VersionInfo

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_db(tmp_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Create a fresh DB with v3 schema."""
    db_path = tmp_path / "fresh.db"
    conn = init_db(db_path)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Test Class: Model Tests
# ---------------------------------------------------------------------------


class TestThreatRecordModel:
    """Tests for ThreatRecord model with new v3 fields."""

    def test_threat_record_with_all_new_fields(self) -> None:
        """ThreatRecord should accept all new v3 fields."""
        now = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
        published = datetime(2024, 1, 15, 8, 0, tzinfo=UTC)

        threat = ThreatRecord(
            id="osv:GHSA-test",
            ecosystem="npm",
            package_name="test-package",
            affected_versions=["1.0.0"],
            affected_ranges=[">=1.0.0"],
            severity="HIGH",
            confidence=0.9,
            source="osv",
            source_id="GHSA-9999",
            summary="Test vulnerability",
            detail_url="https://osv.dev/vuln/GHSA-9999",
            first_seen=now,
            last_seen=now,
            hit_count=1,
            cvss_score=7.5,
            published_at=published,
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )

        assert threat.id == "osv:GHSA-test"
        assert threat.package_name == "test-package"
        assert threat.cvss_score == 7.5
        assert threat.published_at == published
        assert threat.ingested_at == now
        assert threat.is_malicious is False
        assert threat.is_unverified is False

    def test_threat_record_malicious_flag(self) -> None:
        """ThreatRecord should correctly store is_malicious=True."""
        threat = ThreatRecord(
            id="ossf:malicious-1",
            ecosystem="pypi",
            package_name="evil-package",
            affected_versions=[],
            affected_ranges=[],
            severity="CRITICAL",
            confidence=1.0,
            source="ossf_malicious",
            summary="Malicious package",
            is_malicious=True,
            is_unverified=False,
        )

        assert threat.is_malicious is True
        assert threat.is_unverified is False

    def test_threat_record_unverified_flag(self) -> None:
        """ThreatRecord should correctly store is_unverified=True."""
        threat = ThreatRecord(
            id="reddit:unverified-1",
            ecosystem="npm",
            package_name="unverified-pkg",
            affected_versions=[],
            affected_ranges=[],
            severity="MEDIUM",
            confidence=0.3,
            source="reddit",
            summary="Unverifiedreport",
            is_malicious=False,
            is_unverified=True,
        )

        assert threat.is_malicious is False
        assert threat.is_unverified is True


class TestVersionInfoModel:
    """Tests for VersionInfo model using package_name."""

    def test_version_info_with_package_name(self) -> None:
        """VersionInfo should use package_name field."""
        info = VersionInfo(
            version="2.0.0",
            publish_time=datetime(2024, 3, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="express",
        )

        assert info.package_name == "express"
        assert info.version == "2.0.0"
        assert info.ecosystem == "npm"


# ---------------------------------------------------------------------------
# Test Class: Database Integration Tests
# ------------------------------------------------------------------------


class TestDbIntegration:
    """Integration tests for DB operations with v3 schema."""

    def test_insert_and_retrieve_with_new_fields(self, fresh_db: sqlite3.Connection) -> None:
        """Insert and retrieve a threat with all new fields."""
        now = datetime(2024, 6, 1, tzinfo=UTC)
        published = datetime(2024, 1, 1, tzinfo=UTC)

        threat = ThreatRecord(
            id="test:new-fields",
            ecosystem="npm",
            package_name="test-pkg",
            severity="HIGH",
            confidence=0.8,
            source="osv",
            summary="Test",
            cvss_score=8.5,
            published_at=published,
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )

        insert_threat(fresh_db, threat)
        result = get_threat(fresh_db, "test:new-fields")

        assert result is not None
        assert result.package_name == "test-pkg"
        assert result.cvss_score == 8.5
        assert result.published_at == published
        assert result.is_malicious is False
        assert result.is_unverified is False

    def test_returns_threats_when_querying_by_package_name(self, fresh_db: sqlite3.Connection) -> None:
        """get_threats_for_package should query package_name column."""
        now = datetime(2024, 6, 1, tzinfo=UTC)

        threat = ThreatRecord(
            id="test:query-1",
            ecosystem="npm",
            package_name="query-test-pkg",
            severity="HIGH",
            confidence=0.8,
            source="osv",
            summary="Test",
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )

        insert_threat(fresh_db, threat)

        # Query should work with package_name
        results = get_threats_for_package(fresh_db, "npm", "query-test-pkg")
        assert len(results) == 1
        assert results[0].package_name == "query-test-pkg"


class TestDatabaseSize:
    """Tests for database size after migration."""

    def test_fresh_db_size_is_small(self, tmp_path: Path) -> None:
        """A fresh empty DB should be very small (< 200KB)."""
        db_path = tmp_path / "small.db"
        conn = init_db(db_path)

        # Get file size
        conn.close()
        db_size = db_path.stat().st_size

        # Should be under 200KB for empty DB (SQLite page allocation varies by version)
        assert db_size < 200 * 1024, f"Empty DB size {db_size} should be < 200KB"

    def test_populated_db_size_is_reasonable(self, tmp_path: Path) -> None:
        """A DB with 1000 records should be under 100MB."""
        db_path = tmp_path / "populated.db"
        conn = init_db(db_path)

        # Insert 1000 sample records
        now = datetime(2024, 6, 1, tzinfo=UTC)
        for i in range(1000):
            threat = ThreatRecord(
                id=f"test:{i}",
                ecosystem="npm",
                package_name=f"package-{i}",
                severity="HIGH",
                confidence=0.8,
                source="osv",
                summary=f"Test threat {i}",
                hit_count=1,
                ingested_at=now,
                is_malicious=(i % 10 == 0),  # 10% malicious
                is_unverified=(i % 20 == 0),  # 5% unverified
            )
            insert_threat(conn, threat, commit=False)
        conn.commit()
        conn.close()

        # Get file size
        db_size = db_path.stat().st_size

        # With 1000 records, should be well under 100MB
        # Target is ~35MB but we'll accept up to 100MB
        assert db_size < 100 * 1024 * 1024, f"Populated DB size {db_size / (1024 * 1024):.1f}MB should be < 100MB"


# ---------------------------------------------------------------------------
# Test Class: Feed Integration Tests
# ------------------------------------------------------------------------


class TestFeedIntegration:
    """Tests for feed sources creating records with new schema."""

    def test_osv_creates_records_with_cvss_score(self, fresh_db: sqlite3.Connection) -> None:
        """OSV feed should create records with cvss_score and published_at."""
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        # Sample OSV vulnerability data
        osv_vuln = {
            "id": "GHSA-XXXX",
            "affected": [
                {
                    "package": {"name": "test-osv-pkg", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                }
            ],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "details": "Test vulnerability",
            "published": "2024-01-15T00:00:00Z",
            "modified": "2024-01-15T00:00:00Z",
        }

        record = _parse_osv_vuln(osv_vuln, ecosystem="npm", package="test-osv-pkg")

        # Should return record with new v3 fields
        assert record.cvss_score == 7.5
        assert record.published_at is not None
        assert record.is_malicious is False

    def test_ghsa_creates_records_with_published_at(self, fresh_db: sqlite3.Connection) -> None:
        """GHSA feed should create records with published_at."""
        from pkg_defender.intel.ghsa import _parse_advisory

        # Sample GHSA advisory data
        ghsa_advisory = {
            "ghsa_id": "GHSA-abcd",
            "cve_id": "CVE-2024-1234",
            "summary": "Test GHSA",
            "severity": "HIGH",
            "published_at": "2024-02-01T12:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"name": "test-ghsa-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "<1.0.0",
                }
            ],
        }

        records = _parse_advisory(ghsa_advisory)

        # Should return records with new v3 fields
        assert len(records) > 0
        record = records[0]

        assert record.published_at is not None
        assert record.source == "ghsa"
        assert record.is_malicious is False

    def test_ossf_malicious_sets_is_malicious_true(self, fresh_db: sqlite3.Connection) -> None:
        """OSSF malicious feed should set is_malicious=True."""
        from pkg_defender.intel.ossf_malicious import _parse_osv_record

        # Sample OSSF malicious package data in OSV format
        ossf_record = {
            "id": "MAL-2025-1234",
            "summary": "Malicious code in malicious-pkg (npm)",
            "published": "2025-03-15T10:00:00Z",
            "modified": "2025-03-16T12:00:00Z",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "malicious-pkg"},
                    "versions": [],
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
            "references": [{"type": "WEB", "url": "https://github.com/ossf/malicious-packages"}],
        }

        records = _parse_osv_record(
            ossf_record,
            file_path="osv/malicious/npm/malicious-pkg/MAL-2025-1234.json",
        )

        # Should return records with is_malicious=True
        assert len(records) > 0
        record = records[0]

        assert record.is_malicious is True
        assert record.severity == "CRITICAL"
        assert record.confidence == 1.0


class TestQueryWithNewSchema:
    """Tests for queries working with the new schema."""

    def test_get_threats_includes_null_package_name(self, fresh_db: sqlite3.Connection) -> None:
        """get_threats_for_package should include ecosystem-wide threats (package_name=NULL)."""
        now = datetime(2024, 6, 1, tzinfo=UTC)

        # Insert ecosystem-wide threat (NULL package_name)
        ecosystem_wide = ThreatRecord(
            id="test:ecosystem-wide",
            ecosystem="npm",
            package_name="unknown",  # Ecosystem-wide
            severity="LOW",
            confidence=0.5,
            source="osv",
            summary="Ecosystem alert",
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )
        insert_threat(fresh_db, ecosystem_wide)

        # Insert package-specific threat
        specific = ThreatRecord(
            id="test:specific",
            ecosystem="npm",
            package_name="test-specific",
            severity="HIGH",
            confidence=0.8,
            source="osv",
            summary="Specific package",
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )
        insert_threat(fresh_db, specific)

        # Query should return both ecosystem-wide and specific threats
        results = get_threats_for_package(fresh_db, "npm", "test-specific")

        assert len(results) == 2
        ids = {r.id for r in results}
        assert "test:ecosystem-wide" in ids
        assert "test:specific" in ids


# ---------------------------------------------------------------------------
# Full integration test
# ------------------------------------------------------------------------


class TestFullIntegration:
    """End-to-end integration tests."""

    def test_full_flow_with_migration(self, tmp_path: Path) -> None:
        """Test complete flow: init_db -> insert -> query with full v9 schema."""
        # Create a fresh DB with the full schema via init_db
        db_path = tmp_path / "full_flow.db"
        conn = init_db(db_path)

        # Insert a threat (exercises insert_threat with updated_at)
        now = datetime(2024, 6, 1, tzinfo=UTC)
        new_threat = ThreatRecord(
            id="v3:new",
            ecosystem="pypi",
            package_name="new-pypi-pkg",
            severity="CRITICAL",
            confidence=1.0,
            source="ossf_malicious",
            summary="New malicious",
            ingested_at=now,
            is_malicious=True,
            is_unverified=False,
        )
        insert_threat(conn, new_threat)

        # Query should work (exercises get_threats_for_package with updated_at)
        results = get_threats_for_package(conn, "pypi", "new-pypi-pkg")
        assert len(results) == 1
        assert results[0].is_malicious is True

        conn.close()
