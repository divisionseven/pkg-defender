"""Tests for query_threats_by_source and related schema query functions.

Targets: pkg_defender.db.schema.query_threats_by_source
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkg_defender.db.schema import init_db, query_threats_by_source
from pkg_defender.models import ThreatRecord

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_threat_homebrew() -> ThreatRecord:
    """Return a minimal ThreatRecord in the homebrew ecosystem."""
    return ThreatRecord(
        id="homebrew_osv:GHSA-xxxx-xxxx-xxxx",
        ecosystem="homebrew",
        package_name="curl",
        affected_versions=["8.0.0"],
        affected_ranges=["<8.0.1"],
        severity="HIGH",
        confidence=0.9,
        source="homebrew_osv",
        source_id="GHSA-xxxx-xxxx-xxxx",
        summary="Buffer overflow in curl",
        detail_url="https://osv.dev/GHSA-xxxx-xxxx-xxxx",
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen=datetime(2026, 6, 1, tzinfo=UTC),
        hit_count=1,
        cvss_score=7.5,
        published_at=datetime(2026, 1, 1, tzinfo=UTC),
        ingested_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
        is_malicious=False,
        is_unverified=False,
    )


@pytest.fixture()
def sample_threat_homebrew2() -> ThreatRecord:
    """Second homebrew threat for multi-record scenarios."""
    return ThreatRecord(
        id="homebrew_osv:GHSA-yyyy-yyyy-yyyy",
        ecosystem="homebrew",
        package_name="openssl",
        affected_versions=["3.0.0"],
        affected_ranges=["<3.0.1"],
        severity="CRITICAL",
        confidence=0.95,
        source="homebrew_osv",
        source_id="GHSA-yyyy-yyyy-yyyy",
        summary="Remote code execution in openssl",
        detail_url="https://osv.dev/GHSA-yyyy-yyyy-yyyy",
        first_seen=datetime(2026, 2, 1, tzinfo=UTC),
        last_seen=datetime(2026, 6, 1, tzinfo=UTC),
        hit_count=1,
        cvss_score=9.8,
        published_at=datetime(2026, 2, 1, tzinfo=UTC),
        ingested_at=datetime(2026, 6, 1, 14, 0, 0, tzinfo=UTC),
        is_malicious=False,
        is_unverified=False,
    )


@pytest.fixture()
def sample_threat_osv() -> ThreatRecord:
    """A non-homebrew threat for cross-ecosystem filtering tests."""
    return ThreatRecord(
        id="osv:GHSA-zzzz-zzzz-zzzz",
        ecosystem="npm",
        package_name="lodash",
        affected_versions=["4.17.20"],
        affected_ranges=[">=4.0.0,<4.17.21"],
        severity="HIGH",
        confidence=0.85,
        source="osv",
        source_id="GHSA-zzzz-zzzz-zzzz",
        summary="Prototype pollution in lodash",
        detail_url="https://osv.dev/GHSA-zzzz-zzzz-zzzz",
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen=datetime(2026, 6, 1, tzinfo=UTC),
        hit_count=1,
        cvss_score=7.5,
        published_at=datetime(2026, 1, 1, tzinfo=UTC),
        ingested_at=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
        is_malicious=False,
        is_unverified=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestQueryThreatsBySource:
    """Tests for query_threats_by_source()."""

    def test_query_by_ecosystem_and_source(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
        sample_threat_osv: ThreatRecord,
    ) -> None:
        """Query with ecosystem + source returns matching records only."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)
        insert_threat(db_conn, sample_threat_osv, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="homebrew_osv")

        assert len(results) == 1
        assert results[0]["package_name"] == "curl"
        assert results[0]["ecosystem"] == "homebrew"
        assert results[0]["source"] == "homebrew_osv"

    def test_query_by_ecosystem_source_and_ingested_since(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
        sample_threat_homebrew2: ThreatRecord,
    ) -> None:
        """Query with ingested_since filter returns only recent records."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)
        insert_threat(db_conn, sample_threat_homebrew2, commit=True)

        # Filter to only records ingested after the first one
        ingested_since = "2026-06-01T13:00:00"
        results = query_threats_by_source(
            db_conn,
            ecosystem="homebrew",
            source="homebrew_osv",
            ingested_since=ingested_since,
        )

        assert len(results) == 1
        assert results[0]["package_name"] == "openssl"

    def test_query_ingested_since_matches_all(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
        sample_threat_homebrew2: ThreatRecord,
    ) -> None:
        """ingested_since early enough returns all matching records."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)
        insert_threat(db_conn, sample_threat_homebrew2, commit=True)

        results = query_threats_by_source(
            db_conn,
            ecosystem="homebrew",
            source="homebrew_osv",
            ingested_since="2026-01-01T00:00:00",
        )

        assert len(results) == 2

    def test_query_returns_empty_for_non_matching_ecosystem(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
    ) -> None:
        """Query with non-matching ecosystem returns empty list."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="npm", source="homebrew_osv")

        assert results == []

    def test_query_returns_empty_for_non_matching_source(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
    ) -> None:
        """Query with non-matching source returns empty list."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="osv")

        assert results == []

    def test_query_returns_empty_when_no_threats_at_all(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Query on empty table returns empty list."""
        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="homebrew_osv")

        assert results == []

    def test_query_result_contains_all_expected_keys(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
    ) -> None:
        """Each result dict contains all threat table columns."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="homebrew_osv")

        assert len(results) == 1
        row = results[0]
        # Verify key fields are present
        assert row["id"] == "homebrew_osv:GHSA-xxxx-xxxx-xxxx"
        assert row["ecosystem"] == "homebrew"
        assert row["package_name"] == "curl"
        assert row["severity"] == "HIGH"
        assert row["cvss_score"] == 7.5
        assert row["summary"] == "Buffer overflow in curl"

    def test_query_ingested_since_before_all_records(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
    ) -> None:
        """ingested_since after all records returns empty."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)

        results = query_threats_by_source(
            db_conn,
            ecosystem="homebrew",
            source="homebrew_osv",
            ingested_since="2099-01-01T00:00:00",
        )

        assert results == []

    def test_query_with_in_memory_db(self) -> None:
        """query_threats_by_source works with in-memory SQLite database."""
        conn = init_db(Path(":memory:"))
        try:
            conn.execute(
                """INSERT INTO threats
                   (id, ecosystem, package_name, affected_versions, affected_ranges,
                    severity, confidence, source, source_id, summary,
                    ingested_at, is_malicious, is_unverified, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (
                    "homebrew_osv:GHSA-test",
                    "homebrew",
                    "wget",
                    "[]",
                    "[]",
                    "MEDIUM",
                    0.8,
                    "homebrew_osv",
                    "GHSA-test",
                    "Test vulnerability",
                    "2026-06-01T12:00:00",
                    0,
                    0,
                ),
            )
            conn.commit()

            results = query_threats_by_source(conn, ecosystem="homebrew", source="homebrew_osv")

            assert len(results) == 1
            assert results[0]["package_name"] == "wget"
        finally:
            conn.close()


class TestQueryThreatsBySourceEdgeCases:
    """Edge case tests for query_threats_by_source()."""

    def test_query_with_empty_ingested_since(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
    ) -> None:
        """ingested_since=None returns all matching records."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="homebrew_osv", ingested_since=None)

        assert len(results) == 1

    def test_multiple_records_same_source(
        self,
        db_conn: sqlite3.Connection,
        sample_threat_homebrew: ThreatRecord,
        sample_threat_homebrew2: ThreatRecord,
    ) -> None:
        """Multiple records with same source are all returned."""
        from pkg_defender.db.schema import insert_threat

        insert_threat(db_conn, sample_threat_homebrew, commit=True)
        insert_threat(db_conn, sample_threat_homebrew2, commit=True)

        results = query_threats_by_source(db_conn, ecosystem="homebrew", source="homebrew_osv")

        assert len(results) == 2
        package_names = {r["package_name"] for r in results}
        assert package_names == {"curl", "openssl"}
