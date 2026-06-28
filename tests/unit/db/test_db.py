"""Tests for the database schema and operations."""

from __future__ import annotations

import getpass
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from pkg_defender.db.schema import (
    _format_utc_z,
    _validate_threat,
    classify_precision,
    get_all_version_timestamps_for_package,
    get_audit_event_stats,
    get_audit_events,
    get_connection,
    get_feed_state,
    get_feed_stats_history,
    get_metadata,
    get_threat,
    get_threats_for_package,
    get_version_timestamp,
    get_version_timestamps_batch,
    init_db,
    insert_audit_event,
    insert_bypass,
    insert_feed_stats,
    insert_threat,
    insert_threats_bulk,
    insert_version_timestamp,
    set_metadata,
    update_feed_state,
)
from pkg_defender.models import ThreatRecord, VersionInfo

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_threat() -> ThreatRecord:
    """Return a minimal valid ThreatRecord."""
    return ThreatRecord(
        id="osv:GHSA-1234",
        ecosystem="npm",
        package_name="lodash",
        affected_versions=["4.17.20"],
        affected_ranges=[">=4.0.0,<4.17.21"],
        severity="HIGH",
        confidence=0.85,
        source="osv",
        source_id="GHSA-1234",
        summary="Prototype pollution in lodash",
        detail_url="https://osv.dev/GHSA-1234",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 6, 1, tzinfo=UTC),
        hit_count=1,
        cvss_score=7.5,
        published_at=datetime(2024, 1, 1, tzinfo=UTC),
        ingested_at=datetime(2024, 6, 1, tzinfo=UTC),
        is_malicious=False,
        is_unverified=False,
    )


# ---------------------------------------------------------------------------
# Schema init tests
# ---------------------------------------------------------------------------


class TestInitDb:
    """Tests for database initialisation."""

    def test_init_db_creates_all_tables(self, tmp_path: Path) -> None:
        """init_db should create threats, version_timestamps, bypasses,
        and feed_state tables."""
        db_path = tmp_path / "tables.db"
        conn = init_db(db_path)

        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()

        assert "threats" in tables
        assert "version_timestamps" in tables
        assert "bypasses" in tables
        assert "feed_state" in tables

    def test_wal_mode_enabled(self, tmp_path: Path) -> None:
        """WAL mode must be active after init_db."""
        db_path = tmp_path / "wal.db"
        conn = init_db(db_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode.lower() == "wal"

    def test_init_db_idempotent(self, tmp_path: Path) -> None:
        """Calling init_db twice should not raise."""
        db_path = tmp_path / "idempotent.db"
        conn1 = init_db(db_path)
        conn1.close()
        conn2 = init_db(db_path)
        conn2.close()


# ---------------------------------------------------------------------------
# PRAGMA tests
# ---------------------------------------------------------------------------


class TestConnectionPragmas:
    """Tests for SQLite PRAGMA settings on new connections."""

    def test_default_pragmas_set(self, tmp_path: Path) -> None:
        """All 7 PRAGMAs should be set on a new connection from get_connection().

        Regression guard: if someone removes or changes a PRAGMA, this catches it.
        """
        db_path = tmp_path / "pragmas.db"
        conn = get_connection(db_path)

        # 1. journal_mode=WAL
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

        # 2. busy_timeout=5000
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 5000

        # 3. foreign_keys=ON (1)
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

        # 4. synchronous=NORMAL (1)
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        assert sync == 1  # 1 = NORMAL

        # 5. cache_size=-80000 (80 MB in kibibytes)
        cache = conn.execute("PRAGMA cache_size").fetchone()[0]
        assert cache == -80000

        # 6. temp_store=MEMORY (2)
        temp = conn.execute("PRAGMA temp_store").fetchone()[0]
        assert temp == 2  # 2 = MEMORY

        # 7. quick_check passes on fresh database
        rows = conn.execute("PRAGMA quick_check").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "ok"

        conn.close()

    def test_quick_check_detects_corruption(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """get_connection() should log a warning when DB is corrupt but still return a connection."""
        import random
        import string

        db_path = tmp_path / "corrupt.db"

        # Create a valid DB with enough data to span multiple pages
        conn = get_connection(db_path)
        conn.execute("CREATE TABLE t(x)")
        for i in range(500):
            conn.execute("INSERT INTO t VALUES (?)", (i,))
        conn.commit()
        conn.close()

        # Corrupt a data page (not the schema page) — offset 20000 is
        # well past the 100-byte header and first few schema pages
        # for a 4KB page-size database with 500 rows.
        data = bytearray(db_path.read_bytes())
        garbage = "".join(random.choice(string.printable) for _ in range(100)).encode()
        offset = min(20000, len(data) - 100)
        data[offset : offset + 100] = garbage
        db_path.write_bytes(data)

        # get_connection should log a warning but still succeed
        with caplog.at_level("WARNING"):
            conn2 = get_connection(db_path)
        assert conn2 is not None
        assert isinstance(conn2, sqlite3.Connection)
        conn2.close()

        # Verify warning was logged
        assert any(
            "quick check FAILED" in record.message or "could not be completed" in record.message
            for record in caplog.records
        )

    def test_connection_pragmas_with_config(self, tmp_path: Path) -> None:
        """PRAGMAs should reflect DatabaseConfig when config is passed."""
        from pkg_defender.config.settings import DatabaseConfig

        db_path = tmp_path / "config_pragmas.db"

        # Custom config: no WAL, 30s busy timeout
        config = DatabaseConfig(wal_mode=False, busy_timeout_ms=30000)
        conn = get_connection(db_path, config=config)

        # journal_mode should be DELETE (not WAL)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "delete"

        # busy_timeout should be 30000 (not 5000)
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 30000

        # Non-configurable PRAGMAs should still be set
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        assert sync == 1  # NORMAL

        conn.close()


# ---------------------------------------------------------------------------
# Threat CRUD tests
# ---------------------------------------------------------------------------


class TestInsertThreat:
    """Tests for insert_threat and get_threat."""

    def test_malformed_json_in_threat_raises(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Threat with malformed JSON in affected_versions raises (covers _row_to_threat error path)."""
        # Insert a row directly (bypassing insert_threat validation) with bad JSON
        db_conn.execute(
            """
            INSERT INTO threats (id, ecosystem, package_name, affected_versions,
                severity, confidence, source, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "test:badjson",
                "npm",
                "test-pkg",
                "{bad json}",  # Not valid JSON
                "LOW",
                0.5,
                "osv",
                "2024-01-01T00:00:00+00:00",
                "2024-01-01T00:00:00+00:00",
            ),
        )

        with pytest.raises(json.JSONDecodeError):
            get_threat(db_conn, "test:badjson")

    def test_insert_and_retrieve_threat(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """A stored threat should be retrievable by id with matching fields."""
        insert_threat(db_conn, sample_threat)
        result = get_threat(db_conn, "osv:GHSA-1234")
        assert result is not None
        assert result.id == sample_threat.id
        assert result.ecosystem == "npm"
        assert result.package_name == "lodash"
        assert result.severity == "HIGH"
        assert result.confidence == 0.85
        assert result.affected_versions == ["4.17.20"]
        assert result.affected_ranges == [">=4.0.0,<4.17.21"]
        assert result.cvss_score == 7.5

    def test_get_threat_not_found(self, db_conn: sqlite3.Connection) -> None:
        """Querying a missing id returns None."""
        assert get_threat(db_conn, "nonexistent:1") is None

    def test_insert_or_replace_idempotency(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """INSERT OR REPLACE should upsert — second call updates, no duplicate."""
        insert_threat(db_conn, sample_threat)
        sample_threat.severity = "CRITICAL"
        sample_threat.confidence = 1.0
        insert_threat(db_conn, sample_threat)

        result = get_threat(db_conn, "osv:GHSA-1234")
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.confidence == 1.0

        count = db_conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 1

    def test_get_threats_for_package(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """get_threats_for_package returns matching threats."""
        insert_threat(db_conn, sample_threat)
        results = get_threats_for_package(db_conn, "npm", "lodash")
        assert len(results) == 1
        assert results[0].id == "osv:GHSA-1234"

    def test_get_threats_includes_ecosystem_wide(self, db_conn: sqlite3.Connection) -> None:
        """Threats with package_name='unknown' (ecosystem-wide) should be included."""
        threat = ThreatRecord(
            id="osv:ECOSYSTEM-WIDE",
            ecosystem="npm",
            package_name="unknown",
            affected_versions=[],
            affected_ranges=[],
            severity="LOW",
            confidence=0.5,
            source="osv",
            source_id=None,
            summary="ecosystem alert",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            cvss_score=None,
            published_at=None,
            ingested_at=datetime(2024, 1, 1, tzinfo=UTC),
            is_malicious=False,
            is_unverified=False,
        )
        insert_threat(db_conn, threat)
        results = get_threats_for_package(db_conn, "npm", "lodash")
        assert len(results) == 1
        assert results[0].id == "osv:ECOSYSTEM-WIDE"


class TestInsertThreatsBulk:
    """Tests for insert_threats_bulk()."""

    def test_inserts_multiple_threats(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """Bulk insert stores all records."""
        # Build 5 unique threats from the fixture template
        base = sample_threat
        threats = [
            ThreatRecord(
                id=f"test-bulk-{i}",
                ecosystem=base.ecosystem,
                package_name=base.package_name,
                affected_versions=base.affected_versions,
                affected_ranges=base.affected_ranges,
                severity=base.severity,
                confidence=base.confidence,
                source=base.source,
                source_id=f"{base.source_id}-{i}",
                summary=base.summary,
                detail_url=base.detail_url,
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                hit_count=base.hit_count,
                cvss_score=base.cvss_score,
                published_at=base.published_at,
                ingested_at=base.ingested_at,
                is_malicious=base.is_malicious,
                is_unverified=base.is_unverified,
            )
            for i in range(5)
        ]

        count = insert_threats_bulk(db_conn, threats, commit=True)
        assert count == 5

        for t in threats:
            row = db_conn.execute("SELECT id, package_name FROM threats WHERE id = ?", (t.id,)).fetchone()
            assert row is not None
            assert row[1] == t.package_name

    def test_equivalence_with_insert_threat(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """Bulk insert produces identical DB state as single-row inserts."""
        # Insert via executemany
        insert_threats_bulk(db_conn, [sample_threat], commit=True)

        bulk_row = db_conn.execute("SELECT * FROM threats WHERE id = ?", (sample_threat.id,)).fetchone()

        # Insert a different threat via single-row path
        threat2 = ThreatRecord(
            id="test-equivalence-single",
            ecosystem=sample_threat.ecosystem,
            package_name=sample_threat.package_name,
            affected_versions=sample_threat.affected_versions,
            affected_ranges=sample_threat.affected_ranges,
            severity=sample_threat.severity,
            confidence=sample_threat.confidence,
            source=sample_threat.source,
            source_id="EQ-001",
            summary=sample_threat.summary,
            detail_url=sample_threat.detail_url,
            first_seen=sample_threat.first_seen,
            last_seen=sample_threat.last_seen,
            hit_count=sample_threat.hit_count,
            cvss_score=sample_threat.cvss_score,
            published_at=sample_threat.published_at,
            ingested_at=sample_threat.ingested_at,
            is_malicious=sample_threat.is_malicious,
            is_unverified=sample_threat.is_unverified,
        )
        insert_threat(db_conn, threat2, commit=True)

        single_row = db_conn.execute("SELECT * FROM threats WHERE id = ?", (threat2.id,)).fetchone()

        # Same number of columns
        assert len(bulk_row) == len(single_row)

    def test_skips_invalid_source_records(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """Records with invalid source are skipped, valid ones still inserted."""
        # Threat with invalid source
        invalid = ThreatRecord(
            id="test-bulk-invalid-source",
            ecosystem="npm",
            package_name="bad-pkg",
            affected_versions=[],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.85,
            source="fake_source",  # Not in VALID_SOURCES
            source_id="INVALID-001",
            summary="Should be skipped",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            hit_count=1,
            cvss_score=5.0,
            published_at=None,
            ingested_at=datetime(2024, 1, 1, tzinfo=UTC),
            is_malicious=False,
            is_unverified=False,
        )

        count = insert_threats_bulk(db_conn, [sample_threat, invalid], commit=True)
        assert count == 1  # only valid inserted

        # Verify valid is present
        row = db_conn.execute("SELECT id FROM threats WHERE id = ?", (sample_threat.id,)).fetchone()
        assert row is not None

        # Verify invalid is absent
        row = db_conn.execute("SELECT id FROM threats WHERE id = ?", (invalid.id,)).fetchone()
        assert row is None

    def test_empty_list_is_noop(self, db_conn: sqlite3.Connection) -> None:
        """Empty records list does nothing and returns 0."""
        count = insert_threats_bulk(db_conn, [], commit=True)
        assert count == 0

    def test_commit_false_requires_external_commit(
        self,
        db_conn: sqlite3.Connection,
        sample_threat: ThreatRecord,
    ) -> None:
        """With commit=False inside explicit BEGIN, rollback discards writes."""
        threat_id = "test-bulk-rollback"
        threat = ThreatRecord(
            id=threat_id,
            ecosystem=sample_threat.ecosystem,
            package_name=sample_threat.package_name,
            affected_versions=sample_threat.affected_versions,
            affected_ranges=sample_threat.affected_ranges,
            severity=sample_threat.severity,
            confidence=sample_threat.confidence,
            source=sample_threat.source,
            source_id="RB-001",
            summary=sample_threat.summary,
            detail_url=sample_threat.detail_url,
            first_seen=sample_threat.first_seen,
            last_seen=sample_threat.last_seen,
            hit_count=sample_threat.hit_count,
            cvss_score=sample_threat.cvss_score,
            published_at=sample_threat.published_at,
            ingested_at=sample_threat.ingested_at,
            is_malicious=sample_threat.is_malicious,
            is_unverified=sample_threat.is_unverified,
        )

        # Start an explicit transaction; insert with commit=False
        db_conn.execute("BEGIN IMMEDIATE")
        insert_threats_bulk(db_conn, [threat], commit=False)
        # Rollback — data should be discarded
        db_conn.rollback()

        # Verify the threat was NOT persisted
        row = db_conn.execute("SELECT id, package_name FROM threats WHERE id = ?", (threat_id,)).fetchone()
        assert row is None


# ---------------------------------------------------------------------------
# Validation equivalence tests — both insert_threat and insert_threats_bulk
# must produce identical rejection/acceptance for every validation rule.
# ---------------------------------------------------------------------------


class TestValidationEquivalence:
    """Both insert paths reject the same invalid inputs identically."""

    def _valid_base(self) -> ThreatRecord:
        """Return a minimal valid ThreatRecord for use in equivalence tests."""
        return ThreatRecord(
            id="validation-eq-test",
            ecosystem="npm",
            package_name="test-pkg",
            affected_versions=[],
            affected_ranges=[],
            severity="LOW",
            confidence=0.5,
            source="osv",
            source_id="EQ-001",
            summary="equivalence test",
            detail_url="https://example.com",
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            hit_count=1,
            cvss_score=5.0,
            published_at=None,
            ingested_at=datetime(2024, 1, 1, tzinfo=UTC),
            is_malicious=False,
            is_unverified=False,
        )

    def _assert_both_reject(self, db_conn: sqlite3.Connection, threat: ThreatRecord) -> None:
        """Assert that both insert_threat and insert_threats_bulk reject a record."""
        # insert_threat should skip (no insert) and return None
        insert_threat(db_conn, threat, commit=True)
        row = db_conn.execute("SELECT id FROM threats WHERE id = ?", (threat.id,)).fetchone()
        assert row is None, f"insert_threat should have rejected {threat.id}"

        # insert_threats_bulk should skip (0 count) and not insert
        count = insert_threats_bulk(db_conn, [threat], commit=True)
        assert count == 0, f"insert_threats_bulk should have rejected {threat.id}"
        row = db_conn.execute("SELECT id FROM threats WHERE id = ?", (threat.id,)).fetchone()
        assert row is None, f"insert_threats_bulk should not have inserted {threat.id}"

    def test_both_paths_reject_missing_id(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with id=None."""
        threat = self._valid_base()
        threat.id = None  # type: ignore[assignment]
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_missing_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with ecosystem=None."""
        threat = self._valid_base()
        threat.ecosystem = None  # type: ignore[assignment]
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_invalid_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with ecosystem not in VALID_ECOSYSTEMS."""
        threat = self._valid_base()
        threat.ecosystem = "invalid_ecosystem"
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_invalid_source(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with source not in VALID_SOURCES."""
        threat = self._valid_base()
        threat.source = "fake_source"
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_out_of_range_cvss(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with cvss_score > 10."""
        threat = self._valid_base()
        threat.cvss_score = 15.0
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_non_boolean_is_malicious(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with non-boolean is_malicious."""
        threat = self._valid_base()
        # Use a value that fails `not in (True, False)` — int 2 is neither 0 nor 1
        object.__setattr__(threat, "is_malicious", 2)
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_non_boolean_is_unverified(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with non-boolean is_unverified."""
        threat = self._valid_base()
        object.__setattr__(threat, "is_unverified", 2)
        self._assert_both_reject(db_conn, threat)

    def test_both_paths_reject_invalid_detail_url(self, db_conn: sqlite3.Connection) -> None:
        """Both paths skip a threat with detail_url not starting with http:// or https://."""
        threat = self._valid_base()
        threat.detail_url = "ftp://bad.com"
        self._assert_both_reject(db_conn, threat)

    def test_validate_threat_coerces_package_name(self, db_conn: sqlite3.Connection) -> None:
        """_validate_threat coerces package_name=None to 'unknown'.

        Verify both insert_threat and insert_threats_bulk insert the record
        with the coerced package_name.
        """
        # --- Proof via direct _validate_threat call ---
        threat = self._valid_base()
        threat.package_name = None  # type: ignore[assignment]
        validated = _validate_threat(threat)
        assert validated is not None
        assert validated.package_name == "unknown"

        # --- Proof via insert_threat ---
        threat2 = self._valid_base()
        threat2.id = "validation-eq-coerce-single"
        threat2.package_name = None  # type: ignore[assignment]
        insert_threat(db_conn, threat2, commit=True)
        row = db_conn.execute(
            "SELECT package_name FROM threats WHERE id = ?",
            (threat2.id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"

        # --- Proof via insert_threats_bulk ---
        threat3 = self._valid_base()
        threat3.id = "validation-eq-coerce-bulk"
        threat3.package_name = None  # type: ignore[assignment]
        count = insert_threats_bulk(db_conn, [threat3], commit=True)
        assert count == 1
        row = db_conn.execute(
            "SELECT package_name FROM threats WHERE id = ?",
            (threat3.id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"


# ---------------------------------------------------------------------------
# CHECK constraint tests
# ---------------------------------------------------------------------------


class TestCheckConstraints:
    """Tests that SQLite CHECK constraints reject invalid data."""

    def test_rejects_invalid_severity(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with severity not in the allowed set must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO threats
                    (id, ecosystem, severity, confidence, source,
                     first_seen, last_seen)
                VALUES ('bad:sev', 'npm', 'CRITCAL', 0.5, 'osv',
                        '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
                """
            )

    def test_rejects_confidence_out_of_range(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with confidence > 1.0 must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO threats
                    (id, ecosystem, severity, confidence, source,
                     first_seen, last_seen)
                VALUES ('bad:conf', 'npm', 'HIGH', 1.5, 'osv',
                        '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
                """
            )

    def test_rejects_invalid_source(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with unrecognised source must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO threats
                    (id, ecosystem, severity, confidence, source,
                     first_seen, last_seen)
                VALUES ('bad:src', 'npm', 'LOW', 0.5, 'fake_source',
                        '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
                """
            )

    def test_rejects_invalid_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with unrecognised ecosystem must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO threats
                    (id, ecosystem, severity, confidence, source,
                     first_seen, last_seen)
                VALUES ('bad:eco', 'invalid_ecosystem', 'LOW', 0.5, 'osv',
                        '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
                """
            )

    def test_rejects_negative_hit_count(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with hit_count < 0 must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO threats
                    (id, ecosystem, severity, confidence, source,
                     first_seen, last_seen, hit_count)
                VALUES ('bad:hit', 'npm', 'LOW', 0.5, 'osv',
                        '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00',
                        -1)
                """
            )

    def test_accepts_unknown_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """INSERT with ecosystem='unknown' must succeed (social feeds)."""
        db_conn.execute(
            """
            INSERT INTO threats
            (id, ecosystem, package_name, severity, confidence, source,
             first_seen, last_seen)
            VALUES ('social:test1', 'unknown', 'unknown', 'UNKNOWN', 0.4, 'mastodon',
                    '2024-01-01T00:00:00+00:00', '2024-01-01T00:00:00+00:00')
            """
        )
        row = db_conn.execute("SELECT ecosystem FROM threats WHERE id = 'social:test1'").fetchone()
        assert row is not None
        assert row[0] == "unknown"

    def test_accepts_homebrew_osv_source_at_sql_level(self, db_conn: sqlite3.Connection) -> None:
        """SQL CHECK constraint must accept 'homebrew_osv' as a valid source.

        Proves both the Python VALID_SOURCES check (via insert_threat)
        and the SQL CHECK constraint accept the new source value.
        """
        threat = ThreatRecord(
            id="homebrew_osv:GHSA-0001",
            ecosystem="homebrew",
            package_name="curl",
            affected_versions=["7.0.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="homebrew_osv",
            source_id="GHSA-0001",
            summary="Test homebrew_osv SQL check",
            detail_url="https://osv.dev/vulnerability/GHSA-0001",
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            hit_count=1,
        )
        insert_threat(db_conn, threat)
        row = db_conn.execute("SELECT source FROM threats WHERE id = 'homebrew_osv:GHSA-0001'").fetchone()
        assert row is not None
        assert row[0] == "homebrew_osv"


# ---------------------------------------------------------------------------
# Dedup Key Fix tests — cross-ecosystem and namespace collision verification
# ---------------------------------------------------------------------------


class TestCrossEcosystemDedupFix:
    """Verification tests for PLAN-02 dedup key fix.

    These tests prove that the id format change (`osv:{id}:{ecosystem}` for
    OSV and `homebrew_osv:{id}` for Homebrew) correctly prevents SQL-level
    duplicate conflicts for records that differ only by ecosystem or feed.
    """

    def test_cross_ecosystem_osv_records_both_stored(self, db_conn: sqlite3.Connection) -> None:
        """Two OSV records with same osv_id but different ecosystems both survive.

        Before the PLAN-02 fix, both records would have ``id=osv:GHSA-xxxx``
        causing a SQL ``ON CONFLICT(id)`` collision that silently overwrote
        the first record. After the fix, the ecosystem-qualified id
        (``osv:GHSA-xxxx:npm`` vs ``osv:GHSA-xxxx:pypi``) makes them
        distinct SQL rows.
        """
        npm_threat = ThreatRecord(
            id="osv:GHSA-xxxx:npm",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            affected_ranges=[],
            severity="CRITICAL",
            confidence=0.9,
            source="osv",
            source_id="GHSA-xxxx",
            summary="RCE in lodash",
            detail_url="https://osv.dev/vulnerability/GHSA-xxxx",
            first_seen=datetime(2025, 6, 1, tzinfo=UTC),
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
            hit_count=1,
        )
        pypi_threat = ThreatRecord(
            id="osv:GHSA-xxxx:pypi",
            ecosystem="pypi",
            package_name="lodash",
            affected_versions=["2.0.0"],
            affected_ranges=[],
            severity="CRITICAL",
            confidence=0.9,
            source="osv",
            source_id="GHSA-xxxx",
            summary="RCE in lodash",
            detail_url="https://osv.dev/vulnerability/GHSA-xxxx",
            first_seen=datetime(2025, 6, 1, tzinfo=UTC),
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
            hit_count=1,
        )

        insert_threat(db_conn, npm_threat)
        insert_threat(db_conn, pypi_threat)

        npm_row = db_conn.execute("SELECT id, ecosystem FROM threats WHERE id = 'osv:GHSA-xxxx:npm'").fetchone()
        pypi_row = db_conn.execute("SELECT id, ecosystem FROM threats WHERE id = 'osv:GHSA-xxxx:pypi'").fetchone()

        assert npm_row is not None, "npm record should exist in DB"
        assert pypi_row is not None, "pypi record should exist in DB"
        assert npm_row["ecosystem"] == "npm"
        assert pypi_row["ecosystem"] == "pypi"

    def test_homebrew_and_osv_namespace_no_collision(self, db_conn: sqlite3.Connection) -> None:
        """A Homebrew record and an OSV record with the same OSV ID both survive.

        Before the PLAN-02 fix, the Homebrew adapter used ``id=osv:{osv_id}``
        which collided with the OSV adapter's id. After the fix, Homebrew uses
        ``id=homebrew_osv:{osv_id}`` while OSV uses ``id=osv:{osv_id}:{ecosystem}``,
        making them distinct SQL rows.
        """
        homebrew_threat = ThreatRecord(
            id="homebrew_osv:GHSA-xxxx",
            ecosystem="homebrew",
            package_name="curl",
            affected_versions=["7.0.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="homebrew_osv",
            source_id="GHSA-xxxx",
            summary="Vuln in curl",
            detail_url="https://osv.dev/vulnerability/GHSA-xxxx",
            first_seen=datetime(2025, 6, 1, tzinfo=UTC),
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
            hit_count=1,
        )
        osv_threat = ThreatRecord(
            id="osv:GHSA-xxxx:npm",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            affected_ranges=[],
            severity="CRITICAL",
            confidence=0.9,
            source="osv",
            source_id="GHSA-xxxx",
            summary="RCE in lodash",
            detail_url="https://osv.dev/vulnerability/GHSA-xxxx",
            first_seen=datetime(2025, 6, 1, tzinfo=UTC),
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
            hit_count=1,
        )

        insert_threat(db_conn, homebrew_threat)
        insert_threat(db_conn, osv_threat)

        hb_row = db_conn.execute("SELECT id, source FROM threats WHERE id = 'homebrew_osv:GHSA-xxxx'").fetchone()
        osv_row = db_conn.execute("SELECT id, source FROM threats WHERE id = 'osv:GHSA-xxxx:npm'").fetchone()

        assert hb_row is not None, "Homebrew record should exist in DB"
        assert osv_row is not None, "OSV record should exist in DB"
        assert hb_row["source"] == "homebrew_osv"
        assert osv_row["source"] == "osv"


# ---------------------------------------------------------------------------
# Version Timestamp tests
# ---------------------------------------------------------------------------


class TestVersionTimestamp:
    """Tests for insert_version_timestamp and get_version_timestamp."""

    def test_insert_and_retrieve_timestamp(self, db_conn: sqlite3.Connection) -> None:
        """A stored timestamp should be retrievable."""
        info = VersionInfo(
            version="1.2.3",
            publish_time=datetime(2024, 3, 15, 12, 0, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
        )
        insert_version_timestamp(db_conn, info)
        result = get_version_timestamp(db_conn, "npm", "lodash", "1.2.3")
        assert result is not None
        assert result == datetime(2024, 3, 15, 12, 0, tzinfo=UTC)

    def test_get_timestamp_not_found(self, db_conn: sqlite3.Connection) -> None:
        """Querying a missing version returns None."""
        assert get_version_timestamp(db_conn, "npm", "missing", "0.0.1") is None

    def test_insert_or_replace_timestamp(self, db_conn: sqlite3.Connection) -> None:
        """Second insert for same key should update, not duplicate."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="foo",
        )
        insert_version_timestamp(db_conn, info)
        info2 = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 2, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="foo",
        )
        insert_version_timestamp(db_conn, info2)

        result = get_version_timestamp(db_conn, "npm", "foo", "1.0.0")
        assert result == datetime(2024, 2, 1, tzinfo=UTC)

        count = db_conn.execute("SELECT COUNT(*) FROM version_timestamps").fetchone()[0]
        assert count == 1

    # ------------------------------------------------------------------
    # _format_utc_z unit tests (§9.1)
    # ------------------------------------------------------------------

    def test_format_utc_z_aware_whole_seconds(self) -> None:
        """Aware UTC datetime with whole seconds formats without microseconds."""
        result = _format_utc_z(datetime(2024, 1, 1, tzinfo=UTC))
        assert result == "2024-01-01T00:00:00Z"

    def test_format_utc_z_with_microseconds(self) -> None:
        """Microsecond precision is preserved in the formatted string."""
        result = _format_utc_z(datetime(2024, 1, 1, 12, 30, 45, 123456, tzinfo=UTC))
        assert result == "2024-01-01T12:30:45.123456Z"

    def test_format_utc_z_trailing_zero_trimmed(self) -> None:
        """Trailing zeros in the microsecond field are trimmed."""
        result = _format_utc_z(datetime(2024, 1, 1, 12, 30, 45, 123000, tzinfo=UTC))
        assert result == "2024-01-01T12:30:45.123Z"

    def test_format_utc_z_naive_datetime(self) -> None:
        """Naive datetime is formatted as UTC with Z suffix."""
        result = _format_utc_z(datetime(2024, 1, 1))
        assert result == "2024-01-01T00:00:00Z"

    def test_format_utc_z_non_utc_timezone(self) -> None:
        """Non-UTC timezone is formatted as-is (caller expected to normalize)."""
        from datetime import timedelta, timezone

        dt = datetime(2024, 1, 1, tzinfo=timezone(timedelta(hours=5)))
        result = _format_utc_z(dt)
        # _format_utc_z does NOT convert timezone — caller normalizes first
        assert result == "2024-01-01T00:00:00Z"

    # ------------------------------------------------------------------
    # classify_precision unit tests (§9.2)
    # ------------------------------------------------------------------

    def test_classify_precision_microsecond(self) -> None:
        """Datetime with non-zero microseconds classifies as 'microsecond'."""
        result = classify_precision(datetime(2024, 1, 1, 12, 0, 0, 123456, tzinfo=UTC))
        assert result == "microsecond"

    def test_classify_precision_second(self) -> None:
        """Datetime with zero microseconds classifies as 'second'."""
        result = classify_precision(datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC))
        assert result == "second"


# ---------------------------------------------------------------------------
# Bypass tests
# ---------------------------------------------------------------------------


class TestBypass:
    """Tests for insert_bypass."""

    def test_insert_bypass(self, db_conn: sqlite3.Connection, sample_threat: ThreatRecord) -> None:
        """insert_bypass should store the entry and return it via query."""
        # Insert the referenced threat first to satisfy FK constraint
        insert_threat(db_conn, sample_threat)

        insert_bypass(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id="osv:GHSA-1234",
            reason="verified safe upstream",
        )
        rows = db_conn.execute(
            "SELECT ecosystem, package_name, version, threat_id, reason, checks_performed FROM bypasses"
        ).fetchall()
        assert len(rows) == 1
        assert tuple(rows[0]) == (
            "npm",
            "lodash",
            "4.17.21",
            "osv:GHSA-1234",
            "verified safe upstream",
            "bypassed",
        )

    def test_insert_bypass_with_expiry(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass with expires_at should persist the timestamp."""
        exp = datetime(2025, 1, 1, tzinfo=UTC)
        insert_bypass(
            db_conn,
            ecosystem="pypi",
            package="requests",
            version="2.31.0",
            threat_id=None,
            reason="temp exception",
            expires_at=exp,
        )
        row = db_conn.execute("SELECT expires_at, checks_performed FROM bypasses").fetchone()
        assert row[0] == exp.isoformat()
        assert row[1] == "bypassed"

    def test_insert_bypass_checks_performed(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass with checks_performed stores the custom value."""
        insert_bypass(
            db_conn,
            ecosystem="npm",
            package="express",
            version="4.18.0",
            threat_id=None,
            reason="test custom checks_performed",
            checks_performed="threat_only",
        )
        row = db_conn.execute("SELECT checks_performed FROM bypasses").fetchone()
        assert row is not None
        assert row[0] == "threat_only"

    def test_insert_bypass_default_checks_performed(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass without checks_performed defaults to 'bypassed'."""
        insert_bypass(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="test default",
        )
        row = db_conn.execute("SELECT checks_performed FROM bypasses").fetchone()
        assert row is not None
        assert row[0] == "bypassed"

    def test_insert_bypass_invalid_checks_performed(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass with invalid checks_performed raises ValueError."""
        with pytest.raises(ValueError, match="Invalid checks_performed"):
            insert_bypass(
                db_conn,
                ecosystem="npm",
                package="bad",
                version="1.0.0",
                threat_id=None,
                reason="invalid value",
                checks_performed="invalid_value",
            )

    def test_insert_bypass_with_user(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass with explicit user stores the user value."""
        insert_bypass(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="test explicit user",
            user="test-user",
        )
        rows = db_conn.execute("SELECT user FROM bypasses").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "test-user"

    def test_insert_bypass_default_user(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass without user defaults to getpass.getuser()."""
        insert_bypass(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="test default user",
        )
        rows = db_conn.execute("SELECT user FROM bypasses").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == getpass.getuser()

    def test_insert_bypass_user_fallback(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass falls back to 'unknown' when getpass.getuser() fails."""
        with mock.patch("pkg_defender.db.schema.getpass.getuser", side_effect=Exception("no user")):
            insert_bypass(
                db_conn,
                ecosystem="npm",
                package="lodash",
                version="4.17.21",
                threat_id=None,
                reason="test fallback",
            )
        rows = db_conn.execute("SELECT user FROM bypasses").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "unknown"

    def test_insert_bypass_rejects_invalid_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """insert_bypass with ecosystem not in VALID_ECOSYSTEMS returns None."""
        result = insert_bypass(
            db_conn,
            ecosystem="invalid_ecosystem",
            package="pkg",
            version="1.0.0",
            threat_id=None,
            reason="test invalid ecosystem",
        )
        assert result is None
        count = db_conn.execute("SELECT COUNT(*) FROM bypasses").fetchone()[0]
        assert count == 0


# ---------------------------------------------------------------------------
# Feed State tests
# ---------------------------------------------------------------------------


class TestFeedState:
    """Tests for update_feed_state and get_feed_state."""

    def test_insert_and_retrieve_feed_state(self, db_conn: sqlite3.Connection) -> None:
        """update_feed_state should persist and be retrievable."""
        update_feed_state(
            db_conn,
            feed_name="osv",
            cursor="abc123",
            status="syncing",
        )
        result = get_feed_state(db_conn, "osv")
        assert result is not None
        assert result["feed_name"] == "osv"
        assert result["cursor"] == "abc123"
        assert result["status"] == "syncing"
        assert result["last_sync"] is not None

    def test_get_feed_state_not_found(self, db_conn: sqlite3.Connection) -> None:
        """Querying a missing feed returns None."""
        assert get_feed_state(db_conn, "nonexistent") is None

    def test_update_feed_state_with_error(self, db_conn: sqlite3.Connection) -> None:
        """error_message should be stored when status is 'error'."""
        update_feed_state(
            db_conn,
            feed_name="ghsa",
            cursor=None,
            status="error",
            error_message="HTTP 503",
        )
        result = get_feed_state(db_conn, "ghsa")
        assert result is not None
        assert result["status"] == "error"
        assert result["error_message"] == "HTTP 503"

    def test_insert_or_replace_feed_state(self, db_conn: sqlite3.Connection) -> None:
        """Second update for same feed should replace, not duplicate."""
        update_feed_state(db_conn, "osv", "a", "idle")
        update_feed_state(db_conn, "osv", "b", "syncing")

        result = get_feed_state(db_conn, "osv")
        assert result is not None
        assert result["cursor"] == "b"
        assert result["status"] == "syncing"

        count = db_conn.execute("SELECT COUNT(*) FROM feed_state").fetchone()[0]
        assert count == 1


# ---------------------------------------------------------------------------
# Cross-source dedup tests (A2: UNIQUE(source_id) removed)
# ---------------------------------------------------------------------------


class TestCrossSourceDedup:
    """Tests that two threats with same source_id from different sources coexist.

    After removing UNIQUE(source_id), the composite primary key
    id = f\"{source}:{source_id}\" is the sole dedup mechanism.
    """

    def test_same_source_id_different_sources_both_stored(
        self,
        db_conn: sqlite3.Connection,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Same source_id from different sources should both be stored."""
        threat_osv = ThreatRecord(
            id="osv:GHSA-xxxx",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.85,
            source="osv",
            source_id="GHSA-xxxx",
            summary="OSV report",
            detail_url="https://osv.dev/GHSA-xxxx",
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, tzinfo=UTC),
            hit_count=1,
        )
        threat_ghsa = ThreatRecord(
            id="ghsa:GHSA-xxxx",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.20"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="ghsa",
            source_id="GHSA-xxxx",
            summary="GHSA report",
            detail_url="https://ghsa.com/GHSA-xxxx",
            first_seen=datetime(2024, 2, 1, tzinfo=UTC),
            last_seen=datetime(2024, 7, 1, tzinfo=UTC),
            hit_count=1,
        )

        insert_threat(db_conn, threat_osv)
        insert_threat(db_conn, threat_ghsa)

        # Both should be retrievable
        result_osv = get_threat(db_conn, "osv:GHSA-xxxx")
        assert result_osv is not None
        assert result_osv.source == "osv"
        assert result_osv.source_id == "GHSA-xxxx"

        result_ghsa = get_threat(db_conn, "ghsa:GHSA-xxxx")
        assert result_ghsa is not None
        assert result_ghsa.source == "ghsa"
        assert result_ghsa.source_id == "GHSA-xxxx"

        # Total count should be 2
        count = db_conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 2

        # No warning about source_id conflict should be logged
        assert "source_id" not in caplog.text

    def test_same_source_id_does_not_trigger_provenance_loss(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """source_id must not be cleared when another threat shares the same value."""
        t1 = ThreatRecord(
            id="osv:GHSA-yyyy",
            ecosystem="npm",
            package_name="react",
            affected_versions=["18.0.0"],
            affected_ranges=[],
            severity="MEDIUM",
            confidence=0.7,
            source="osv",
            source_id="GHSA-yyyy",
            summary="first source",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            hit_count=1,
        )
        t2 = ThreatRecord(
            id="ghsa:GHSA-yyyy",
            ecosystem="npm",
            package_name="react",
            affected_versions=["18.0.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="ghsa",
            source_id="GHSA-yyyy",
            summary="second source",
            detail_url=None,
            first_seen=datetime(2024, 2, 1, tzinfo=UTC),
            last_seen=datetime(2024, 2, 1, tzinfo=UTC),
            hit_count=1,
        )

        insert_threat(db_conn, t1)
        insert_threat(db_conn, t2)

        # Verify both source_ids are preserved
        r1 = get_threat(db_conn, "osv:GHSA-yyyy")
        assert r1 is not None and r1.source_id == "GHSA-yyyy", "First threat's source_id must not be cleared"

        r2 = get_threat(db_conn, "ghsa:GHSA-yyyy")
        assert r2 is not None and r2.source_id == "GHSA-yyyy", "Second threat's source_id must not be cleared"


class TestUpsertAfterUniqueRemoval:
    """Tests that the UPSERT still deduplicates on composite primary key."""

    def test_upsert_on_same_id_updates_fields(
        self,
        db_conn: sqlite3.Connection,
        sample_threat: ThreatRecord,
    ) -> None:
        """Inserting with same id should update fields via UPSERT."""
        insert_threat(db_conn, sample_threat)
        sample_threat.severity = "CRITICAL"
        sample_threat.confidence = 1.0
        insert_threat(db_conn, sample_threat)

        result = get_threat(db_conn, "osv:GHSA-1234")
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.confidence == 1.0

        count = db_conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 1

    def test_upsert_preserves_first_seen_on_reinsert(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """UPSERT should keep earliest first_seen (MIN aggregation)."""
        t1 = ThreatRecord(
            id="osv:GHSA-zzzz",
            ecosystem="npm",
            package_name="express",
            affected_versions=["4.18.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.8,
            source="osv",
            source_id="GHSA-zzzz",
            summary="express vuln",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, tzinfo=UTC),
            hit_count=1,
        )
        t2 = ThreatRecord(
            id="osv:GHSA-zzzz",
            ecosystem="npm",
            package_name="express",
            affected_versions=["4.18.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.8,
            source="osv",
            source_id="GHSA-zzzz",
            summary="express vuln",
            detail_url=None,
            first_seen=datetime(2023, 6, 1, tzinfo=UTC),  # Earlier
            last_seen=datetime(2024, 6, 1, tzinfo=UTC),
            hit_count=1,
        )

        insert_threat(db_conn, t1)
        insert_threat(db_conn, t2)

        result = get_threat(db_conn, "osv:GHSA-zzzz")
        assert result is not None
        assert result.first_seen == datetime(2023, 6, 1, tzinfo=UTC), "first_seen should be the earlier value"
        assert result.hit_count >= 1


# ---------------------------------------------------------------------------
# Legacy DB recreation tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


class TestMetadata:
    """Tests for get_metadata / set_metadata helpers."""

    def test_get_set_metadata(self, db_conn: sqlite3.Connection) -> None:
        """Verify get_metadata/set_metadata roundtrip."""
        # Key doesn't exist
        assert get_metadata(db_conn, "test:key") is None

        # Set and retrieve
        set_metadata(db_conn, "test:key", "test-value")
        assert get_metadata(db_conn, "test:key") == "test-value"

        # Overwrite
        set_metadata(db_conn, "test:key", "new-value")
        assert get_metadata(db_conn, "test:key") == "new-value"

    def test_set_metadata_no_commit(self, tmp_path: Path) -> None:
        """Verify set_metadata with commit=False doesn't persist until committed."""
        db_path = tmp_path / "no_commit.db"
        conn = init_db(db_path)

        set_metadata(conn, "test:key", "uncommitted", commit=False)
        assert get_metadata(conn, "test:key") == "uncommitted"

        # Rollback and verify it's gone
        conn.rollback()
        assert get_metadata(conn, "test:key") is None

        conn.close()

    def test_get_metadata_nonexistent_key(self, db_conn: sqlite3.Connection) -> None:
        """Verify get_metadata returns None for missing keys."""
        assert get_metadata(db_conn, "nonexistent") is None


# ---------------------------------------------------------------------------
# get_all_version_timestamps_for_package tests
# ---------------------------------------------------------------------------


class TestGetAllVersionTimestampsForPackage:
    """Tests for get_all_version_timestamps_for_package()."""

    def test_returns_multiple_versions_ordered_by_publish_time_desc(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should return all version timestamps for a package, DESC by publish_time."""
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0", publish_time=datetime(2024, 1, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="2.0.0", publish_time=datetime(2024, 6, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.5.0", publish_time=datetime(2024, 3, 15, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )

        result = get_all_version_timestamps_for_package(db_conn, "npm", "lodash")

        assert len(result) == 3
        assert result[0] == ("2.0.0", "2024-06-01T00:00:00Z")
        assert result[1] == ("1.5.0", "2024-03-15T00:00:00Z")
        assert result[2] == ("1.0.0", "2024-01-01T00:00:00Z")

    def test_returns_empty_list_when_no_data(self, db_conn: sqlite3.Connection) -> None:
        """Should return empty list when no version timestamps exist."""
        result = get_all_version_timestamps_for_package(db_conn, "npm", "nonexistent")
        assert result == []

    def test_only_returns_requested_ecosystem_and_package(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should not return versions for other packages or ecosystems."""
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0", publish_time=datetime(2024, 1, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="2.0.0", publish_time=datetime(2024, 6, 1, tzinfo=UTC), ecosystem="pypi", package_name="lodash"
            ),
        )
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.5.0", publish_time=datetime(2024, 3, 1, tzinfo=UTC), ecosystem="npm", package_name="express"
            ),
        )

        result = get_all_version_timestamps_for_package(db_conn, "npm", "lodash")

        assert len(result) == 1
        assert result[0][0] == "1.0.0"

    def test_returns_string_timestamp_not_datetime(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Each result tuple contains (version_string, timestamp_string), not datetime."""
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0", publish_time=datetime(2024, 1, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )

        result = get_all_version_timestamps_for_package(db_conn, "npm", "lodash")

        assert len(result) == 1
        version, pub_time = result[0]
        assert isinstance(version, str)
        assert isinstance(pub_time, str)
        assert version == "1.0.0"
        assert pub_time == "2024-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# get_version_timestamps_batch tests
# ---------------------------------------------------------------------------


class TestGetVersionTimestampsBatch:
    """Tests for get_version_timestamps_batch()."""

    def test_empty_input_returns_empty_dict(self, db_conn: sqlite3.Connection) -> None:
        """Empty package_versions list should return empty dict."""
        result = get_version_timestamps_batch(db_conn, "npm", [])
        assert result == {}

    def test_returns_matching_publish_times(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should return publish times for matching package versions only."""
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0", publish_time=datetime(2024, 1, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="2.0.0", publish_time=datetime(2024, 6, 1, tzinfo=UTC), ecosystem="npm", package_name="lodash"
            ),
        )

        result = get_version_timestamps_batch(
            db_conn, "npm", [("lodash", "1.0.0"), ("lodash", "2.0.0"), ("lodash", "3.0.0")]
        )

        assert len(result) == 2
        assert ("npm", "lodash", "1.0.0") in result
        assert ("npm", "lodash", "2.0.0") in result
        assert ("npm", "lodash", "3.0.0") not in result
        # Verify tuple values (datetime, source_label)
        val1 = result[("npm", "lodash", "1.0.0")]
        assert isinstance(val1, tuple)
        assert len(val1) == 2
        assert isinstance(val1[0], datetime)
        assert isinstance(val1[1], str)
        assert val1[0] == datetime(2024, 1, 1, tzinfo=UTC)
        assert val1[1] == ""  # source_label defaults to ""
        val2 = result[("npm", "lodash", "2.0.0")]
        assert isinstance(val2, tuple)
        assert val2[0] == datetime(2024, 6, 1, tzinfo=UTC)
        assert val2[1] == ""  # source_label defaults to ""

    def test_does_not_return_other_ecosystem_results(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should not return results from other ecosystems."""
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0", publish_time=datetime(2024, 1, 1, tzinfo=UTC), ecosystem="pypi", package_name="lodash"
            ),
        )

        result = get_version_timestamps_batch(db_conn, "npm", [("lodash", "1.0.0")])
        assert result == {}


# ---------------------------------------------------------------------------
# insert_version_timestamp edge cases
# ---------------------------------------------------------------------------


class TestInsertVersionTimestampEdgeCases:
    """Edge case tests for insert_version_timestamp() validation and date_source mapping."""

    def test_commit_false_requires_external_commit(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """With commit=False inside explicit BEGIN, rollback discards the insert."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
        )

        # Start explicit transaction, insert with commit=False, then rollback
        db_conn.execute("BEGIN IMMEDIATE")
        insert_version_timestamp(db_conn, info, commit=False)
        db_conn.rollback()

        # Verify insert was discarded
        row = db_conn.execute(
            "SELECT version FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is None

    def test_skips_when_publish_time_is_none(self, db_conn: sqlite3.Connection) -> None:
        """Should log a warning and return without inserting when publish_time is None."""
        info = VersionInfo(version="1.0.0", publish_time=None, ecosystem="npm", package_name="lodash")
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT version FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is None

    def test_skips_when_ecosystem_is_invalid(self, db_conn: sqlite3.Connection) -> None:
        """Should skip insert when ecosystem is not in VALID_ECOSYSTEMS."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="INVALID_ECOSYSTEM",
            package_name="lodash",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT version FROM version_timestamps WHERE package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is None

    def test_registry_date_source_maps_to_claimed(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='registry' should set trust_level='claimed'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="registry",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "claimed"

    def test_registry_api_date_source_maps_to_verified(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='registry_api' should set trust_level='verified' and store source_label.

        Regression test for Bug 3. Before fix, 'registry_api' was not in the
        verified sources tuple (schema.py:884), so it fell through to 'none'.
        This test FAILS before the fix and PASSES after.
        """
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="registry_api",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level, source_label FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "verified", f"Expected trust_level='verified', got '{row[0]}'"
        assert row[1] == "registry_api", f"Expected source_label='registry_api', got '{row[1]}'"

    def test_koji_date_source_maps_to_proxied(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='koji' should set trust_level='proxied'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="koji",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "proxied"

    def test_unknown_date_source_maps_to_unknown(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """An unrecognised date_source should set trust_level='unknown' and store source_label."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="some_unknown_source",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level, source_label FROM version_timestamps"
            " WHERE ecosystem = 'npm'"
            " AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"  # trust_level maps to "unknown"
        assert row[1] == "some_unknown_source"  # source_label preserves original

    def test_date_source_stored_as_source_label(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source is stored verbatim in source_label column."""
        from pkg_defender.db.schema import get_version_timestamps_batch

        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="github_tags",
        )
        insert_version_timestamp(db_conn, info)

        # Verify via batch lookup — source_label is what get_version_timestamps_batch returns
        result = get_version_timestamps_batch(db_conn, "npm", [("lodash", "1.0.0")])
        assert ("npm", "lodash", "1.0.0") in result
        dt, source = result[("npm", "lodash", "1.0.0")]
        assert source == "github_tags"

    # ------------------------------------------------------------------
    # SOURCE_TRUST_MAP coverage tests (§9.3)
    # ------------------------------------------------------------------

    def test_bodhi_date_source_maps_to_verified(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='bodhi' should set trust_level='verified'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="bodhi",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "verified"

    def test_repodata_date_source_maps_to_proxied(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='repodata' should set trust_level='proxied'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="repodata",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "proxied"

    def test_github_releases_date_source_maps_to_claimed(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='github_releases' should set trust_level='claimed'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="github_releases",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "claimed"

    def test_github_tags_date_source_maps_to_claimed(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='github_tags' should set trust_level='claimed'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="github_tags",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "claimed"

    def test_libraries_io_date_source_maps_to_claimed(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='libraries_io' should set trust_level='claimed'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="libraries_io",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "claimed"

    def test_user_manual_date_source_maps_to_claimed(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='unresolved' should set trust_level='unknown'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="unresolved",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"

    def test_cache_date_source_maps_to_unknown(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """date_source='cache' should set trust_level='unknown'."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="cache",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"

    def test_empty_date_source_maps_to_unknown(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Empty date_source should set trust_level='unknown' (not in SOURCE_TRUST_MAP)."""
        info = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            ecosystem="npm",
            package_name="lodash",
            date_source="",
        )
        insert_version_timestamp(db_conn, info)

        row = db_conn.execute(
            "SELECT trust_level FROM version_timestamps"
            " WHERE ecosystem = 'npm' AND package_name = 'lodash' AND version = '1.0.0'"
        ).fetchone()
        assert row is not None
        assert row[0] == "unknown"


class TestSourceLabelMigration:
    """Verify init_db() doesn't fabricate source_label values.

    After the backfill removal (Session 41), empty source_labels remain
    empty — init_db() does NOT mutate version_timestamps data.

    Coverage:
      - test_init_db_does_not_overwrite_valid_source_labels  Non-empty labels are preserved
      - test_init_db_leaves_empty_source_labels_untouched     Empty labels stay empty
    """

    def test_init_db_leaves_empty_source_labels_untouched(self, tmp_path: Path) -> None:
        """Empty source_labels remain empty after init_db().

        Regression test for the backfill removal (Session 41):
        init_db() no longer fabricates 'user_manual' for empty source_labels.
        Empty means 'unknown' — the honest answer.
        """
        import sqlite3

        from pkg_defender.db.schema import SCHEMA_SQL, init_db

        # Step 1: Create a DB with the schema
        db_path = tmp_path / "empty_label.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript(SCHEMA_SQL)

        # Insert a row with empty source_label (pre-Session-39 simulation)
        conn.execute(
            "INSERT INTO version_timestamps"
            " (ecosystem, package_name, version, publish_time, trust_level, source_label)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("pypi", "legacy-pkg", "1.0.0", "2024-06-01T00:00:00Z", "verified", ""),
        )
        conn.commit()

        # Sanity: row exists with empty source_label
        pre = conn.execute(
            "SELECT source_label FROM version_timestamps WHERE package_name='legacy-pkg'",
        ).fetchone()
        assert pre is not None
        assert pre[0] == "", "Pre-init row should have empty source_label"
        conn.close()

        # Step 2: Run init_db (which no longer backfills)
        conn = init_db(db_path)

        # Step 3: Verify empty source_label is UNCHANGED
        post = conn.execute(
            "SELECT source_label FROM version_timestamps WHERE package_name='legacy-pkg'",
        ).fetchone()
        assert post is not None
        assert post[0] == "", (
            f"Expected source_label='' (unchanged), got {post[0]!r}. init_db() must NOT backfill empty source_labels."
        )

        # Step 4: Idempotency check — second init_db run must also be a no-op
        conn.close()
        conn2 = init_db(db_path)
        post2 = conn2.execute(
            "SELECT source_label FROM version_timestamps WHERE package_name='legacy-pkg'",
        ).fetchone()
        assert post2 is not None
        assert post2[0] == "", "Second init_db run must also leave empty source_label unchanged"
        conn2.close()

    def test_init_db_does_not_overwrite_valid_source_labels(self, tmp_path: Path) -> None:
        """init_db() must not overwrite non-empty source_labels."""
        import sqlite3

        from pkg_defender.db.schema import SCHEMA_SQL, init_db

        db_path = tmp_path / "valid_label.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript(SCHEMA_SQL)

        # Insert a row with a meaningful source_label (e.g., from post-Session-39 cache)
        conn.execute(
            "INSERT INTO version_timestamps"
            " (ecosystem, package_name, version, publish_time, trust_level, source_label)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("pypi", "good-pkg", "2.0.0", "2026-01-15T12:00:00Z", "verified", "github_tags"),
        )
        conn.commit()
        conn.close()

        # Run init_db (backfill must NOT touch this row)
        conn = init_db(db_path)
        row = conn.execute(
            "SELECT source_label FROM version_timestamps WHERE package_name='good-pkg'",
        ).fetchone()
        assert row is not None
        assert row[0] == "github_tags", (
            f"Expected source_label='github_tags', got {row[0]!r}."
            " init_db() must not overwrite non-empty source_labels."
        )
        conn.close()


# ---------------------------------------------------------------------------
# Schema v1 → v2 migration tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# insert_audit_event validation rejection tests
# ---------------------------------------------------------------------------


class TestInsertAuditEventValidation:
    """Tests that insert_audit_event() rejects invalid parameters by returning 0.

    The happy path is tested through the dispatcher integration tests.
    These tests cover the 7 validation rejection branches.
    """

    def _valid_kwargs(self) -> dict[str, Any]:
        """Return minimal valid parameters for insert_audit_event."""
        return {
            "ecosystem": "npm",
            "package_name": "test-pkg",
            "version": "1.0.0",
            "action": "install",
            "risk_level": "critical",
            "source": "cli",
            "manager": "npm",
            "subcommand": "install",
            "verdict": "PASS",
            "exit_code": 0,
        }

    def _assert_rejects(self, db_conn: sqlite3.Connection, **override_kwargs: Any) -> None:
        """Assert that insert_audit_event returns 0 (rejected) with the given overrides."""
        kwargs = self._valid_kwargs()
        kwargs.update(override_kwargs)
        result = insert_audit_event(db_conn, **kwargs)
        assert result == 0, f"Expected return 0 (rejected), got {result}"

    def test_rejects_invalid_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """ecosystem not in VALID_ECOSYSTEMS returns 0."""
        self._assert_rejects(db_conn, ecosystem="invalid_ecosystem")

    def test_rejects_invalid_manager(self, db_conn: sqlite3.Connection) -> None:
        """manager not in VALID_MANAGERS returns 0."""
        self._assert_rejects(db_conn, manager="invalid_manager")

    def test_rejects_negative_exit_code(self, db_conn: sqlite3.Connection) -> None:
        """exit_code < 0 returns 0."""
        self._assert_rejects(db_conn, exit_code=-1)

    def test_rejects_exit_code_above_255(self, db_conn: sqlite3.Connection) -> None:
        """exit_code > 255 returns 0."""
        self._assert_rejects(db_conn, exit_code=256)

    def test_rejects_negative_threat_count_general(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """threat_count_general < 0 returns 0."""
        self._assert_rejects(db_conn, threat_count_general=-1)

    def test_rejects_negative_threat_count_versioned(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """threat_count_versioned < 0 returns 0."""
        self._assert_rejects(db_conn, threat_count_versioned=-1)

    def test_rejects_negative_runtime_ms(self, db_conn: sqlite3.Connection) -> None:
        """runtime_ms < 0 returns 0."""
        self._assert_rejects(db_conn, runtime_ms=-1)

    def test_rejects_invalid_coverage_tier(self, db_conn: sqlite3.Connection) -> None:
        """coverage_tier not in (full, partial, audit) returns 0."""
        self._assert_rejects(db_conn, coverage_tier="invalid_tier")


# ---------------------------------------------------------------------------
# get_audit_events tests
# ---------------------------------------------------------------------------


class TestGetAuditEvents:
    """Tests for get_audit_events()."""

    def test_returns_all_events_without_filters(self, db_conn: sqlite3.Connection) -> None:
        """Without filters, should return all events up to the default limit."""
        insert_audit_event(db_conn, "npm", "lodash", "1.0.0", "install", "critical", "cli", "npm", "install", "FAIL", 1)
        insert_audit_event(db_conn, "pypi", "requests", "2.0.0", "install", "watch", "cli", "pip", "install", "PASS", 0)

        result = get_audit_events(db_conn)

        assert len(result) == 2
        ecosystems = {r["ecosystem"] for r in result}
        assert ecosystems == {"npm", "pypi"}
        # Verify default values for new config-state columns
        assert result[0]["fail_on_threat_enabled"] is True
        assert result[0]["cooldown_enabled"] is True
        assert result[0]["coverage_tier"] == "full"

    def test_filters_by_ecosystem(self, db_conn: sqlite3.Connection) -> None:
        """Should filter by ecosystem."""
        insert_audit_event(db_conn, "npm", "lodash", "1.0.0", "install", "critical", "cli", "npm", "install", "FAIL", 1)
        insert_audit_event(db_conn, "pypi", "requests", "2.0.0", "install", "watch", "cli", "pip", "install", "PASS", 0)

        result = get_audit_events(db_conn, ecosystem="npm")

        assert len(result) == 1
        assert result[0]["ecosystem"] == "npm"

    def test_filters_by_package_name(self, db_conn: sqlite3.Connection) -> None:
        """Should filter by package_name."""
        insert_audit_event(db_conn, "npm", "lodash", "1.0.0", "install", "critical", "cli", "npm", "install", "FAIL", 1)
        insert_audit_event(db_conn, "npm", "express", "4.0.0", "install", "watch", "cli", "npm", "install", "PASS", 0)

        result = get_audit_events(db_conn, package_name="lodash")

        assert len(result) == 1
        assert result[0]["package_name"] == "lodash"

    def test_filters_by_verdict(self, db_conn: sqlite3.Connection) -> None:
        """Should filter by verdict."""
        insert_audit_event(db_conn, "npm", "lodash", "1.0.0", "install", "critical", "cli", "npm", "install", "FAIL", 1)
        insert_audit_event(db_conn, "npm", "express", "4.0.0", "install", "watch", "cli", "npm", "install", "PASS", 0)

        result = get_audit_events(db_conn, verdict="FAIL")

        assert len(result) == 1
        assert result[0]["verdict"] == "FAIL"

    def test_filters_by_source(self, db_conn: sqlite3.Connection) -> None:
        """Should filter by source."""
        insert_audit_event(db_conn, "npm", "lodash", "1.0.0", "install", "critical", "cli", "npm", "install", "FAIL", 1)
        insert_audit_event(
            db_conn, "npm", "express", "4.0.0", "install", "watch", "shell_hook", "npm", "install", "PASS", 0
        )

        result = get_audit_events(db_conn, source="shell_hook")

        assert len(result) == 1
        assert result[0]["source"] == "shell_hook"

    def test_returns_empty_list_when_no_matches(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should return empty list when no events match the filters."""
        result = get_audit_events(db_conn, ecosystem="nonexistent")
        assert result == []

    def test_returns_recent_events_with_default_limit(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Should default to returning 100 events (or fewer if less exist)."""
        for _ in range(5):
            insert_audit_event(
                db_conn,
                "npm",
                "pkg",
                "1.0.0",
                "install",
                "critical",
                "cli",
                "npm",
                "install",
                "PASS",
                0,
            )

        result = get_audit_events(db_conn, limit=3)

        assert len(result) == 3

    def test_filters_by_since(self, db_conn: sqlite3.Connection) -> None:
        """Events after 'since' should be included."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        since = datetime(2000, 1, 1, tzinfo=UTC)
        result = get_audit_events(db_conn, since=since)

        assert len(result) == 1

    def test_filters_by_until(self, db_conn: sqlite3.Connection) -> None:
        """Events before 'until' should be included."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        until = datetime(2099, 1, 1, tzinfo=UTC)
        result = get_audit_events(db_conn, until=until)

        assert len(result) == 1

    def test_filters_since_excludes_old_events(self, db_conn: sqlite3.Connection) -> None:
        """Events before 'since' should be excluded."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        since = datetime(2099, 1, 1, tzinfo=UTC)
        result = get_audit_events(db_conn, since=since)

        assert result == []

    def test_filters_until_excludes_new_events(self, db_conn: sqlite3.Connection) -> None:
        """Events after 'until' should be excluded."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        until = datetime(2000, 1, 1, tzinfo=UTC)
        result = get_audit_events(db_conn, until=until)

        assert result == []


# ---------------------------------------------------------------------------
# get_audit_event_stats tests
# ---------------------------------------------------------------------------


class TestGetAuditEventStats:
    """Tests for get_audit_event_stats()."""

    def test_no_events_returns_zero_counts(self, db_conn: sqlite3.Connection) -> None:
        """With no events, all counts should be zero and breakdowns empty."""
        stats = get_audit_event_stats(db_conn)

        assert stats["total"] == 0
        assert stats["by_verdict"] == {}
        assert stats["by_ecosystem"] == {}
        assert stats["by_source"] == {}

    def test_aggregates_all_events_without_filter(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Without filters, should return aggregated stats for all events."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )
        insert_audit_event(
            db_conn,
            "pypi",
            "requests",
            "2.0.0",
            "install",
            "watch",
            "shell_hook",
            "pip",
            "install",
            "PASS",
            0,
        )

        stats = get_audit_event_stats(db_conn)

        assert stats["total"] == 2
        assert stats["by_verdict"] == {"FAIL": 1, "PASS": 1}
        assert stats["by_ecosystem"] == {"npm": 1, "pypi": 1}
        assert stats["by_source"] == {"cli": 1, "shell_hook": 1}

    def test_since_filter_includes_recent_events(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Events after 'since' should be counted."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        # Use a datetime in the past — today's events are definitely after year 2000
        since = datetime(2000, 1, 1, tzinfo=UTC)
        stats = get_audit_event_stats(db_conn, since=since)

        assert stats["total"] == 1

    def test_since_filter_excludes_old_events(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Events before 'since' should be excluded (none exist in 2099 scenario)."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        # Use a far-future datetime — today's events are before 2099
        since = datetime(2099, 1, 1, tzinfo=UTC)
        stats = get_audit_event_stats(db_conn, since=since)

        assert stats["total"] == 0

    def test_until_filter_includes_historical_events(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Events before 'until' should be counted."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        # Use a far-future datetime — today's events are before 2099
        until = datetime(2099, 1, 1, tzinfo=UTC)
        stats = get_audit_event_stats(db_conn, until=until)

        assert stats["total"] == 1

    def test_until_filter_excludes_recent_events(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Events after 'until' should be excluded."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        # Use a past datetime — today's events are after 2000
        until = datetime(2000, 1, 1, tzinfo=UTC)
        stats = get_audit_event_stats(db_conn, until=until)

        assert stats["total"] == 0

    def test_since_and_until_together(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Both since and until should apply together."""
        insert_audit_event(
            db_conn,
            "npm",
            "lodash",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )

        since = datetime(2000, 1, 1, tzinfo=UTC)
        until = datetime(2099, 1, 1, tzinfo=UTC)
        stats = get_audit_event_stats(db_conn, since=since, until=until)

        assert stats["total"] == 1

    def test_aggregates_multiple_verdicts(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Multiple events with same verdict should be counted together."""
        insert_audit_event(
            db_conn,
            "npm",
            "a",
            "1.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )
        insert_audit_event(
            db_conn,
            "npm",
            "b",
            "2.0.0",
            "install",
            "critical",
            "cli",
            "npm",
            "install",
            "FAIL",
            1,
        )
        insert_audit_event(
            db_conn,
            "npm",
            "c",
            "3.0.0",
            "install",
            "watch",
            "cli",
            "npm",
            "install",
            "PASS",
            0,
        )

        stats = get_audit_event_stats(db_conn)

        assert stats["total"] == 3
        assert stats["by_verdict"] == {"FAIL": 2, "PASS": 1}


# ---------------------------------------------------------------------------
# update_feed_state edge cases
# ---------------------------------------------------------------------------


class TestUpdateFeedStateEdgeCases:
    """Edge case tests for update_feed_state()."""

    def test_update_last_sync_false_preserves_existing_last_sync(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """With update_last_sync=False, the existing last_sync should be preserved."""
        update_feed_state(db_conn, feed_name="osv", cursor="abc", status="syncing", update_last_sync=True)

        # Capture the last_sync value
        first_state = get_feed_state(db_conn, "osv")
        assert first_state is not None
        original_last_sync = first_state["last_sync"]

        # Update without updating last_sync
        update_feed_state(db_conn, feed_name="osv", cursor="def", status="idle", update_last_sync=False)

        second_state = get_feed_state(db_conn, "osv")
        assert second_state is not None
        assert second_state["last_sync"] == original_last_sync
        assert second_state["cursor"] == "def"
        assert second_state["status"] == "idle"


# ---------------------------------------------------------------------------
# insert_feed_stats / get_feed_stats_history tests
# ---------------------------------------------------------------------------


class TestFeedStats:
    """Tests for insert_feed_stats() and get_feed_stats_history()."""

    def test_insert_and_retrieve_feed_stats(self, db_conn: sqlite3.Connection) -> None:
        """insert_feed_stats should persist and get_feed_stats_history should retrieve."""
        insert_feed_stats(db_conn, feed_name="osv", record_count=150, avg_confidence=0.75)

        history = get_feed_stats_history(db_conn, feed_name="osv", days=30)

        assert len(history) >= 1
        entry = history[0]
        assert entry["feed_name"] == "osv"
        assert entry["record_count"] == 150
        assert entry["avg_confidence"] == 0.75
        assert entry["synced_at"] is not None
        assert entry["skipped_count"] == 0

    def test_get_history_no_data(self, db_conn: sqlite3.Connection) -> None:
        """get_feed_stats_history should return empty list for feed with no stats."""
        history = get_feed_stats_history(db_conn, feed_name="nonexistent", days=7)
        assert history == []

    def test_insert_feed_stats_with_none_confidence(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """insert_feed_stats with avg_confidence=None should be stored as NULL."""
        insert_feed_stats(db_conn, feed_name="osv", record_count=0, avg_confidence=None, skipped_count=0)

        row = db_conn.execute(
            "SELECT record_count, avg_confidence FROM feed_stats WHERE feed_name = ?",
            ("osv",),
        ).fetchone()
        assert row is not None
        assert row[0] == 0
        assert row[1] is None

    def test_feed_stats_prunes_old_entries(self, db_conn: sqlite3.Connection) -> None:
        """Only the 30 most recent feed_stats entries per feed are retained.

        Root cause: schema.py:1495-1507 (DELETE after INSERT in
        ``insert_feed_stats``). Before the fix, feed_stats accumulated
        indefinitely.
        This test FAILS before the fix (36 rows survive) and
        PASSES after (30 rows remain).

        Scenario: 35 existing rows for one feed + 1 new insert = 36 total.
        Expected: After ``insert_feed_stats()``, only 30 rows remain
        (the oldest 6 are pruned, keeping the 30 most recent).
        Previously: All 36 rows persisted.
        """
        for i in range(35):
            db_conn.execute(
                """INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence, skipped_count)
                   VALUES (?, datetime('now', ?), ?, ?, 0)""",
                ("prune-feed", f"-{35 - i} minutes", 100, 0.5),
            )
        db_conn.commit()

        # This call triggers the prune (INSERT + DELETE)
        insert_feed_stats(db_conn, "prune-feed", 200, 0.75, 0)

        count = db_conn.execute("SELECT COUNT(*) FROM feed_stats WHERE feed_name = ?", ("prune-feed",)).fetchone()[0]
        assert count == 30, f"Expected 30 feed_stats rows after prune, got {count}"

    def test_feed_stats_under_limit_not_pruned(self, db_conn: sqlite3.Connection) -> None:
        """Feeds with ≤30 stats entries are not pruned."""
        for i in range(15):
            db_conn.execute(
                """INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence, skipped_count)
                   VALUES (?, datetime('now', ?), ?, ?, 0)""",
                ("keep-feed", f"-{15 - i} minutes", 100, 0.5),
            )
        db_conn.commit()

        insert_feed_stats(db_conn, "keep-feed", 200, 0.75, 0)

        count = db_conn.execute("SELECT COUNT(*) FROM feed_stats WHERE feed_name = ?", ("keep-feed",)).fetchone()[0]
        assert count == 16, f"Expected 16 feed_stats rows (under limit), got {count}"

    def test_insert_feed_stats_with_skipped_count(self, db_conn: sqlite3.Connection) -> None:
        """Non-zero skipped_count should be stored and retrievable."""
        insert_feed_stats(db_conn, feed_name="skip-feed", record_count=10, avg_confidence=0.8, skipped_count=3)

        history = get_feed_stats_history(db_conn, feed_name="skip-feed", days=30)

        assert len(history) >= 1
        entry = history[0]
        assert entry["record_count"] == 10
        assert entry["avg_confidence"] == 0.8
        assert entry["skipped_count"] == 3

    def test_feed_stats_skipped_count_defaults_to_zero(self, db_conn: sqlite3.Connection) -> None:
        """Direct SQL INSERT without skipped_count should read back as 0."""
        db_conn.execute(
            """INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence)
               VALUES (?, datetime('now'), ?, ?)""",
            ("default-feed", 50, 0.9),
        )
        row = db_conn.execute(
            "SELECT skipped_count FROM feed_stats WHERE feed_name = ?",
            ("default-feed",),
        ).fetchone()
        assert row is not None
        assert row[0] == 0
