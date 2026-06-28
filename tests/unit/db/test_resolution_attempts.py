"""Tests for the resolution_attempts table and CRUD operations."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkg_defender.db.schema import (
    VALID_RESOLUTION_STATUSES,
    ResolutionAttemptRow,
    cleanup_expired_resolution_attempts,
    get_resolution_attempt,
    get_resolution_attempts_batch,
    init_db,
    insert_resolution_attempt,
)

# ---------------------------------------------------------------------------
# Schema creation tests
# ---------------------------------------------------------------------------


class TestResolutionAttemptsSchema:
    """Tests that the resolution_attempts table is created correctly."""

    def test_init_db_creates_resolution_attempts_table(
        self,
        tmp_path: Path,
    ) -> None:
        """init_db() should create the resolution_attempts table."""
        db_path = tmp_path / "schema_test.db"
        conn = init_db(db_path)

        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()

        assert "resolution_attempts" in tables

    def test_schema_migration_existing_db(
        self,
        tmp_path: Path,
    ) -> None:
        """CREATE TABLE IF NOT EXISTS on an existing DB creates table without error."""
        db_path = tmp_path / "existing.db"

        # First init — creates all tables
        conn1 = init_db(db_path)
        conn1.close()

        # Second init — must not raise
        conn2 = init_db(db_path)
        tables = {row[0] for row in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn2.close()

        assert "resolution_attempts" in tables

    def test_check_constraint_rejects_invalid_status(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """INSERT with invalid resolution_status must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO resolution_attempts
                    (ecosystem, package_name, version, resolution_status)
                VALUES ('npm', 'test-pkg', '1.0.0', 'invalid_status')
                """
            )

    def test_check_constraint_rejects_invalid_ecosystem(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """INSERT with invalid ecosystem must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO resolution_attempts
                    (ecosystem, package_name, version, resolution_status)
                VALUES ('invalid_ecosystem', 'test-pkg', '1.0.0', 'resolved')
                """
            )

    def test_publish_time_null_accepted(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """NULL publish_time must be accepted (failure case)."""
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status)
            VALUES ('npm', 'test-pkg', '1.0.0', 'all_sources_failed')
            """
        )
        row = db_conn.execute("SELECT publish_time FROM resolution_attempts WHERE package_name = 'test-pkg'").fetchone()
        assert row is not None
        assert row[0] is None

    def test_publish_time_valid_glob_accepted(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Valid ISO 8601 publish_time must be accepted."""
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, publish_time, resolution_status)
            VALUES ('npm', 'test-pkg', '1.0.0',
                    '2024-06-01T12:00:00Z', 'resolved')
            """
        )
        row = db_conn.execute("SELECT publish_time FROM resolution_attempts WHERE package_name = 'test-pkg'").fetchone()
        assert row is not None
        assert row[0] == "2024-06-01T12:00:00Z"

    def test_publish_time_invalid_glob_rejected(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Invalid publish_time format must raise IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                """
                INSERT INTO resolution_attempts
                    (ecosystem, package_name, version, publish_time, resolution_status)
                VALUES ('npm', 'test-pkg', '1.0.0',
                        'not-a-date', 'resolved')
                """
            )

    def test_attempted_at_defaults_to_now(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """attempted_at should default to current UTC time."""
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status)
            VALUES ('npm', 'test-pkg', '1.0.0', 'all_sources_failed')
            """
        )
        row = db_conn.execute("SELECT attempted_at FROM resolution_attempts WHERE package_name = 'test-pkg'").fetchone()
        assert row is not None
        assert row[0] is not None
        # Verify it's a valid ISO timestamp parseable by fromisoformat
        dt = datetime.fromisoformat(row[0])
        assert dt.year == datetime.now(UTC).year

    def test_source_label_defaults_to_empty(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """source_label should default to empty string."""
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status)
            VALUES ('npm', 'test-pkg', '1.0.0', 'all_sources_failed')
            """
        )
        row = db_conn.execute("SELECT source_label FROM resolution_attempts WHERE package_name = 'test-pkg'").fetchone()
        assert row is not None
        assert row[0] == ""


# ---------------------------------------------------------------------------
# insert_resolution_attempt tests
# ---------------------------------------------------------------------------


class TestInsertResolutionAttempt:
    """Tests for insert_resolution_attempt()."""

    def test_insert_resolved_record(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Insert a resolved record and verify round-trip."""
        now = datetime(2024, 6, 15, 12, 0, tzinfo=UTC)
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="lodash",
            version="4.17.21",
            publish_time=now,
            resolution_status="resolved",
            source_label="github_tags",
        )

        result = get_resolution_attempt(db_conn, "npm", "lodash", "4.17.21")
        assert result is not None
        assert result.ecosystem == "npm"
        assert result.package_name == "lodash"
        assert result.version == "4.17.21"
        assert result.publish_time is not None
        assert result.resolution_status == "resolved"
        assert result.source_label == "github_tags"
        assert result.last_error is None
        assert result.retry_after is None

    def test_insert_failure_record(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Insert a failure record with NULL publish_time."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="pypi",
            package_name="requests",
            version="2.31.0",
            publish_time=None,
            resolution_status="rate_limited",
            source_label="rate_limited",
            last_error="API rate limit exceeded",
        )

        result = get_resolution_attempt(db_conn, "pypi", "requests", "2.31.0")
        assert result is not None
        assert result.publish_time is None
        assert result.resolution_status == "rate_limited"
        assert result.source_label == "rate_limited"
        assert result.last_error == "API rate limit exceeded"

    def test_upsert_overwrites_existing(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """ON CONFLICT DO UPDATE overwrites existing record."""
        # First insert — failure
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="express",
            version="4.18.0",
            publish_time=None,
            resolution_status="timeout",
            source_label="timeout",
            last_error="Request timed out",
        )

        # Second insert — success (retry succeeded)
        now = datetime(2024, 7, 1, tzinfo=UTC)
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="express",
            version="4.18.0",
            publish_time=now,
            resolution_status="resolved",
            source_label="github_releases",
        )

        result = get_resolution_attempt(db_conn, "npm", "express", "4.18.0")
        assert result is not None
        assert result.resolution_status == "resolved"
        assert result.publish_time is not None
        assert result.source_label == "github_releases"

        # Must be exactly 1 row (upsert, not duplicate)
        count = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts").fetchone()[0]
        assert count == 1

    def test_skips_invalid_ecosystem(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Invalid ecosystem is rejected at application level."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="invalid_ecosystem",
            package_name="pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
        )

        row = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts").fetchone()[0]
        assert row == 0

    def test_skips_invalid_resolution_status(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Invalid resolution_status is rejected at application level."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="invalid_status",
        )

        row = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts").fetchone()[0]
        assert row == 0

    def test_commit_false_requires_external_commit(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """With commit=False inside explicit BEGIN, rollback discards write."""
        db_conn.execute("BEGIN IMMEDIATE")
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="rollback-test",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
            commit=False,
        )
        db_conn.rollback()

        row = db_conn.execute(
            "SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'rollback-test'"
        ).fetchone()[0]
        assert row == 0

    def test_retry_after_datetime_formatted(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """retry_after datetime is stored as ISO 8601 with Z suffix."""
        retry_dt = datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC)
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="ttl-test",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
            retry_after=retry_dt,
        )

        result = get_resolution_attempt(db_conn, "npm", "ttl-test", "1.0.0")
        assert result is not None
        assert result.retry_after is not None
        assert result.retry_after == retry_dt


# ---------------------------------------------------------------------------
# get_resolution_attempt tests
# ---------------------------------------------------------------------------


class TestGetResolutionAttempt:
    """Tests for get_resolution_attempt()."""

    def test_returns_none_for_unknown_package(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Querying a missing package returns None."""
        result = get_resolution_attempt(db_conn, "npm", "nonexistent", "0.0.1")
        assert result is None

    def test_returns_correct_row(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns the exact row matching the composite PK."""
        now = datetime(2024, 6, 1, tzinfo=UTC)
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="lodash",
            version="4.17.21",
            publish_time=now,
            resolution_status="resolved",
            source_label="github_tags",
        )
        insert_resolution_attempt(
            db_conn,
            ecosystem="pypi",
            package_name="requests",
            version="2.31.0",
            publish_time=None,
            resolution_status="timeout",
            source_label="timeout",
            last_error="timed out",
        )

        result = get_resolution_attempt(db_conn, "pypi", "requests", "2.31.0")
        assert result is not None
        assert result.ecosystem == "pypi"
        assert result.package_name == "requests"
        assert result.version == "2.31.0"
        assert result.resolution_status == "timeout"

    def test_does_not_cross_ecosystem(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Same package name in different ecosystem returns None."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="lodash",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
        )

        result = get_resolution_attempt(db_conn, "pypi", "lodash", "1.0.0")
        assert result is None


# ---------------------------------------------------------------------------
# get_resolution_attempts_batch tests
# ---------------------------------------------------------------------------


class TestGetResolutionAttemptsBatch:
    """Tests for get_resolution_attempts_batch()."""

    def test_empty_input_returns_empty_dict(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Empty package_versions list returns empty dict."""
        result = get_resolution_attempts_batch(db_conn, "npm", [])
        assert result == {}

    def test_returns_matching_rows(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns resolution attempts for matching packages."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="lodash",
            version="1.0.0",
            publish_time=None,
            resolution_status="timeout",
            source_label="timeout",
        )
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="express",
            version="4.18.0",
            publish_time=datetime(2024, 6, 1, tzinfo=UTC),
            resolution_status="resolved",
            source_label="github_releases",
        )

        result = get_resolution_attempts_batch(
            db_conn,
            "npm",
            [("lodash", "1.0.0"), ("express", "4.18.0"), ("missing", "0.0.1")],
        )

        assert len(result) == 2
        assert ("npm", "lodash", "1.0.0") in result
        assert ("npm", "express", "4.18.0") in result
        assert ("npm", "missing", "0.0.1") not in result

        lodash_result = result[("npm", "lodash", "1.0.0")]
        assert isinstance(lodash_result, ResolutionAttemptRow)
        assert lodash_result.resolution_status == "timeout"
        assert lodash_result.publish_time is None

        express_result = result[("npm", "express", "4.18.0")]
        assert express_result.resolution_status == "resolved"
        assert express_result.publish_time is not None

    def test_does_not_return_other_ecosystem(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Does not return results from other ecosystems."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="pypi",
            package_name="lodash",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
        )

        result = get_resolution_attempts_batch(db_conn, "npm", [("lodash", "1.0.0")])
        assert result == {}

    def test_matches_get_version_timestamps_batch_pattern(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Same input pattern as get_version_timestamps_batch produces results."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="lodash",
            version="4.17.21",
            publish_time=datetime(2024, 1, 1, tzinfo=UTC),
            resolution_status="resolved",
            source_label="github_tags",
        )

        result = get_resolution_attempts_batch(db_conn, "npm", [("lodash", "4.17.21")])

        assert len(result) == 1
        key = ("npm", "lodash", "4.17.21")
        assert key in result
        assert result[key].resolution_status == "resolved"


# ---------------------------------------------------------------------------
# cleanup_expired_resolution_attempts tests
# ---------------------------------------------------------------------------


class TestCleanupExpiredResolutionAttempts:
    """Tests for cleanup_expired_resolution_attempts()."""

    def test_removes_expired_retry_after_rows(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Rows with retry_after in the past are deleted."""
        # Insert a row with retry_after in the past
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status,
                 retry_after)
            VALUES ('npm', 'old-pkg', '1.0.0', 'all_sources_failed',
                    '2020-01-01T00:00:00Z')
            """
        )
        # Insert a row with retry_after in the future
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status,
                 retry_after)
            VALUES ('npm', 'future-pkg', '2.0.0', 'all_sources_failed',
                    '2099-12-31T23:59:59Z')
            """
        )
        # Insert a resolved row with retry_after in the past (should NOT be deleted)
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status,
                 retry_after)
            VALUES ('npm', 'resolved-pkg', '3.0.0', 'resolved',
                    '2020-01-01T00:00:00Z')
            """
        )
        db_conn.commit()

        deleted = cleanup_expired_resolution_attempts(db_conn)

        assert deleted == 1  # Only old-pkg deleted

        # Verify old-pkg is gone
        row = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'old-pkg'").fetchone()[0]
        assert row == 0

        # Verify future-pkg still exists
        row = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'future-pkg'").fetchone()[
            0
        ]
        assert row == 1

        # Verify resolved-pkg still exists (resolved status is never cleaned)
        row = db_conn.execute(
            "SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'resolved-pkg'"
        ).fetchone()[0]
        assert row == 1

    def test_null_retry_after_not_deleted(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Rows with NULL retry_after are never deleted."""
        db_conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status,
                 retry_after)
            VALUES ('npm', 'null-retry', '1.0.0', 'all_sources_failed',
                    NULL)
            """
        )
        db_conn.commit()

        deleted = cleanup_expired_resolution_attempts(db_conn)

        assert deleted == 0
        row = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'null-retry'").fetchone()[
            0
        ]
        assert row == 1

    def test_returns_zero_when_no_expired_rows(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns 0 when no rows need cleanup."""
        deleted = cleanup_expired_resolution_attempts(db_conn)
        assert deleted == 0

    def test_commit_false_does_not_persist(
        self,
        tmp_path: Path,
    ) -> None:
        """With commit=False, deletion is not persisted."""
        db_path = tmp_path / "cleanup_test.db"
        conn = init_db(db_path)

        # Insert an expired row
        conn.execute(
            """
            INSERT INTO resolution_attempts
                (ecosystem, package_name, version, resolution_status,
                 retry_after)
            VALUES ('npm', 'cleanup-test', '1.0.0', 'all_sources_failed',
                    '2020-01-01T00:00:00Z')
            """
        )
        conn.commit()

        # Cleanup without commit
        deleted = cleanup_expired_resolution_attempts(conn, commit=False)
        assert deleted == 1

        # Rollback — row should still exist
        conn.rollback()
        row = conn.execute("SELECT COUNT(*) FROM resolution_attempts WHERE package_name = 'cleanup-test'").fetchone()[0]
        assert row == 1

        conn.close()


# ---------------------------------------------------------------------------
# ResolutionAttemptRow dataclass tests
# ---------------------------------------------------------------------------


class TestResolutionAttemptRowDataclass:
    """Tests for the ResolutionAttemptRow dataclass."""

    def test_dataclass_fields(self) -> None:
        """ResolutionAttemptRow has all expected fields."""
        now = datetime(2024, 6, 1, tzinfo=UTC)
        row = ResolutionAttemptRow(
            ecosystem="npm",
            package_name="test",
            version="1.0.0",
            publish_time=now,
            resolution_status="resolved",
            source_label="github_tags",
            last_error=None,
            attempted_at=now,
            retry_after=None,
        )
        assert row.ecosystem == "npm"
        assert row.package_name == "test"
        assert row.version == "1.0.0"
        assert row.publish_time == now
        assert row.resolution_status == "resolved"
        assert row.source_label == "github_tags"
        assert row.last_error is None
        assert row.attempted_at == now
        assert row.retry_after is None

    def test_dataclass_nullable_fields(self) -> None:
        """publish_time, last_error, and retry_after can be None."""
        now = datetime(2024, 6, 1, tzinfo=UTC)
        row = ResolutionAttemptRow(
            ecosystem="npm",
            package_name="test",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
            source_label="",
            last_error="some error",
            attempted_at=now,
            retry_after=None,
        )
        assert row.publish_time is None
        assert row.last_error == "some error"
        assert row.retry_after is None


# ---------------------------------------------------------------------------
# VALID_RESOLUTION_STATUSES tests
# ---------------------------------------------------------------------------


class TestValidResolutionStatuses:
    """Tests for the VALID_RESOLUTION_STATUSES constant."""

    def test_contains_all_expected_statuses(self) -> None:
        """VALID_RESOLUTION_STATUSES contains exactly the 9 expected values."""
        expected = {
            "resolved",
            "all_sources_failed",
            "no_github_url",
            "rate_limited",
            "timeout",
            "network_error",
            "not_found",
            "server_error",
            "unknown_error",
        }
        assert set(VALID_RESOLUTION_STATUSES) == expected

    def test_tuple_is_immutable(self) -> None:
        """VALID_RESOLUTION_STATUSES is a tuple (immutable)."""
        assert isinstance(VALID_RESOLUTION_STATUSES, tuple)

    def test_count_is_nine(self) -> None:
        """There are exactly 9 valid resolution statuses."""
        assert len(VALID_RESOLUTION_STATUSES) == 9


# ---------------------------------------------------------------------------
# Round-trip integration tests
# ---------------------------------------------------------------------------


class TestResolutionAttemptsRoundTrip:
    """Integration-style tests verifying full insert→query round-trips."""

    def test_all_statuses_round_trip(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Every VALID_RESOLUTION_STATUS can be inserted and retrieved."""
        for i, status in enumerate(VALID_RESOLUTION_STATUSES):
            insert_resolution_attempt(
                db_conn,
                ecosystem="npm",
                package_name=f"pkg-{status}",
                version=f"{i}.0.0",
                publish_time=None if status != "resolved" else datetime(2024, 1, 1, tzinfo=UTC),
                resolution_status=status,
                source_label=status,
            )

        for i, status in enumerate(VALID_RESOLUTION_STATUSES):
            result = get_resolution_attempt(db_conn, "npm", f"pkg-{status}", f"{i}.0.0")
            assert result is not None, f"Missing record for status '{status}'"
            assert result.resolution_status == status

        # All 9 rows exist
        count = db_conn.execute("SELECT COUNT(*) FROM resolution_attempts").fetchone()[0]
        assert count == 9

    def test_batch_matches_individual_lookups(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """get_resolution_attempts_batch returns same data as individual lookups."""
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="alpha",
            version="1.0.0",
            publish_time=None,
            resolution_status="timeout",
            source_label="timeout",
            last_error="timed out",
        )
        insert_resolution_attempt(
            db_conn,
            ecosystem="npm",
            package_name="beta",
            version="2.0.0",
            publish_time=datetime(2024, 6, 1, tzinfo=UTC),
            resolution_status="resolved",
            source_label="github_tags",
        )

        batch = get_resolution_attempts_batch(db_conn, "npm", [("alpha", "1.0.0"), ("beta", "2.0.0")])

        for key, batch_row in batch.items():
            individual = get_resolution_attempt(db_conn, key[0], key[1], key[2])
            assert individual is not None
            assert batch_row.ecosystem == individual.ecosystem
            assert batch_row.package_name == individual.package_name
            assert batch_row.version == individual.version
            assert batch_row.resolution_status == individual.resolution_status
            assert batch_row.publish_time == individual.publish_time
