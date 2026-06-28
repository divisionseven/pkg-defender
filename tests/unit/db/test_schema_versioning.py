"""Tests for schema versioning and migration framework."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkg_defender.db.schema import (
    CURRENT_SCHEMA_VERSION,
    get_schema_version,
    init_db,
    migrate_db,
    set_schema_version,
)


class TestGetSetSchemaVersion:
    """Tests for get_schema_version and set_schema_version."""

    def test_get_version_returns_zero_for_empty_table(self, tmp_path: Path) -> None:
        """A database with no schema_version rows returns 0."""
        from pkg_defender.db.schema import get_connection

        db_path = tmp_path / "nover.db"
        conn = get_connection(db_path)
        conn.executescript("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        version = get_schema_version(conn)
        conn.close()
        assert version == 0

    def test_get_version_returns_zero_for_no_table(self, tmp_path: Path) -> None:
        """A database without schema_version table returns 0."""
        from pkg_defender.db.schema import get_connection

        db_path = tmp_path / "notable.db"
        conn = get_connection(db_path)
        # No table created — get_schema_version should handle gracefully
        version = get_schema_version(conn)
        conn.close()
        assert version == 0

    def test_set_and_get_version(self, tmp_path: Path) -> None:
        """set_schema_version should persist the version for later retrieval."""
        from pkg_defender.db.schema import get_connection

        db_path = tmp_path / "versioned.db"
        conn = get_connection(db_path)
        conn.executescript("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        set_schema_version(conn, 42)
        assert get_schema_version(conn) == 42
        conn.close()

    def test_set_version_persists_across_connections(self, tmp_path: Path) -> None:
        """Version should survive connection close and reopen."""
        from pkg_defender.db.schema import get_connection

        db_path = tmp_path / "persist.db"
        conn1 = get_connection(db_path)
        conn1.executescript("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        set_schema_version(conn1, 7)
        conn1.close()

        conn2 = get_connection(db_path)
        assert get_schema_version(conn2) == 7
        conn2.close()

    def test_current_schema_version_is_positive(self) -> None:
        """CURRENT_SCHEMA_VERSION must be a positive integer."""
        assert isinstance(CURRENT_SCHEMA_VERSION, int)
        assert CURRENT_SCHEMA_VERSION >= 1


class TestInitDbVersioning:
    """Tests for init_db schema versioning behavior."""

    def test_fresh_db_gets_current_version(self, tmp_path: Path) -> None:
        """A fresh database created by init_db should have CURRENT_SCHEMA_VERSION."""
        db_path = tmp_path / "fresh.db"
        conn = init_db(db_path)
        version = get_schema_version(conn)
        conn.close()
        assert version == CURRENT_SCHEMA_VERSION

    def test_schema_version_table_exists(self, tmp_path: Path) -> None:
        """init_db should create the schema_version table."""
        db_path = tmp_path / "table_check.db"
        conn = init_db(db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "schema_version" in tables

    def test_schema_version_row_exists(self, tmp_path: Path) -> None:
        """init_db should insert a version row into schema_version."""
        db_path = tmp_path / "row_check.db"
        conn = init_db(db_path)
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        conn.close()
        assert row is not None
        assert row[0] == CURRENT_SCHEMA_VERSION

    def test_existing_db_gets_versioned(self, tmp_path: Path) -> None:
        """A pre-existing DB with schema_version=0 should be stamped to CURRENT_SCHEMA_VERSION."""
        db_path = tmp_path / "existing.db"

        # Create a full DB, then clear the schema_version table
        conn = init_db(db_path)
        conn.execute("DELETE FROM schema_version")
        conn.commit()
        conn.close()

        # init_db should stamp it to current version
        conn = init_db(db_path)
        assert get_schema_version(conn) == CURRENT_SCHEMA_VERSION
        conn.close()

    def test_init_db_idempotent_with_version(self, tmp_path: Path) -> None:
        """Calling init_db twice should not change the version."""
        db_path = tmp_path / "idempotent.db"
        conn1 = init_db(db_path)
        v1 = get_schema_version(conn1)
        conn1.close()

        conn2 = init_db(db_path)
        v2 = get_schema_version(conn2)
        conn2.close()

        assert v1 == v2 == CURRENT_SCHEMA_VERSION

    def test_all_tables_present_after_init(self, tmp_path: Path) -> None:
        """init_db should create all expected tables including schema_version."""
        db_path = tmp_path / "tables.db"
        conn = init_db(db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()

        expected = {
            "threats",
            "version_timestamps",
            "resolution_attempts",
            "bypasses",
            "feed_state",
            "feed_stats",
            "db_metadata",
            "audit_events",
            "schema_version",
        }
        assert expected.issubset(tables)


class TestMigrateDb:
    """Tests for migrate_db function."""

    def test_noop_when_already_at_current_version(self, tmp_path: Path) -> None:
        """migrate_db should do nothing when version matches."""
        db_path = tmp_path / "current.db"
        conn = init_db(db_path)
        # Should not raise or change anything
        migrate_db(conn)
        assert get_schema_version(conn) == CURRENT_SCHEMA_VERSION
        conn.close()

    def test_raises_on_newer_version(self, tmp_path: Path) -> None:
        """migrate_db should raise RuntimeError for a database newer than code."""
        from pkg_defender.db.schema import get_connection

        db_path = tmp_path / "newer.db"
        conn = get_connection(db_path)
        conn.executescript("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        set_schema_version(conn, CURRENT_SCHEMA_VERSION + 99)
        conn.close()

        # Create a connection with a version higher than current
        conn2 = get_connection(db_path)
        with pytest.raises(RuntimeError, match="newer than code version"):
            migrate_db(conn2)
        conn2.close()


class TestBackwardCompatibility:
    """Tests for handling databases created by older code versions."""

    def test_unversioned_db_with_all_tables(self, tmp_path: Path) -> None:
        """A DB with all tables but empty schema_version should be stamped."""
        db_path = tmp_path / "unversioned_full.db"

        # Create a full DB with data, then clear schema_version
        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, source) VALUES (?, ?, ?, ?, ?, ?)",
            ("test:threat", "npm", "test-pkg", "LOW", 0.5, "osv"),
        )
        conn.commit()
        conn.execute("DELETE FROM schema_version")
        conn.commit()
        conn.close()

        # init_db should preserve data and stamp version
        conn = init_db(db_path)
        assert get_schema_version(conn) == CURRENT_SCHEMA_VERSION
        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("test:threat",)).fetchone()
        assert row is not None
        conn.close()
