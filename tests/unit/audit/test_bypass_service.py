"""Tests for BypassService."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest import mock

from pkg_defender.audit.bypass_service import BypassService


class TestBypassService:
    """Unit tests for BypassService."""

    def test_none_db_path_returns_empty(self) -> None:
        """BypassService with db_path=None returns empty set."""
        service = BypassService(None)
        assert service.get_active_bypasses("pypi") == set()

    def test_nonexistent_db_returns_empty(self) -> None:
        """BypassService with nonexistent db_path returns empty set."""
        service = BypassService(Path("/nonexistent/path.db"))
        assert service.get_active_bypasses("pypi") == set()

    def test_sqlite_error_returns_empty(self) -> None:
        """SQLite error during query returns empty set (not an exception)."""
        with mock.patch("pkg_defender.db.schema.get_connection") as mock_get_conn:
            mock_get_conn.side_effect = sqlite3.Error("mock error")
            service = BypassService(Path("/tmp/fake.db"))
            result = service.get_active_bypasses("pypi")
            assert result == set()

    def test_returns_active_bypasses(self, tmp_path: Path) -> None:
        """BypassService returns active bypass tuples for matching ecosystem."""
        db_path = self._create_test_db(
            tmp_path,
            rows=[
                ("pypi", "requests", "2.31.0", None),  # never expires
                ("pypi", "urllib3", "1.26.18", "2099-01-01"),  # far future
                ("npm", "lodash", "4.17.21", None),  # wrong ecosystem
                ("pypi", "expired", "1.0.0", "2020-01-01"),  # expired
            ],
        )
        service = BypassService(db_path)
        result = service.get_active_bypasses("pypi")
        assert result == {("requests", "2.31.0"), ("urllib3", "1.26.18")}

    def test_empty_when_no_matching_ecosystem(self, tmp_path: Path) -> None:
        """BypassService returns empty set when no bypasses exist for ecosystem."""
        db_path = self._create_test_db(
            tmp_path,
            rows=[
                ("npm", "lodash", "4.17.21", None),
            ],
        )
        service = BypassService(db_path)
        result = service.get_active_bypasses("pypi")
        assert result == set()

    @staticmethod
    def _create_test_db(
        tmp_path: Path,
        rows: list[tuple[str, str, str, str | None]],
    ) -> Path:
        """Create a test SQLite database with bypass table and rows."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE bypasses (
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                expires_at TEXT
            )
        """)
        for row in rows:
            conn.execute(
                "INSERT INTO bypasses (ecosystem, package_name, version, expires_at) VALUES (?, ?, ?, ?)",
                row,
            )
        conn.commit()
        conn.close()
        return db_path
