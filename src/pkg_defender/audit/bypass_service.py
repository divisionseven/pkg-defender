"""Service for querying active bypass entries.

Provides a single, centralized implementation for querying active bypasses,
eliminating the duplicated bypass queries that previously existed in both
the threat check and cooldown check pathways in dispatcher.py.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


class BypassService:
    """Centralized service for querying active bypass entries.

    Eliminates the duplicated inline bypass queries by providing
    a single, consistent implementation for both threat and cooldown checks.

    Usage::

        service = BypassService(db_path)
        active = service.get_active_bypasses("pypi")
        # Returns {("requests", "2.31.0"), ...}
    """

    def __init__(self, db_path: Path | None) -> None:
        """Initialize with an optional database path.

        Args:
            db_path: Path to the SQLite database, or None (returns empty set
                for all queries).
        """
        self._db_path = db_path

    def get_active_bypasses(self, ecosystem: str) -> set[tuple[str, str]]:
        """Get all non-expired bypass entries for a given ecosystem.

        Returns a ``set[tuple[str, str]]`` of ``(package_name, version)`` pairs
        for all active (non-expired) bypasses matching *ecosystem*.

        Returns an empty set if:
        * ``db_path`` was ``None`` or the database file does not exist.
        * A :class:`sqlite3.Error` occurs during the query.
        """
        # Local import to avoid Python module caching issues with test patches
        from pkg_defender.db.schema import get_connection

        if not self._db_path or not self._db_path.exists():
            return set()

        try:
            conn = get_connection(self._db_path)
            try:
                rows = conn.execute(
                    "SELECT package_name, version FROM bypasses "
                    "WHERE ecosystem = ? "
                    "AND (expires_at IS NULL OR expires_at >= datetime('now'))",
                    (ecosystem,),
                ).fetchall()
                return {(row[0], row[1]) for row in rows}
            finally:
                conn.close()
        except sqlite3.Error:
            logger.warning("Could not query active bypasses, proceeding without bypass check")
            return set()
