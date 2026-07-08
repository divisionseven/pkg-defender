"""Tests for database schema, connection management, and retry utilities."""

from __future__ import annotations

import sqlite3

import pytest

from pkg_defender.db.schema import retry_on_busy

# ---------------------------------------------------------------------------
# Tests: retry_on_busy decorator (Item 6 — exponential backoff for SQLITE_BUSY)
# ---------------------------------------------------------------------------


class TestRetryOnBusy:
    """Unit tests for the ``retry_on_busy`` decorator in isolation.

    These tests apply ``@retry_on_busy`` directly to simple test functions
    rather than testing it through the ``FeedAggregator._sync_feed_db_ops``
    integration path. This avoids the flaw where ``patch.object()``
    bypasses the decorator entirely (because ``patch.object`` replaces the
    method at the instance attribute level, while the decorator wraps at
    the class definition level).
    """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_counter() -> dict[str, int]:
        """Return a mutable container for tracking call counts."""
        return {"count": 0}

    # ------------------------------------------------------------------
    # Happy path: retry succeeds after transient busy errors
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("max_retries", [1, 3, 5])
    def test_retries_on_consecutive_busy_errors(self, max_retries: int) -> None:
        """Retry succeeds when the function stops raising SQLITE_BUSY.

        Succeeds on the last attempt (``max_retries`` calls total).
        This parametrised variant proves the decorator works at
        boundary values (1, 3, 5).
        """
        counter = self._make_counter()

        @retry_on_busy(max_retries=max_retries, base_delay=0.01)
        def _work() -> int:
            counter["count"] += 1
            if counter["count"] < max_retries:
                msg = "database is locked"
                raise sqlite3.OperationalError(msg)
            return 42

        result = _work()

        assert result == 42
        assert counter["count"] == max_retries

    # ------------------------------------------------------------------
    # Exhaustion: all retries consumed, exception propagates
    # ------------------------------------------------------------------

    def test_exhausts_all_retries_and_raises(self) -> None:
        """After exhausting all retries, the last ``OperationalError`` propagates."""
        call_count = 0

        @retry_on_busy(max_retries=3, base_delay=0.01)
        def _always_fail() -> int:
            nonlocal call_count
            call_count += 1
            msg = "database is locked"
            raise sqlite3.OperationalError(msg)

        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            _always_fail()

        assert call_count == 3  # All 3 attempts made before giving up

    # ------------------------------------------------------------------
    # Non-busy OperationalError: must NOT retry
    # ------------------------------------------------------------------

    def test_does_not_retry_non_busy_operational_error(self) -> None:
        """``OperationalError`` without "database is locked" propagates immediately."""
        call_count = 0

        @retry_on_busy(max_retries=3, base_delay=0.01)
        def _no_such_table() -> None:
            nonlocal call_count
            call_count += 1
            msg = "no such table: threats"
            raise sqlite3.OperationalError(msg)

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            _no_such_table()

        assert call_count == 1  # No retry — only 1 call

    # ------------------------------------------------------------------
    # IntegrityError: must NOT retry
    # ------------------------------------------------------------------

    def test_does_not_retry_integrity_error(self) -> None:
        """``IntegrityError`` propagates immediately — no retry."""
        call_count = 0

        @retry_on_busy(max_retries=3, base_delay=0.01)
        def _unique_violation() -> None:
            nonlocal call_count
            call_count += 1
            raise sqlite3.IntegrityError("UNIQUE constraint failed")

        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
            _unique_violation()

        assert call_count == 1  # No retry — only 1 call

    # ------------------------------------------------------------------
    # Success path: no error on first attempt
    # ------------------------------------------------------------------

    def test_success_path_no_retry(self) -> None:
        """When the function succeeds on the first call, no retry occurs."""
        call_count = 0

        @retry_on_busy(max_retries=3, base_delay=0.01)
        def _succeed() -> str:
            nonlocal call_count
            call_count += 1
            return "ok"

        result = _succeed()

        assert result == "ok"
        assert call_count == 1  # Exactly 1 call — no retry
