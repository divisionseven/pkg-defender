"""Unit tests for daemon runner utility functions."""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


class TestCleanupStuckSyncingFeeds:
    """Tests for _cleanup_stuck_syncing_feeds cleanup function."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_db_with_feed_state(tmp_path: Path, rows: list[tuple[str, str, str | None]]) -> Path:
        """Create a temp SQLite DB with feed_state table and fixture rows.

        Args:
            tmp_path: Temp directory path.
            rows: List of (feed_name, status, updated_at) tuples.

        Returns:
            Path to the created database file.
        """
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE feed_state (  feed_name TEXT PRIMARY KEY,  status TEXT,  updated_at TEXT)")
        for feed_name, status, updated_at in rows:
            if updated_at is not None:
                conn.execute(
                    "INSERT INTO feed_state (feed_name, status, updated_at) VALUES (?, ?, ?)",
                    (feed_name, status, updated_at),
                )
            else:
                conn.execute(
                    "INSERT INTO feed_state (feed_name, status) VALUES (?, ?)",
                    (feed_name, status),
                )
        conn.commit()
        conn.close()
        return db_path

    @staticmethod
    def _get_feed_status(db_path: Path, feed_name: str) -> tuple[str, str] | None:
        """Get status and updated_at for a feed.

        Args:
            db_path: Path to the SQLite database.
            feed_name: Feed name to look up.

        Returns:
            (status, updated_at) tuple, or None if feed not found.
        """
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT status, updated_at FROM feed_state WHERE feed_name = ?",
                (feed_name,),
            ).fetchone()
            if row is None:
                return None
            return (row[0], row[1])
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_cleans_stuck_syncing_feeds(self, tmp_path: Path) -> None:
        """Reset single 'syncing' row to 'idle' with updated timestamp."""
        from pkg_defender.daemon.runner import _cleanup_stuck_syncing_feeds

        db_path = self._create_db_with_feed_state(tmp_path, [("test-feed", "syncing", "2025-01-01 00:00:00")])

        _cleanup_stuck_syncing_feeds(db_path)

        result = self._get_feed_status(db_path, "test-feed")
        assert result is not None
        status, updated_at = result
        assert status == "idle"
        assert updated_at is not None
        assert updated_at != "2025-01-01 00:00:00"

    def test_does_not_affect_idle_status(self, tmp_path: Path) -> None:
        """Idle row remains unchanged after cleanup."""
        from pkg_defender.daemon.runner import _cleanup_stuck_syncing_feeds

        db_path = self._create_db_with_feed_state(tmp_path, [("test-feed", "idle", "2025-01-01 00:00:00")])

        _cleanup_stuck_syncing_feeds(db_path)

        result = self._get_feed_status(db_path, "test-feed")
        assert result is not None
        status, updated_at = result
        assert status == "idle"
        assert updated_at == "2025-01-01 00:00:00"

    def test_does_not_affect_error_status(self, tmp_path: Path) -> None:
        """Error row remains unchanged after cleanup."""
        from pkg_defender.daemon.runner import _cleanup_stuck_syncing_feeds

        db_path = self._create_db_with_feed_state(tmp_path, [("test-feed", "error", "2025-01-01 00:00:00")])

        _cleanup_stuck_syncing_feeds(db_path)

        result = self._get_feed_status(db_path, "test-feed")
        assert result is not None
        status, updated_at = result
        assert status == "error"
        assert updated_at == "2025-01-01 00:00:00"

    def test_mixed_statuses(self, tmp_path: Path) -> None:
        """Only syncing row is reset; idle and error remain unchanged."""
        from pkg_defender.daemon.runner import _cleanup_stuck_syncing_feeds

        db_path = self._create_db_with_feed_state(
            tmp_path,
            [
                ("feed-syncing", "syncing", "2025-01-01 00:00:00"),
                ("feed-idle", "idle", "2025-01-01 00:00:00"),
                ("feed-error", "error", "2025-01-01 00:00:00"),
            ],
        )

        _cleanup_stuck_syncing_feeds(db_path)

        syncing_result = self._get_feed_status(db_path, "feed-syncing")
        assert syncing_result is not None
        assert syncing_result[0] == "idle"
        assert syncing_result[1] != "2025-01-01 00:00:00"

        idle_result = self._get_feed_status(db_path, "feed-idle")
        assert idle_result is not None
        assert idle_result[0] == "idle"
        assert idle_result[1] == "2025-01-01 00:00:00"

        error_result = self._get_feed_status(db_path, "feed-error")
        assert error_result is not None
        assert error_result[0] == "error"
        assert error_result[1] == "2025-01-01 00:00:00"

    def test_empty_table_is_noop(self, tmp_path: Path) -> None:
        """Empty feed_state table causes no error."""
        from pkg_defender.daemon.runner import _cleanup_stuck_syncing_feeds

        db_path = self._create_db_with_feed_state(tmp_path, [])

        # Should not raise any exception
        _cleanup_stuck_syncing_feeds(db_path)

        # Verify table is still empty
        conn = sqlite3.connect(str(db_path))
        try:
            count = conn.execute("SELECT COUNT(*) FROM feed_state").fetchone()[0]
            assert count == 0
        finally:
            conn.close()


# ============================================================================
# TestRemovePidFile
# ============================================================================


class TestRemovePidFile:
    """Tests for ``_remove_pid_file()`` helper."""

    def test_remove_pid_file_removes_existing(self, monkeypatch, tmp_path) -> None:
        """PID file exists -> ``_remove_pid_file()`` removes it."""
        from pkg_defender.daemon.runner import PID_FILENAME, _remove_pid_file

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        # Patch at runner module level because runner.py imports get_data_dir
        # at module top level (unlike daemon.py which uses local imports)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.get_data_dir",
            lambda: data_dir,
        )

        pid_file = data_dir / PID_FILENAME
        pid_file.write_text("12345")

        _remove_pid_file()

        assert not pid_file.exists()

    def test_remove_pid_file_missing_ok(self, monkeypatch, tmp_path) -> None:
        """PID file does not exist -> no error raised."""
        from pkg_defender.daemon.runner import _remove_pid_file

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.get_data_dir",
            lambda: data_dir,
        )

        # Should not raise
        _remove_pid_file()

    def test_remove_pid_file_oserror_handled(self, monkeypatch, tmp_path, caplog) -> None:
        """``unlink`` raises ``OSError`` -> logged and swallowed.

        Root cause: ``runner.py`` lines 171-174 -- ``except OSError``
        catches the exception and logs at DEBUG level without re-raising.
        """
        import logging

        from pkg_defender.daemon.runner import PID_FILENAME, _remove_pid_file

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.get_data_dir",
            lambda: data_dir,
        )

        pid_file = data_dir / PID_FILENAME
        pid_file.write_text("12345")

        # Monkeypatch Path.unlink to raise OSError for this test
        def _broken_unlink(self, *args, **kwargs):
            raise OSError("Permission denied")

        monkeypatch.setattr(Path, "unlink", _broken_unlink)

        with caplog.at_level(logging.DEBUG):
            _remove_pid_file()

        assert "Could not remove PID file" in caplog.text


# ============================================================================
# TestDaemonTimeout — C7 feed_sync_timeout
# ============================================================================


class TestDaemonTimeout:
    """Tests for daemon TimeoutError handling (C7: feed_sync_timeout)."""

    async def test_timeout_during_sync_writes_error_heartbeat(self, tmp_path: Path) -> None:
        """sync_all raises TimeoutError → error heartbeat written, daemon continues.

        When ``asyncio.wait_for(aggregator.sync_all(), ...)`` raises
        ``TimeoutError`` on the first sync attempt:
        1. An error heartbeat is written with status "error" and a "timed out"
           message.
        2. The daemon applies backoff and continues the loop (``continue`` path).
        3. On the second sync attempt, sync succeeds.
        4. The daemon shuts down cleanly when shutdown is signaled.
        """
        from pkg_defender.config.settings import PKGDConfig
        from pkg_defender.daemon.runner import daemon_loop

        data_dir = tmp_path / "data"
        data_dir.mkdir()

        config = PKGDConfig()
        config.feeds.feed_sync_timeout = 300

        mock_aggregator = MagicMock()
        mock_aggregator.sync_all = AsyncMock(
            side_effect=[TimeoutError("sync timed out"), {}],
        )

        captured_heartbeats: list[dict[str, Any]] = []

        def _capture_heartbeat(_dir: Any, hb_data: dict[str, Any]) -> None:
            captured_heartbeats.append(hb_data)

        wait_call_count = 0

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            nonlocal wait_call_count
            wait_call_count += 1

            if wait_call_count == 1:
                # Call 1: sync_all wrapper → propagate TimeoutError from mock
                try:
                    return await coro
                except TimeoutError:
                    raise

            if wait_call_count == 2:
                # Call 2: shutdown.wait() with backoff timeout inside
                # TimeoutError handler → raise TimeoutError so daemon continues
                if hasattr(coro, "close") and callable(coro.close):
                    with contextlib.suppress(Exception):
                        coro.close()
                raise TimeoutError()

            if wait_call_count == 3:
                # Call 3: sync_all in second iteration → succeeds
                return await coro

            # Call 4+: shutdown.wait() → resolve to break the loop
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            return

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.write_heartbeat", side_effect=_capture_heartbeat),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
        ):
            await daemon_loop(config)

        # Verify the daemon loop continued and sync was attempted twice
        assert mock_aggregator.sync_all.call_count == 2, (
            f"Expected sync_all to be called twice, got {mock_aggregator.sync_all.call_count}"
        )

        # Verify that an error heartbeat was written (at least one after startup)
        error_heartbeats = [h for h in captured_heartbeats if h.get("status") == "error"]
        assert len(error_heartbeats) >= 1, f"Expected at least 1 error heartbeat, got: {captured_heartbeats}"
        last_error = error_heartbeats[-1]
        assert last_error["status"] == "error"
        assert "timed out" in last_error.get("error", "").lower()
