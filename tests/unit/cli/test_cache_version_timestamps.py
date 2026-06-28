"""Tests for ManagerDispatcher._cache_version_timestamps_async() — Phase 3 failure recording.

Verifies that resolution failures are written to the ``resolution_attempts``
table instead of being silently dropped, and that successes are recorded in
both ``version_timestamps`` and ``resolution_attempts``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.cli.dispatcher import ManagerDispatcher, _derive_failure_status
from pkg_defender.models.command import CommandIntent, PackageRef, ParsedCommand


def _make_dispatcher() -> ManagerDispatcher:
    """Create a bare dispatcher instance (bypasses __init__)."""
    dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
    dispatcher.manager_name = "pip"
    return dispatcher


def _make_parsed(
    name: str = "requests",
    version: str = "2.0.0",
    ecosystem: str = "pypi",
) -> ParsedCommand:
    """Build a minimal ParsedCommand for testing."""
    pkg = PackageRef(name=name, version=version, ecosystem=ecosystem)
    return ParsedCommand(
        manager="pip",
        intent=CommandIntent.INSTALL,
        packages=[pkg],
        raw_args=["pip", "install", f"{name}=={version}"],
        pkgd_flags={},
    )


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestDeriveFailureStatus:
    """Tests for _derive_failure_status() helper."""

    def test_rate_limited_from_source_label(self) -> None:
        """source_label='rate_limited' → 'rate_limited'."""
        assert _derive_failure_status("rate_limited", set()) == "rate_limited"

    def test_rate_limited_from_session_errors(self) -> None:
        """Session error 'rate_limited' overrides any source_label."""
        assert _derive_failure_status("unresolved", {"rate_limited"}) == "rate_limited"

    def test_not_found(self) -> None:
        """source_label='not_found' → 'not_found'."""
        assert _derive_failure_status("not_found", set()) == "not_found"

    def test_timeout(self) -> None:
        """source_label='timeout' → 'timeout'."""
        assert _derive_failure_status("timeout", set()) == "timeout"

    def test_network_error(self) -> None:
        """source_label='network_error' → 'network_error'."""
        assert _derive_failure_status("network_error", set()) == "network_error"

    def test_server_error(self) -> None:
        """source_label='server_error' → 'server_error'."""
        assert _derive_failure_status("server_error", set()) == "server_error"

    def test_unknown_error(self) -> None:
        """source_label='unknown_error' → 'unknown_error'."""
        assert _derive_failure_status("unknown_error", set()) == "unknown_error"

    def test_user_manual_fallback(self) -> None:
        """source_label='user_manual' → 'all_sources_failed'."""
        assert _derive_failure_status("unresolved", set()) == "all_sources_failed"

    def test_unknown_source_label_fallback(self) -> None:
        """Unrecognized source_label → 'all_sources_failed'."""
        assert _derive_failure_status("something_weird", set()) == "all_sources_failed"

    def test_session_errors_override_not_found(self) -> None:
        """Session 'rate_limited' overrides source_label='not_found'."""
        assert _derive_failure_status("not_found", {"rate_limited"}) == "rate_limited"


# ---------------------------------------------------------------------------
# Cache writer integration tests
# ---------------------------------------------------------------------------


class TestCacheWritesResolutionAttempt:
    """Tests verifying _cache_version_timestamps_async writes to resolution_attempts."""

    @pytest.mark.asyncio
    async def test_cache_failure_writes_resolution_attempt(self, tmp_path: Path) -> None:
        """Adapter returns (None, 'rate_limited') → resolution_attempts row exists."""
        from pkg_defender.db.schema import (
            get_connection,
            get_resolution_attempt,
            init_db,
        )

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(return_value=(None, "rate_limited"))
        adapter.ecosystem = "pypi"

        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = _make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        try:
            attempt = get_resolution_attempt(conn, "pypi", "requests", "2.0.0")
            assert attempt is not None, "resolution_attempts row must exist after failure"
            assert attempt.publish_time is None
            assert attempt.resolution_status == "rate_limited"
            assert attempt.source_label == "rate_limited"
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_cache_success_writes_resolution_attempt(self, tmp_path: Path) -> None:
        """Adapter returns datetime → both version_timestamps and resolution_attempts updated."""
        from pkg_defender.db.schema import (
            get_connection,
            get_resolution_attempt,
            get_version_timestamps_batch,
            init_db,
        )

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        publish_dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(return_value=(publish_dt, "registry_api"))
        adapter.ecosystem = "pypi"

        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = _make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        try:
            # Verify version_timestamps has the success record
            ts = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
            assert ("pypi", "requests", "2.0.0") in ts
            dt, source = ts[("pypi", "requests", "2.0.0")]
            assert dt == publish_dt
            assert source == "registry_api"

            # Verify resolution_attempts also has the success record
            attempt = get_resolution_attempt(conn, "pypi", "requests", "2.0.0")
            assert attempt is not None, "resolution_attempts row must exist on success"
            assert attempt.publish_time == publish_dt
            assert attempt.resolution_status == "resolved"
            assert attempt.source_label == "registry_api"
            assert attempt.last_error is None
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_cache_timeout_writes_timeout_status(self, tmp_path: Path) -> None:
        """Adapter raises TimeoutError → resolution_status='timeout'."""
        from pkg_defender.db.schema import (
            get_connection,
            get_resolution_attempt,
            init_db,
        )

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(side_effect=TimeoutError("timed out"))
        adapter.ecosystem = "pypi"

        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = _make_dispatcher()
            dispatcher.adapter = adapter
            # Should not raise — TimeoutError is caught and logged
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        try:
            attempt = get_resolution_attempt(conn, "pypi", "requests", "2.0.0")
            assert attempt is not None, "resolution_attempts row must exist after timeout"
            assert attempt.publish_time is None
            assert attempt.resolution_status == "timeout"
            assert attempt.source_label == "timeout"
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_cache_failure_does_not_block_install(self, tmp_path: Path) -> None:
        """Failure is recorded but the method completes without raising."""
        from pkg_defender.db.schema import (
            get_connection,
            get_resolution_attempt,
            init_db,
        )

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(return_value=(None, "not_found"))
        adapter.ecosystem = "pypi"

        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = _make_dispatcher()
            dispatcher.adapter = adapter
            # Must complete without raising — best-effort
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        try:
            attempt = get_resolution_attempt(conn, "pypi", "requests", "2.0.0")
            assert attempt is not None
            assert attempt.resolution_status == "not_found"
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_cache_generic_exception_writes_failure(self, tmp_path: Path) -> None:
        """Generic exception from adapter → failure record written with derived status."""
        from pkg_defender.db.schema import (
            get_connection,
            get_resolution_attempt,
            init_db,
        )

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(side_effect=RuntimeError("boom"))
        adapter.ecosystem = "pypi"

        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = _make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        try:
            attempt = get_resolution_attempt(conn, "pypi", "requests", "2.0.0")
            assert attempt is not None, "resolution_attempts row must exist after exception"
            assert attempt.publish_time is None
            # RuntimeError doesn't match any known status → all_sources_failed
            assert attempt.resolution_status == "all_sources_failed"
        finally:
            conn.close()
