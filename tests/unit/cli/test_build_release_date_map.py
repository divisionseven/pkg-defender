"""Tests for ManagerDispatcher._build_release_date_map() — Phase 5 JOIN logic.

Verifies that the release-date map merges successful timestamps from
``version_timestamps`` with failure metadata from ``resolution_attempts``,
and that success takes priority over failure when both are present.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from pkg_defender.cli.dispatcher import ManagerDispatcher
from pkg_defender.models.command import CommandIntent, PackageRef, ParsedCommand

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dispatcher() -> ManagerDispatcher:
    """Create a bare dispatcher instance (bypasses __init__)."""
    dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
    dispatcher.manager_name = "pip"
    dispatcher.adapter = MagicMock()
    dispatcher.adapter.ecosystem = "pypi"
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


def _populate_success(
    conn: object,
    *,
    ecosystem: str = "pypi",
    name: str = "requests",
    version: str = "2.0.0",
    publish_time: datetime | None = None,
    source_label: str = "registry_api",
) -> None:
    """Insert a successful timestamp into ``version_timestamps``."""
    from pkg_defender.db.schema import insert_version_timestamp
    from pkg_defender.models import VersionInfo

    if publish_time is None:
        publish_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    insert_version_timestamp(
        conn=cast(sqlite3.Connection, conn),
        info=VersionInfo(
            ecosystem=ecosystem,
            package_name=name,
            version=version,
            publish_time=publish_time,
            date_source=source_label,
        ),
    )


def _populate_failure(
    conn: object,
    *,
    ecosystem: str = "pypi",
    name: str = "requests",
    version: str = "2.0.0",
    resolution_status: str = "rate_limited",
    source_label: str = "rate_limited",
    last_error: str | None = "rate_limited",
) -> None:
    """Insert a failure record into ``resolution_attempts``."""
    from pkg_defender.db.schema import insert_resolution_attempt

    insert_resolution_attempt(
        conn=cast(sqlite3.Connection, conn),
        ecosystem=ecosystem,
        package_name=name,
        version=version,
        publish_time=None,
        resolution_status=resolution_status,
        source_label=source_label,
        last_error=last_error,
    )


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


class TestBuildReleaseDateMap:
    """Tests for _build_release_date_map() JOIN logic."""

    def test_build_map_includes_failure_status(self, tmp_path: Path) -> None:
        """Failure in resolution_attempts appears as (None, <failure_status>).

        When a package has a failure record in ``resolution_attempts`` but no
        success record in ``version_timestamps``, the map entry is
        ``(None, <resolution_status>)``.
        """
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)

        try:
            _populate_failure(conn, resolution_status="rate_limited", source_label="rate_limited")
        finally:
            conn.close()

        dispatcher = _make_dispatcher()
        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            result = dispatcher._build_release_date_map(parsed)

        assert "requests" in result
        dt, source = result["requests"]
        assert dt is None
        assert source == "rate_limited"

    def test_build_map_success_takes_priority(self, tmp_path: Path) -> None:
        """Success in version_timestamps overrides failure in resolution_attempts.

        When a package has both a success record (``version_timestamps``) and a
        failure record (``resolution_attempts``), the success wins because
        ``version_timestamps`` is written first and the map assigns it before
        checking ``resolution_attempts``.
        """
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)

        publish_dt = datetime(2026, 3, 10, 8, 0, 0, tzinfo=UTC)
        try:
            _populate_success(conn, publish_time=publish_dt, source_label="github_tags")
            _populate_failure(conn, resolution_status="not_found", source_label="not_found")
        finally:
            conn.close()

        dispatcher = _make_dispatcher()
        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            result = dispatcher._build_release_date_map(parsed)

        assert "requests" in result
        dt, source = result["requests"]
        assert dt == publish_dt
        assert source == "github_tags"

    def test_build_map_empty_on_no_data(self, tmp_path: Path) -> None:
        """No rows in either table returns empty dict."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        dispatcher = _make_dispatcher()
        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            result = dispatcher._build_release_date_map(parsed)

        assert result == {}

    def test_build_map_graceful_fallback_no_db(self) -> None:
        """Missing DB returns empty dict without raising."""
        dispatcher = _make_dispatcher()
        parsed = _make_parsed()

        with patch("pkg_defender.config.get_db_path", return_value=None):
            result = dispatcher._build_release_date_map(parsed)

        assert result == {}

    def test_build_map_various_failure_statuses(self, tmp_path: Path) -> None:
        """Different failure statuses flow through correctly."""
        from pkg_defender.db.schema import init_db

        statuses = [
            ("all_sources_failed", "all_sources_failed"),
            ("no_github_url", "no_github_url"),
            ("timeout", "timeout"),
            ("network_error", "network_error"),
            ("not_found", "not_found"),
            ("server_error", "server_error"),
            ("unknown_error", "unknown_error"),
        ]

        for status, expected_source in statuses:
            db_path = tmp_path / f"test_{status}.db"
            conn = init_db(db_path)

            try:
                _populate_failure(
                    conn,
                    name="test-pkg",
                    version="1.0.0",
                    resolution_status=status,
                    source_label=status,
                )
            finally:
                conn.close()

            dispatcher = _make_dispatcher()
            pkg = PackageRef(name="test-pkg", version="1.0.0", ecosystem="pypi")
            parsed = ParsedCommand(
                manager="pip",
                intent=CommandIntent.INSTALL,
                packages=[pkg],
                raw_args=["pip", "install", "test-pkg==1.0.0"],
                pkgd_flags={},
            )

            with patch("pkg_defender.config.get_db_path", return_value=db_path):
                result = dispatcher._build_release_date_map(parsed)

            assert "test-pkg" in result, f"Missing entry for status={status}"
            dt, source = result["test-pkg"]
            assert dt is None, f"publish_time should be None for status={status}"
            assert source == expected_source, f"Wrong source for status={status}"


class TestCheckCooldownFailureStatus:
    """Tests verifying failure status flows through _check_cooldown to display."""

    def test_check_cooldown_passes_failure_status_to_display(self, tmp_path: Path) -> None:
        """Failure status from _build_release_date_map reaches handle_blocked_command.

        When ``release_dates`` maps a package to ``(None, "rate_limited")``,
        ``_check_cooldown`` should pass ``date_source="rate_limited"`` to
        ``handle_blocked_command``.
        """
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        dispatcher = _make_dispatcher()

        # Simulate release_dates as returned by _build_release_date_map
        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (None, "rate_limited"),
        }

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        click_ctx = MagicMock()
        click_ctx.obj = {"fail_on_threat": True}

        # Mock bypass_service property to avoid DB access
        mock_bypass = MagicMock()
        mock_bypass.get_active_bypasses.return_value = {}

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch("pkg_defender.config.load_config") as mock_config,
            patch.object(
                type(dispatcher),
                "bypass_service",
                new_callable=lambda: property(lambda self: mock_bypass),
            ),
        ):
            # Mock config
            config = MagicMock()
            config.cooldown.enabled = True
            config.cooldown.cooldown_days = 3
            config.cooldown.trust_adjustments = {}
            mock_config.return_value = config

            result = dispatcher._check_cooldown(
                parsed,
                click_ctx,
                release_dates,
                start_time_ms=None,
            )

            # Verify block_decision has the failure status
            assert result.block_decision is not None
            assert result.block_decision.date_source == "rate_limited"
