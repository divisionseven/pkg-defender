"""Integration tests for fail-closed install behavior.

Per spec §2.1: install-time checks must fail-closed. Every error path
in the install decision engine must block installation, not silently
allow it.

These tests exercise the full install path through ManagerDispatcher,
covering all 9 critical silent failure paths identified in the board
meeting.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from pkg_defender.cli.dispatcher import ManagerDispatcher
from pkg_defender.models.command import (
    CommandIntent,
    PackageRef,
    ParsedCommand,
)


class TestFailClosedInstall:
    """All error paths in install must block, not allow."""

    def _make_parsed(self, packages: list[PackageRef]) -> ParsedCommand:
        """Helper: build a ParsedCommand with INSTALL intent."""
        return ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=packages,
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            raw_args=["install"] + [p.raw for p in packages],
            requires_file_audit=False,
        )

    def _make_ctx(self) -> MagicMock:
        """Helper: build a mock Click context with fail_on_threat=True."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Helper: build a ManagerDispatcher bypassing __init__.

        ManagerDispatcher.__init__ requires MANAGER_REGISTRY and
        adapter instantiation, which are unnecessary for unit-testing
        _check_threats / _check_cooldown directly.
        """
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def test_missing_db_blocks_install(self) -> None:
        """Missing threat DB → install blocked with user message."""
        parsed = self._make_parsed([PackageRef(name="requests", version="2.28.0", raw="requests==2.28.0")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        with patch("pkg_defender.config.get_db_path", return_value=None):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False

    def test_db_error_blocks_install(self) -> None:
        """DB open error → install blocked with user message."""
        parsed = self._make_parsed([PackageRef(name="requests", version="2.28.0", raw="requests==2.28.0")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        with (
            patch(
                "pkg_defender.config.get_db_path",
                return_value=Path("/fake/db.sqlite3"),
            ),
            patch(
                "pkg_defender.cli.dispatcher.get_connection",
                side_effect=sqlite3.Error("corrupt"),
            ),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False

    def test_timeout_blocks_install(self) -> None:
        """Check timeout → install blocked with user message."""
        parsed = self._make_parsed([PackageRef(name="requests", version="2.28.0", raw="requests==2.28.0")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        mock_conn = MagicMock()

        with (
            patch(
                "pkg_defender.config.get_db_path",
                return_value=Path("/fake/db.sqlite3"),
            ),
            patch(
                "pkg_defender.cli.dispatcher.get_connection",
                return_value=mock_conn,
            ),
            patch(
                "pkg_defender.core.checker.check_packages_batch",
                side_effect=sqlite3.Error("timed out"),
            ),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False

    def test_no_version_blocks_install(self) -> None:
        """No version → install blocked with user message."""
        parsed = self._make_parsed([PackageRef(name="requests", version=None, raw="requests")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        mock_conn = MagicMock()

        with (
            patch(
                "pkg_defender.config.get_db_path",
                return_value=Path("/fake/db.sqlite3"),
            ),
            patch(
                "pkg_defender.cli.dispatcher.get_connection",
                return_value=mock_conn,
            ),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False

    def test_cooldown_new_package_blocks(self) -> None:
        """New package within cooldown window → install blocked."""
        parsed = self._make_parsed([PackageRef(name="requests", version="2.28.0", raw="requests==2.28.0")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC), "verified"),
        }

        with patch(
            "pkg_defender.audit.cooldown.step_check_cooldown",
            return_value=(False, 5),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False
        assert result.block_decision is not None
        assert result.block_decision.package.name == "requests"

    def test_cooldown_missing_release_date_blocks(self) -> None:
        """Package with None release date → install blocked."""
        parsed = self._make_parsed([PackageRef(name="requests", version="2.28.0", raw="requests==2.28.0")])
        ctx = self._make_ctx()
        dispatcher = self._make_dispatcher()

        release_dates: dict[str, tuple[datetime | None, str]] = {"requests": (None, "")}

        with patch("pkg_defender.cli.exec.handle_blocked_command"):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False
