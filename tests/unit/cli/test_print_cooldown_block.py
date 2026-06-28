"""Tests for _print_cooldown_block failure diagnostics (Phase 4).

Verifies that:
- Known-date blocks show "Published:" line (honest).
- Unknown-date blocks show resolution status, error detail, last attempt time.
- Unknown-date blocks without a DB record show "not attempted" message.
- The string "Published:" NEVER appears when
  release_date is None (regression guard against lying to the user).
"""

from __future__ import annotations

import io
import sqlite3
import sys
from collections.abc import Generator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from pkg_defender.db.schema import (
    ResolutionAttemptRow,
    get_connection,
    init_db,
    insert_resolution_attempt,
)
from pkg_defender.models.command import BlockReason, CommandIntent, PackageRef, ParsedCommand

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PACKAGE_REF = PackageRef(name="test-pkg", raw="test-pkg")

_PARSED_COMMAND = ParsedCommand(
    manager="pip",
    intent=CommandIntent.INSTALL,
    packages=[_PACKAGE_REF],
    manager_subcommand="install",
    manager_flags=[],
    pkgd_flags={},
    file_targets=[],
    raw_args=["install", "test-pkg"],
    requires_file_audit=False,
    is_global=False,
    is_dev_dependency=False,
)


def _make_parsed(**overrides: Any) -> ParsedCommand:
    """Create a ParsedCommand with optional overrides."""
    base = ParsedCommand(
        manager="pip",
        intent=CommandIntent.INSTALL,
        packages=[_PACKAGE_REF],
        manager_subcommand="install",
        manager_flags=[],
        pkgd_flags={},
        file_targets=[],
        raw_args=["install", "test-pkg"],
        requires_file_audit=False,
        is_global=False,
        is_dev_dependency=False,
    )
    if overrides:
        return replace(base, **overrides)
    return base


def _capture_stderr_output(func: Any, *args: Any, **kwargs: Any) -> str:
    """Run a function and capture its stderr output as a string."""
    from pkg_defender.cli import exec as exec_module

    captured = io.StringIO()

    def _plain_write(msg: str) -> None:
        sys.stderr.write(msg + "\n")

    with (
        patch.object(sys, "stderr", captured),
        patch.object(exec_module, "_stderr_write", _plain_write),
    ):
        func(*args, **kwargs)
    return captured.getvalue()


@pytest.fixture()
def db_conn(tmp_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Create an isolated database with resolution_attempts table."""
    db_path = tmp_path / "test.db"
    _init_conn = init_db(db_path)
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()
        _init_conn.close()


# ---------------------------------------------------------------------------
# Tests: _format_resolution_status
# ---------------------------------------------------------------------------


class TestFormatResolutionStatus:
    """Tests for _format_resolution_status()."""

    def test_resolved(self) -> None:
        """'resolved' maps to 'resolved'."""
        from pkg_defender.cli.exec import _format_resolution_status

        assert _format_resolution_status("resolved") == "resolved"

    def test_all_sources_failed(self) -> None:
        """'all_sources_failed' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("all_sources_failed")
        assert result == "resolution failed (all sources exhausted)"

    def test_no_github_url(self) -> None:
        """'no_github_url' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("no_github_url")
        assert result == "no repository URL available for resolution"

    def test_rate_limited(self) -> None:
        """'rate_limited' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("rate_limited")
        assert result == "resolution failed (API rate limit exceeded)"

    def test_timeout(self) -> None:
        """'timeout' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("timeout")
        assert result == "resolution failed (request timed out)"

    def test_network_error(self) -> None:
        """'network_error' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("network_error")
        assert result == "resolution failed (network error)"

    def test_not_found(self) -> None:
        """'not_found' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("not_found")
        assert result == "resolution failed (version not found in any source)"

    def test_server_error(self) -> None:
        """'server_error' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("server_error")
        assert result == "resolution failed (server error)"

    def test_unknown_error(self) -> None:
        """'unknown_error' maps to user-friendly string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("unknown_error")
        assert result == "resolution failed (unknown error)"

    def test_unknown_status_falls_through(self) -> None:
        """An unrecognized status returns a passthrough string."""
        from pkg_defender.cli.exec import _format_resolution_status

        result = _format_resolution_status("custom_status")
        assert result == "resolution status: custom_status"

    def test_all_statuses_have_display_mappings(self) -> None:
        """Every VALID_RESOLUTION_STATUSES entry has a display mapping."""
        from pkg_defender.cli.exec import _RESOLUTION_STATUS_DISPLAY
        from pkg_defender.db.schema import VALID_RESOLUTION_STATUSES

        for status in VALID_RESOLUTION_STATUSES:
            assert status in _RESOLUTION_STATUS_DISPLAY, (
                f"VALID_RESOLUTION_STATUSES entry '{status}' missing from _RESOLUTION_STATUS_DISPLAY"
            )


# ---------------------------------------------------------------------------
# Tests: _lookup_resolution_info
# ---------------------------------------------------------------------------


class TestLookupResolutionInfo:
    """Tests for _lookup_resolution_info()."""

    def test_returns_row_when_record_exists(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Returns a ResolutionAttemptRow when a matching record exists."""
        from pkg_defender.cli.exec import _lookup_resolution_info

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="rate_limited",
            source_label="rate_limited",
            last_error="API rate limit exceeded",
        )

        pkg = PackageRef(name="test-pkg", version="1.0.0")
        # Mock get_db_path to return the real test DB path so exists() passes.
        # Don't mock get_connection — let it create its own connection to the same file.
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        result = _lookup_resolution_info(pkg, "pypi")
        assert result is not None
        assert isinstance(result, ResolutionAttemptRow)
        assert result.resolution_status == "rate_limited"
        assert result.last_error == "API rate limit exceeded"

    def test_returns_none_when_no_record(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Returns None when no matching record exists."""
        from pkg_defender.cli.exec import _lookup_resolution_info

        db_path = tmp_path / "test.db"
        pkg = PackageRef(name="unknown-pkg", version="0.0.1")
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        result = _lookup_resolution_info(pkg, "pypi")
        assert result is None

    def test_returns_none_when_ecosystem_is_none(self) -> None:
        """Returns None immediately when ecosystem is None."""
        from pkg_defender.cli.exec import _lookup_resolution_info

        pkg = PackageRef(name="test-pkg", version="1.0.0")
        result = _lookup_resolution_info(pkg, None)
        assert result is None

    def test_returns_none_on_db_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns None gracefully when DB operations raise."""
        from pkg_defender.cli.exec import _lookup_resolution_info

        pkg = PackageRef(name="test-pkg", version="1.0.0")

        def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("DB error")

        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            _raise,
        )
        result = _lookup_resolution_info(pkg, "pypi")
        assert result is None

    def test_returns_none_when_db_path_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns None when get_db_path returns None."""
        from pkg_defender.cli.exec import _lookup_resolution_info

        pkg = PackageRef(name="test-pkg", version="1.0.0")
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: None,
        )
        result = _lookup_resolution_info(pkg, "pypi")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: _print_cooldown_block — known date
# ---------------------------------------------------------------------------


class TestCooldownBlockKnownDate:
    """Tests for _print_cooldown_block when release_date is known."""

    def test_shows_published_recently_message(self) -> None:
        """When release_date is known, message shows Published line."""
        from pkg_defender.cli.exec import _print_cooldown_block

        release_date = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=release_date,
            date_source="github_tags",
            window_days=3,
        )
        assert "Published:" in output

    def test_shows_published_date(self) -> None:
        """When release_date is known, the Published line is included."""
        from pkg_defender.cli.exec import _print_cooldown_block

        release_date = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=release_date,
            date_source="github_tags",
            window_days=3,
        )
        assert "Published: 2026-06-10 @ 12:00 UTC (source: GitHub Tags)" in output

    def test_does_not_show_precautionary_message(self) -> None:
        """When release_date is known, precautionary block message is NOT shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        release_date = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=release_date,
            date_source="github_tags",
            window_days=3,
        )
        assert "precautionary block" not in output

    def test_does_not_show_resolution_status(self) -> None:
        """When release_date is known, resolution status is NOT shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        release_date = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=release_date,
            date_source="github_tags",
            window_days=3,
        )
        assert "Resolution status" not in output

    def test_block_with_naive_release_date(self) -> None:
        """_print_cooldown_block handles naive release_date without crashing."""
        from pkg_defender.cli.exec import _print_cooldown_block

        naive_date = datetime(2026, 3, 1, 12, 0, 0)  # naive
        pkg = PackageRef(name="test-pkg", version="1.0.0")
        parsed = _make_parsed()
        output = _capture_stderr_output(
            _print_cooldown_block,
            pkg,
            parsed,
            window_days=7,
            release_date=naive_date,
            date_source="test",
            ecosystem="pypi",
        )
        assert "BLOCKED" in output
        assert "test-pkg" in output


# ---------------------------------------------------------------------------
# Tests: _print_cooldown_block — unknown date with resolution record
# ---------------------------------------------------------------------------


class TestCooldownBlockUnknownDateWithRecord:
    """Tests for _print_cooldown_block when release_date is None and a DB record exists."""

    _VERSIONED_PKG = PackageRef(name="test-pkg", version="1.0.0")

    def test_shows_failure_when_date_unknown(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When date is unknown and resolution failed, shows resolution status."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="rate_limited",
            source_label="rate_limited",
            last_error="API rate limit exceeded",
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Could not determine release date." in output
        assert "Resolution status:" in output

    def test_shows_error_detail(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When date is unknown and resolution failed, last_error is shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="rate_limited",
            source_label="rate_limited",
            last_error="API rate limit exceeded",
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Error detail: API rate limit exceeded" in output

    def test_shows_last_attempt_time(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When date is unknown and resolution failed, last attempt time is shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="rate_limited",
            source_label="rate_limited",
            last_error="API rate limit exceeded",
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Last attempt:" in output

    def test_shows_precautionary_block_message(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When date is unknown, precautionary block message is shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="not_found",
            source_label="not_found",
            last_error="Package not found",
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "precautionary block" in output
        assert "cannot confirm this version is safe" in output

    def test_does_not_show_published_recently(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When date is unknown, 'Published:' is NOT shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="timeout",
            source_label="timeout",
            last_error="Connection timed out",
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Published:" not in output

    def test_omits_error_detail_when_last_error_is_none(
        self,
        db_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When last_error is None, the Error detail line is omitted."""
        from pkg_defender.cli.exec import _print_cooldown_block

        db_path = tmp_path / "test.db"
        insert_resolution_attempt(
            conn=db_conn,
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
            publish_time=None,
            resolution_status="all_sources_failed",
            source_label="all_sources_failed",
            last_error=None,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        output = _capture_stderr_output(
            _print_cooldown_block,
            self._VERSIONED_PKG,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Error detail:" not in output
        assert "Resolution status:" in output


# ---------------------------------------------------------------------------
# Tests: _print_cooldown_block — unknown date without resolution record
# ---------------------------------------------------------------------------


class TestCooldownBlockUnknownDateNoRecord:
    """Tests for _print_cooldown_block when release_date is None and no DB record exists."""

    def test_fallback_no_resolution_record(self) -> None:
        """When date is unknown and no DB record, shows 'not attempted' message."""
        from pkg_defender.cli.exec import _print_cooldown_block

        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Resolution has not been attempted for this package." in output

    def test_shows_precautionary_message_without_record(self) -> None:
        """When date is unknown and no DB record, precautionary block message is shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "precautionary block" in output

    def test_does_not_show_published_recently_without_record(self) -> None:
        """When date is unknown and no DB record, 'published recently' is NOT shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Published:" not in output

    def test_no_resolution_status_without_record(self) -> None:
        """When date is unknown and no DB record, resolution status is NOT shown."""
        from pkg_defender.cli.exec import _print_cooldown_block

        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=None,
            window_days=3,
            ecosystem="pypi",
        )
        assert "Resolution status" not in output


# ---------------------------------------------------------------------------
# Tests: handle_blocked_command passes ecosystem through
# ---------------------------------------------------------------------------


class TestHandleBlockedCommandEcosystem:
    """Tests that handle_blocked_command forwards ecosystem to _print_cooldown_block."""

    def test_ecosystem_passed_to_print_cooldown_block(self) -> None:
        """handle_blocked_command passes ecosystem kwarg to _print_cooldown_block."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="eco-pkg", raw="eco-pkg")
        parsed = _make_parsed()

        with (
            patch.object(exec_module, "_print_cooldown_block") as mock_print,
            patch.object(exec_module, "_ask_bypass", return_value=False),
            pytest.raises(SystemExit),
        ):
            exec_module.handle_blocked_command(
                parsed,
                BlockReason.COOLDOWN,
                pkg_ref,
                ecosystem="pypi",
            )

        mock_print.assert_called_once()
        call_kwargs = mock_print.call_args.kwargs
        assert call_kwargs.get("ecosystem") == "pypi"


# ---------------------------------------------------------------------------
# Regression: never lie about date
# ---------------------------------------------------------------------------


class TestNeverLieAboutDate:
    """Regression guard: 'Published:' only appears
    when release_date is not None."""

    def test_known_date_shows_recent(self) -> None:
        """release_date is known → 'published recently' appears."""
        from pkg_defender.cli.exec import _print_cooldown_block

        release_date = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
        output = _capture_stderr_output(
            _print_cooldown_block,
            _PACKAGE_REF,
            _PARSED_COMMAND,
            release_date=release_date,
            date_source="github_tags",
            window_days=3,
        )
        assert "Published:" in output

    def test_unknown_date_with_record_shows_precaution(self) -> None:
        """release_date is None, record exists → 'published recently' does NOT appear."""
        from pkg_defender.cli.exec import _print_cooldown_block

        # We can't insert into a real DB here without mocking, so we mock the lookup
        with patch("pkg_defender.cli.exec._lookup_resolution_info") as mock_lookup:
            mock_lookup.return_value = ResolutionAttemptRow(
                ecosystem="pypi",
                package_name="test-pkg",
                version="1.0.0",
                publish_time=None,
                resolution_status="rate_limited",
                source_label="rate_limited",
                last_error="rate limited",
                attempted_at=datetime(2026, 6, 12, 14, 30, tzinfo=UTC),
                retry_after=None,
            )
            output = _capture_stderr_output(
                _print_cooldown_block,
                _PACKAGE_REF,
                _PARSED_COMMAND,
                release_date=None,
                window_days=3,
                ecosystem="pypi",
            )
        assert "Published:" not in output
        assert "Could not determine release date." in output

    def test_unknown_date_no_record_shows_not_attempted(self) -> None:
        """release_date is None, no record → 'published recently' does NOT appear."""
        from pkg_defender.cli.exec import _print_cooldown_block

        with patch("pkg_defender.cli.exec._lookup_resolution_info", return_value=None):
            output = _capture_stderr_output(
                _print_cooldown_block,
                _PACKAGE_REF,
                _PARSED_COMMAND,
                release_date=None,
                window_days=3,
                ecosystem="pypi",
            )
        assert "Published:" not in output
        assert "Resolution has not been attempted" in output

    def test_never_lies_about_date_regression(self) -> None:
        """Comprehensive regression guard: with release_date=None, the string
        'Published:' MUST NOT appear in output,
        regardless of ecosystem or resolution state."""
        from pkg_defender.cli.exec import _print_cooldown_block

        # Test all three branches: with record, without record, ecosystem=None
        for scenario, lookup_return in [
            (
                "with record",
                ResolutionAttemptRow(
                    ecosystem="pypi",
                    package_name="test-pkg",
                    version="1.0.0",
                    publish_time=None,
                    resolution_status="all_sources_failed",
                    source_label="all_sources_failed",
                    last_error=None,
                    attempted_at=datetime(2026, 6, 12, 14, 30, tzinfo=UTC),
                    retry_after=None,
                ),
            ),
            ("without record", None),
            ("ecosystem=None", None),
        ]:
            ecosystem = "pypi" if scenario != "ecosystem=None" else None
            with patch("pkg_defender.cli.exec._lookup_resolution_info", return_value=lookup_return):
                output = _capture_stderr_output(
                    _print_cooldown_block,
                    _PACKAGE_REF,
                    _PARSED_COMMAND,
                    release_date=None,
                    window_days=3,
                    ecosystem=ecosystem,
                )
            assert "Published:" not in output, f"LIED about date in scenario: {scenario}"
