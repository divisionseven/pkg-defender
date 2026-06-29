"""Tests for pkg_defender.cli.commands.audit_logs module.

Covers ``audit-logs query`` and ``audit-logs stats`` commands.
Targets 90%+ line and branch coverage.

Strategy
--------
- Uses ``isolated_env`` fixture to create a real temp DB with all tables
  (including ``audit_events``) and monkeypatched ``get_db_path``.
- Inserts test rows directly into ``audit_events`` via real SQLite.
- Verifies output content for both table (query) and summary (stats)
  display modes, plus all error paths (invalid datetimes, missing DB).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli
from pkg_defender.db.schema import get_connection


def _add_event(
    conn: sqlite3.Connection,
    *,
    ecosystem: str = "npm",
    package_name: str = "test-pkg",
    action: str = "install",
    risk_level: str = "critical",
    source: str = "cli",
    manager: str = "npm",
    verdict: str = "FAIL",
    exit_code: int = 1,
    runtime_ms: int = 42,
    timestamp: str | None = None,
) -> None:
    """Insert a single audit event row with valid CHECK-constraint values."""

    ts = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    conn.execute(
        """INSERT INTO audit_events
        (timestamp, ecosystem, package_name, version, action, risk_level,
         source, manager, subcommand, verdict, exit_code, error_message,
         threat_count_general, threat_count_versioned, cooldown_pass,
         cooldown_days_remaining, ci_mode, runtime_ms, user, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ts,
            ecosystem,
            package_name,
            "1.0.0",
            action,
            risk_level,
            source,
            manager,
            "audit",
            verdict,
            exit_code,
            None,
            0,
            0,
            1,
            0,
            0,
            runtime_ms,
            "tester",
            "sess-001",
        ),
    )
    conn.commit()


# ============================================================================
# TestAuditLogsGroup
# ============================================================================


class TestAuditLogsGroup:
    """Basic group-level behaviour."""

    def test_audit_logs_help(self, runner: CliRunner) -> None:
        """``pkgd audit-logs --help`` shows subcommands."""
        result = runner.invoke(cli, ["audit-logs", "--help"])
        assert result.exit_code == 0
        assert "query" in result.output
        assert "stats" in result.output


# ============================================================================
# TestAuditLogsQuery
# ============================================================================


class TestAuditLogsQuery:
    """Tests for ``pkgd audit-logs query``."""

    def test_query_help(self, runner: CliRunner) -> None:
        """``pkgd audit-logs query --help`` shows options."""
        result = runner.invoke(cli, ["audit-logs", "query", "--help"])
        assert result.exit_code == 0
        assert "--ecosystem" in result.output
        assert "--limit" in result.output

    def test_query_no_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing database prints error and exits 1.

        Root cause: ``audit_logs.py`` lines 102-105 — when ``get_db_path()``
        returns a path that does not exist, the command prints an error and
        raises ``SystemExit(1)``. This test verifies that path.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.commands.audit_logs.get_db_path",
            lambda: tmp_path / "no_such_dir" / "threats.db",
        )
        result = runner.invoke(cli, ["audit-logs", "query"])
        assert result.exit_code == 1
        assert "Database not found" in result.output

    def test_query_empty_db(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Query with no matching events prints "No audit events found"."""
        result = runner.invoke(cli, ["audit-logs", "query"])
        assert result.exit_code == 0
        assert "No audit events found" in result.output

    def test_query_with_events(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Query returns table with event data."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, package_name="table-pkg")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query"])
        assert result.exit_code == 0
        assert "table-pkg" in result.output
        assert "npm" in result.output
        assert "FAIL" in result.output

    def test_query_limit(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--limit`` controls the number of events shown."""
        conn = get_connection(isolated_env["db_path"])
        for i in range(5):
            _add_event(conn, package_name=f"pkg-{i}")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--limit", "3"])
        assert result.exit_code == 0
        # Only 3 of 5 package names should appear
        assert "Total events: 3" in result.output

    def test_query_ecosystem_filter(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--ecosystem`` filters results."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, ecosystem="npm", package_name="npm-pkg")
        _add_event(conn, ecosystem="pypi", package_name="pypi-pkg")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--ecosystem", "npm"])
        assert result.exit_code == 0
        assert "npm-pkg" in result.output
        assert "pypi-pkg" not in result.output

    def test_query_package_filter(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--package`` filters results."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, package_name="lodash")
        _add_event(conn, package_name="react")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--package", "lodash"])
        assert result.exit_code == 0
        assert "lodash" in result.output
        assert "react" not in result.output

    def test_query_verdict_filter(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--verdict`` filters results."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, verdict="FAIL", package_name="failing")
        _add_event(conn, verdict="PASS", package_name="passing")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--verdict", "FAIL"])
        assert result.exit_code == 0
        assert "failing" in result.output
        assert "passing" not in result.output

    def test_query_source_filter(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--source`` filters results."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, source="cli", package_name="cli-pkg")
        _add_event(conn, source="cron", package_name="cron-pkg")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--source", "cli"])
        assert result.exit_code == 0
        assert "cli-pkg" in result.output
        assert "cron-pkg" not in result.output

    def test_query_since_valid(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--since`` filters to events after a datetime."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, timestamp="2025-01-01T00:00:00", package_name="old")
        _add_event(conn, timestamp="2026-06-01T00:00:00", package_name="new")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--since", "2026-01-01T00:00:00"])
        assert result.exit_code == 0
        assert "new" in result.output
        assert "old" not in result.output

    def test_query_until_valid(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--until`` filters to events before a datetime."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, timestamp="2025-01-01T00:00:00", package_name="old")
        _add_event(conn, timestamp="2026-06-01T00:00:00", package_name="new")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "query", "--until", "2026-01-01T00:00:00"])
        assert result.exit_code == 0
        assert "old" in result.output
        assert "new" not in result.output

    def test_query_since_with_z_suffix(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--since`` with trailing ``Z`` is parsed correctly.

        Root cause: ``audit_logs.py`` line 87 — the ``Z`` suffix is
        replaced with ``+00:00`` before ``fromisoformat`` is called.
        """
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, timestamp="2026-06-15T12:00:00", package_name="z-pkg")
        conn.close()

        result = runner.invoke(
            cli,
            ["audit-logs", "query", "--since", "2026-06-01T00:00:00Z"],
        )
        assert result.exit_code == 0
        assert "z-pkg" in result.output

    def test_query_invalid_since(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Invalid ``--since`` format prints error and exits 1.

        Root cause: ``audit_logs.py`` lines 86-91 — when
        ``datetime.fromisoformat`` raises ``ValueError``, the code prints
        an error message and exits with ``_EXIT_GENERAL_ERROR`` (1).
        """
        result = runner.invoke(cli, ["audit-logs", "query", "--since", "not-a-date"])
        assert result.exit_code == 1
        assert "Invalid --since format" in result.output

    def test_query_invalid_until(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Invalid ``--until`` format prints error and exits 1.

        Root cause: ``audit_logs.py`` lines 95-100 — same pattern as
        ``--since`` validation.
        """
        result = runner.invoke(cli, ["audit-logs", "query", "--until", "not-a-date"])
        assert result.exit_code == 1
        assert "Invalid --until format" in result.output


# ============================================================================
# TestAuditLogsStats
# ============================================================================


class TestAuditLogsStats:
    """Tests for ``pkgd audit-logs stats``."""

    def test_stats_help(self, runner: CliRunner) -> None:
        """``pkgd audit-logs stats --help`` shows options."""
        result = runner.invoke(cli, ["audit-logs", "stats", "--help"])
        assert result.exit_code == 0
        assert "--since" in result.output

    def test_stats_no_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing database prints error and exits 1.

        Root cause: ``audit_logs.py`` lines 198-201 — same DB-not-found
        check as query, in the ``stats`` command handler.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.commands.audit_logs.get_db_path",
            lambda: tmp_path / "no_such_dir" / "threats.db",
        )
        result = runner.invoke(cli, ["audit-logs", "stats"])
        assert result.exit_code == 1
        assert "Database not found" in result.output

    def test_stats_empty_db(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Stats with no events prints "No audit events found"."""
        result = runner.invoke(cli, ["audit-logs", "stats"])
        assert result.exit_code == 0
        assert "No audit events found" in result.output

    def test_stats_with_events(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Stats with events shows breakdown by verdict, ecosystem, source.

        Root cause: ``audit_logs.py`` lines 210-225 — the stats output
        iterates over ``by_verdict``, ``by_ecosystem``, and ``by_source``
        dicts and prints each item. This test exercises all three sections.
        """
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, ecosystem="npm", verdict="FAIL", source="cli")
        _add_event(conn, ecosystem="npm", verdict="FAIL", source="cron")
        _add_event(conn, ecosystem="pypi", verdict="PASS", source="cli")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "stats"])
        assert result.exit_code == 0
        assert "Total Audit Events: 3" in result.output
        assert "By Verdict:" in result.output
        assert "By Ecosystem:" in result.output
        assert "By Source:" in result.output

    def test_stats_since_valid(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--since`` filters stats events."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, timestamp="2025-01-01T00:00:00", package_name="old")
        _add_event(conn, timestamp="2026-06-01T00:00:00", package_name="new")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "stats", "--since", "2026-01-01T00:00:00"])
        assert result.exit_code == 0
        assert "Total Audit Events: 1" in result.output

    def test_stats_invalid_since(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Invalid ``--since`` format prints error and exits 1.

        Root cause: ``audit_logs.py`` lines 182-187 — same ValueError
        handling as the query command, in the stats handler.
        """
        result = runner.invoke(cli, ["audit-logs", "stats", "--since", "bad-date"])
        assert result.exit_code == 1
        assert "Invalid --since format" in result.output

    def test_stats_invalid_until(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Invalid ``--until`` format prints error and exits 1."""
        result = runner.invoke(cli, ["audit-logs", "stats", "--until", "bad-date"])
        assert result.exit_code == 1
        assert "Invalid --until format" in result.output

    def test_stats_until_valid(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """``--until`` filters stats events."""
        conn = get_connection(isolated_env["db_path"])
        _add_event(conn, timestamp="2025-01-01T00:00:00", package_name="old")
        _add_event(conn, timestamp="2026-06-01T00:00:00", package_name="new")
        conn.close()

        result = runner.invoke(cli, ["audit-logs", "stats", "--until", "2026-01-01T00:00:00"])
        assert result.exit_code == 0
        assert "Total Audit Events: 1" in result.output
