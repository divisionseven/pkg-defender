"""Targeted unit tests for the audit command (pkg_defender/cli/commands/audit.py).

Covers CSV output, DB staleness detection, deep mode progress context,
and fail-on-threat branch coverage — gaps identified by coverage analysis.

Each test uses mock.patch on module-level imports of audit.py
(pkg_defender.cli.commands.audit.<symbol>) and invokes via CliRunner.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_THREAT_DETECTED as _EXIT_THREAT_DETECTED
from pkg_defender.cli.main import cli

pytestmark = pytest.mark.unit


# ============================================================================
# TestAuditCsvOutput (5 tests)
# ============================================================================


class TestAuditCsvOutput:
    """CSV output format tests for ``pkgd audit --output csv``.

    All tests mock ``audit_lock_file``, ``get_feed_state``, and
    ``display_stale_db_warning`` to isolate from real DB/filesystem,
    then assert on the CSV content rendered via ``click.echo``.
    """

    def test_csv_output_header_row(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CSV output with empty audit result produces only the header row.

        Verifies the header columns are ``["package", "version", "ecosystem",
        "lock_file", "severity", "source", "published_at", "version_match_type",
        "summary"]`` and that exactly one row (header only) is emitted when
        there are no threats and no cooldown entries.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.cooldown.strict_mode = False

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "csv"])

        assert result.exit_code == 0
        expected_header = "package,version,ecosystem,lock_file,severity,source,published_at,version_match_type,summary"
        assert result.output.startswith(expected_header)

        parsed = list(csv.reader(io.StringIO(result.output)))
        assert parsed[0] == [
            "package",
            "version",
            "ecosystem",
            "lock_file",
            "severity",
            "source",
            "published_at",
            "version_match_type",
            "summary",
        ]
        assert len(parsed) == 1  # Header only, no data rows

    def test_csv_output_includes_threat_data(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CSV output includes threat rows with correct field values.

        Creates a single threat entry (axios@1.6.0, HIGH severity) and
        verifies that the CSV row contains the expected package, version,
        ecosystem, lock_file, severity, source, published_at,
        version_match_type, and summary values in order.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.cooldown.strict_mode = False

        mock_threat = mock.MagicMock()
        mock_threat.display_severity = "HIGH"
        mock_threat.record.summary = "Test threat summary"
        mock_threat.record.source = "osv"
        mock_threat.record.published_at = None
        mock_threat.record.source_id = "OSV-2024-001"
        mock_threat.record.detail_url = None
        mock_threat.version_match_type = "exact"

        mock_entry = mock.MagicMock()
        mock_entry.package = "axios"
        mock_entry.version = "1.6.0"
        mock_entry.ecosystem = "npm"
        mock_entry.lock_file = "package-lock.json"
        mock_entry.threats = [mock_threat]

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = [mock_entry]
        mock_audit_result.cooldown_pending = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "csv"])

        assert result.exit_code == 0

        parsed = list(csv.reader(io.StringIO(result.output)))
        assert len(parsed) == 2  # Header + 1 threat
        assert parsed[1] == [
            "axios",
            "1.6.0",
            "npm",
            "package-lock.json",
            "HIGH",
            "osv",
            "",
            "exact",
            "Test threat summary",
        ]

    def test_csv_output_includes_cooldown_data(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CSV output includes cooldown-pending rows with ``COOLDOWN`` severity.

        The cooldown entry writes before the unconditional exit-4 check at
        line 288 (``if cooldown_count > 0: should_exit = True``), so
        CliRunner captures the full CSV content. The test asserts both the
        CSV content and the expected exit code (4).
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.cooldown.strict_mode = False

        mock_cooldown_entry = mock.MagicMock()
        mock_cooldown_entry.package = "new-pkg"
        mock_cooldown_entry.version = "2.0.0"
        mock_cooldown_entry.ecosystem = "pypi"
        mock_cooldown_entry.lock_file = "requirements.txt"
        mock_cooldown_entry.clears_at = datetime(2026, 7, 1, tzinfo=UTC)

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = [mock_cooldown_entry]

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "csv"])

        # Unconditional cooldown exit — CSV is written before this check
        assert result.exit_code == _EXIT_THREAT_DETECTED

        parsed = list(csv.reader(io.StringIO(result.output)))
        assert len(parsed) == 2  # Header + 1 cooldown
        assert parsed[1] == [
            "new-pkg",
            "2.0.0",
            "pypi",
            "requirements.txt",
            "COOLDOWN",
            "cooldown",
            "",
            "",
            "clears at 2026-07-01T00:00:00+00:00",
        ]

    def test_csv_output_empty_audit_produces_valid_csv(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CSV with no threats and no cooldown produces valid parseable CSV.

        ``buf.getvalue().strip()`` must produce non-empty output
        containing at least the header row. The test verifies that parsing
        with ``csv.reader`` succeeds and yields exactly one row.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.cooldown.strict_mode = False

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "csv"])

        assert result.exit_code == 0
        assert result.output, "CSV output must not be empty"

        parsed = list(csv.reader(io.StringIO(result.output)))
        assert len(parsed) == 1  # Header only
        assert parsed[0] == [
            "package",
            "version",
            "ecosystem",
            "lock_file",
            "severity",
            "source",
            "published_at",
            "version_match_type",
            "summary",
        ]

    def test_csv_output_special_characters_in_summary(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """CSV correctly escapes commas and quotes in the summary field.

        The summary ``"critical"`` contains both commas and double-quote
        characters. ``csv.writer`` must quote the field and escape internal
        quotes. The test verifies that ``csv.reader`` parses it back correctly
        and that ``[:80]`` truncation is applied.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.cooldown.strict_mode = False

        mock_threat = mock.MagicMock()
        mock_threat.display_severity = "MEDIUM"
        mock_threat.record.source = "osv"
        mock_threat.record.summary = (
            'Vulnerability CVE-2024-1234: allows code execution, remote attack, "critical" impact'
        )
        mock_threat.record.published_at = None
        mock_threat.record.source_id = "OSV-2024-001"
        mock_threat.record.detail_url = None
        mock_threat.version_match_type = "exact"

        mock_entry = mock.MagicMock()
        mock_entry.package = "axios"
        mock_entry.version = "1.6.0"
        mock_entry.ecosystem = "npm"
        mock_entry.lock_file = "package-lock.json"
        mock_entry.threats = [mock_threat]

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = [mock_entry]
        mock_audit_result.cooldown_pending = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "csv"])

        assert result.exit_code == 0

        parsed = list(csv.reader(io.StringIO(result.output)))
        assert len(parsed) == 2  # Header + 1 threat

        summary_field = parsed[1][8]
        assert len(summary_field) <= 80, "summary[:80] truncation must apply"
        assert summary_field == mock_threat.record.summary[:80]


# ============================================================================
# TestAuditDbStaleness (4 tests)
# ============================================================================


class TestAuditDbStaleness:
    """DB staleness detection tests for ``pkgd audit``.

    Each test mocks ``get_feed_state`` to control the ``last_sync`` value
    and verifies that ``display_stale_db_warning`` is called (or not called)
    with the correct argument. The config is mocked with
    ``staleness_threshold_hours=0`` so that ANY positive age triggers the
    stale warning, making the test deterministic.
    """

    def test_stale_db_warning_called_when_osv_feed_stale(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``display_stale_db_warning`` is called with parsed ``last_sync`` when feed is stale.

        Mocks ``get_feed_state`` to return a naive ISO datetime string
        (``2020-01-01T00:00:00``), which triggers the ``tzinfo is None``
        code path at line 141-142 (``replace(tzinfo=UTC)``). The assertion
        verifies that ``display_stale_db_warning`` receives the timezone-aware
        replacement datetime.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.feeds = mock.MagicMock(staleness_threshold_hours=0)
        mock_config.cooldown = mock.MagicMock(strict_mode=False)

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.get_feed_state",
                return_value={"last_sync": "2020-01-01T00:00:00"},
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.display_stale_db_warning",
            ) as mock_display_warning,
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_display_warning.assert_called_once_with(datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC))

    def test_stale_db_warning_called_with_none_when_last_sync_missing(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``display_stale_db_warning(None)`` is called when ``last_sync`` key is ``None``.

        When ``_state.get("last_sync")`` returns ``None``, the code takes
        the ``else`` branch at line 148-149 and calls
        ``display_stale_db_warning(None)``.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.feeds = mock.MagicMock(staleness_threshold_hours=0)
        mock_config.cooldown = mock.MagicMock(strict_mode=False)

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.get_feed_state",
                return_value={"feed_name": "osv", "last_sync": None},
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.display_stale_db_warning",
            ) as mock_display_warning,
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_display_warning.assert_called_once_with(None)

    def test_stale_db_warning_called_with_none_when_state_is_none(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``display_stale_db_warning(None)`` is called when ``get_feed_state`` returns ``None``.

        When ``_state`` is falsy (``None``), the ``else`` branch at line
        150-151 calls ``display_stale_db_warning(None)``.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.feeds = mock.MagicMock(staleness_threshold_hours=0)
        mock_config.cooldown = mock.MagicMock(strict_mode=False)

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.get_feed_state",
                return_value=None,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.display_stale_db_warning",
            ) as mock_display_warning,
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_display_warning.assert_called_once_with(None)

    def test_no_stale_db_warning_when_feed_recent(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """No stale warning is shown when ``last_sync`` is within the threshold.

        The feed was synced 30 seconds ago, well within the 8-hour threshold.
        ``display_stale_db_warning`` must NOT be called (the comparison at
        line 144 evaluates to ``False``).
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = False
        mock_config.feeds = mock.MagicMock(staleness_threshold_hours=8)
        mock_config.cooldown = mock.MagicMock(strict_mode=False)

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        recent_sync = (datetime.now(UTC) - timedelta(seconds=30)).isoformat()

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.get_feed_state",
                return_value={"last_sync": recent_sync},
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.display_stale_db_warning",
            ) as mock_display_warning,
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_display_warning.assert_not_called()


# ============================================================================
# TestAuditDeepModeProgress (1 test)
# ============================================================================


class TestAuditDeepModeProgress:
    """Deep mode progress context tests for ``pkgd audit --deep``.

    Verifies that ``progress_context`` is entered with the correct
    description string when ``--deep`` is used and ``should_show_progress()``
    returns ``True``.
    """

    def test_deep_mode_enters_progress_context(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``progress_context`` is entered with ``"Scanning packages (deep mode)..."``.

        Mocks ``should_show_progress`` to return ``True`` and
        ``progress_context`` to a ``MagicMock``. Asserts that
        ``progress_context`` was called with the correct description and
        that ``audit_lock_file`` was called (proving execution continued
        through the context manager).
        """
        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = []
        mock_audit_result.cooldown_pending = []
        mock_audit_result.total_packages = 0
        mock_audit_result.passed_packages = []

        with (
            mock.patch(
                "pkg_defender.cli.commands.audit.should_show_progress",
                return_value=True,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit.progress_context",
            ) as mock_progress,
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ) as mock_audit,
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--deep"])

        assert result.exit_code == 0
        mock_progress.assert_called_once_with("Scanning packages (deep mode)...")
        mock_audit.assert_called_once()


# ============================================================================
# TestAuditFailOnThreatBranch (1 test)
# ============================================================================


class TestAuditFailOnThreatBranch:
    """Fail-on-threat branch tests for ``pkgd audit``.

    Verifies the negative branch of the blocking-threat check (lines
    282-287): when ``fail_on_threat`` is True but threats have only LOW
    severity (not CRITICAL or HIGH), the exit is NOT triggered.
    """

    def test_fail_on_threat_with_non_blocking_severity_does_not_exit_4(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """LOW-severity threats do NOT trigger exit 4 when ``fail_on_threat`` is enabled.

        ``fail_on_threat_enabled=True`` enters the ``if fail_on_threat:``
        block, but ``display_severity="LOW"`` means
        ``has_blocking_threat`` is ``False``, so ``should_exit`` remains
        ``False`` and the command exits 0.
        """
        mock_config = mock.MagicMock()
        mock_config.fail_on_threat_enabled = True
        mock_config.cooldown.strict_mode = False

        mock_threat = mock.MagicMock()
        mock_threat.display_severity = "LOW"
        mock_threat.record.summary = "Non-blocking test threat"
        mock_threat.record.source = "test"

        mock_entry = mock.MagicMock()
        mock_entry.package = "axios"
        mock_entry.version = "1.6.0"
        mock_entry.ecosystem = "npm"
        mock_entry.threats = [mock_threat]

        mock_audit_result = mock.MagicMock()
        mock_audit_result.threats = [mock_entry]
        mock_audit_result.cooldown_pending = []

        with (
            mock.patch(
                "pkg_defender.core.auditor.audit_lock_file",
                return_value=mock_audit_result,
            ),
            mock.patch(
                "pkg_defender.cli.commands.audit._get_config_from_context",
                return_value=mock_config,
            ),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        assert result.exit_code != _EXIT_THREAT_DETECTED
