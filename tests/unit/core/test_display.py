"""Tests for pkg_defender.display module."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from rich.console import Console

from pkg_defender.display import (
    display_allowed,
    display_audit_results,
    display_both_block,
    display_cooldown_block,
    display_stale_db_warning,
    display_threat_block,
    format_json,
    humanize_timedelta,
    set_no_color,
    severity_color,
)
from pkg_defender.models import (
    AuditCooldownEntry,
    AuditThreatEntry,
    CooldownResult,
    PackageAuditResult,
    ScoredThreat,
    ThreatRecord,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_threat(
    severity: str = "HIGH",
    source: str = "osv",
    summary: str = "Test vulnerability",
    detail_url: str | None = "https://example.com/vuln/1",
    package_name: str = "test-pkg",
) -> ThreatRecord:
    """Create a minimal ThreatRecord for testing."""
    return ThreatRecord(
        id="test-id-1",
        ecosystem="npm",
        package_name=package_name,
        severity=severity,
        confidence=0.85,
        source=source,
        source_id="OSV-2024-001",
        summary=summary,
        detail_url=detail_url,
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 6, 1, tzinfo=UTC),
    )


def _make_scored_threat(
    severity: str = "HIGH",
    score: float = 0.85,
    match_type: str = "exact",
    summary: str = "Test vulnerability",
) -> ScoredThreat:
    """Create a ScoredThreat for testing."""
    record = _make_threat(severity=severity, summary=summary)
    return ScoredThreat(
        record=record,
        final_score=score,
        display_severity=severity,
        version_match_type=match_type,
    )


def _console_capture() -> Console:
    """Create a recording Console for output capture."""
    return Console(record=True, no_color=True, width=80)


# ---------------------------------------------------------------------------
# severity_color tests
# ---------------------------------------------------------------------------


class TestSeverityColor:
    def test_critical(self) -> None:
        assert severity_color("CRITICAL") == "bold red"

    def test_high(self) -> None:
        assert severity_color("HIGH") == "red"

    def test_medium(self) -> None:
        assert severity_color("MEDIUM") == "yellow"

    def test_low(self) -> None:
        assert severity_color("LOW") == "blue"

    def test_unknown(self) -> None:
        assert severity_color("UNKNOWN") == "dim"

    def test_unrecognized_returns_dim(self) -> None:
        assert severity_color("FOOBAR") == "dim"


# ---------------------------------------------------------------------------
# humanize_timedelta tests
# ---------------------------------------------------------------------------


class TestHumanizeTimedelta:
    def test_zero(self) -> None:
        assert humanize_timedelta(timedelta(0)) == "0 seconds"

    def test_negative(self) -> None:
        assert humanize_timedelta(timedelta(seconds=-10)) == "0 seconds"

    def test_seconds_only(self) -> None:
        assert humanize_timedelta(timedelta(seconds=45)) == "45 seconds"

    def test_minutes(self) -> None:
        assert humanize_timedelta(timedelta(minutes=30)) == "30 minutes"

    def test_one_minute(self) -> None:
        assert humanize_timedelta(timedelta(minutes=1)) == "1 minute"

    def test_hours(self) -> None:
        assert humanize_timedelta(timedelta(hours=2)) == "2 hours"

    def test_one_hour(self) -> None:
        assert humanize_timedelta(timedelta(hours=1)) == "1 hour"

    def test_days(self) -> None:
        assert humanize_timedelta(timedelta(days=3)) == "3 days"

    def test_one_day(self) -> None:
        assert humanize_timedelta(timedelta(days=1)) == "1 day"

    def test_compound(self) -> None:
        assert humanize_timedelta(timedelta(days=1, hours=3)) == "1 day 3 hours"

    def test_compound_with_minutes(self) -> None:
        assert humanize_timedelta(timedelta(days=1, hours=3, minutes=15)) == "1 day 3 hours 15 minutes"

    def test_sub_minute_nonzero_shows_seconds(self) -> None:
        assert humanize_timedelta(timedelta(seconds=30)) == "30 seconds"

    def test_minutes_and_seconds(self) -> None:
        # Minutes shown, seconds hidden when minutes > 0
        td = timedelta(minutes=5, seconds=30)
        result = humanize_timedelta(td)
        assert result == "5 minutes"


# ---------------------------------------------------------------------------
# display_cooldown_block tests
# ---------------------------------------------------------------------------


class TestDisplayCooldownBlock:
    def test_renders_without_error(self) -> None:
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            safe_version="1.13.0",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "axios@1.14.1" in output
        assert "2 hours" in output
        assert "22 hours" in output
        assert "1.13.0" in output
        assert "Cooldown Block" in output

    def test_renders_without_safe_version(self) -> None:
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=1),
            remaining=timedelta(hours=23),
            reason="too_new",
        )
        display_cooldown_block("pkg", "0.0.1", result, console=con)
        output = con.export_text()
        assert "pkg@0.0.1" in output
        assert "Safe version" not in output

    def test_bypass_hint_shown(self) -> None:
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=1),
            remaining=timedelta(hours=23),
            reason="too_new",
        )
        display_cooldown_block("pkg", "0.0.1", result, console=con)
        output = con.export_text()
        assert "--bypass" in output

    def test_registry_api_date_source_shows_verified_timestamp(self) -> None:
        """date_source='registry_api' should display as '(verified timestamp)'.

        Regression test for Bug 6 (display.py:257). Before fix, 'registry_api'
        was not in the condition, so it fell through to the else branch and
        showed '(no timestamp source)'.
        """
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="registry_api",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "verified timestamp" in output

    def test_registry_date_source_shows_claimed_timestamp(self) -> None:
        """date_source='registry' should display as '✗ claimed timestamp'."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="registry",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "claimed timestamp" in output

    def test_none_date_source_shows_no_timestamp(self) -> None:
        """date_source=None should display as '✗ no timestamp source'."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "no timestamp source" in output


class TestTrustDisplayIndicators:
    """Tests for trust level icons and penalty messages in display_cooldown_block."""

    @pytest.fixture(autouse=True)
    def _reset_ascii_mode(self) -> None:
        """Reset _ascii_mode global to False before each test to prevent cross-worker leaks."""
        from pkg_defender.display import _ascii_mode, set_ascii_mode

        if _ascii_mode:
            set_ascii_mode(False)

    def test_verified_shows_check_icon(self) -> None:
        """date_source='registry_api' shows '✓ verified timestamp'."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="registry_api",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "verified timestamp" in output

    def test_proxied_shows_warning_icon(self) -> None:
        """date_source='repodata' shows '⚠ proxied timestamp'."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="repodata",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "proxied timestamp" in output

    def test_claimed_shows_cross_icon(self) -> None:
        """date_source='registry' shows '✗ claimed timestamp'."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="registry",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "claimed timestamp" in output

    def test_penalty_message_shown_when_claimed_and_blocked(self) -> None:
        """trust='claimed', not allowed → penalty line visible."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=1,
            date_source="registry",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        assert "penalty applied" in output
        assert "claimed" in output.lower()

    def test_penalty_message_not_shown_when_claimed_and_allowed(self) -> None:
        """trust='claimed', allowed → no penalty line."""
        con = _console_capture()
        result = CooldownResult(
            allowed=True,
            age=timedelta(days=10),
            remaining=None,
            reason="ok",
            publish_time=datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
            effective_cooldown_days=7,
            date_source="registry",
        )
        display_cooldown_block("axios", "1.14.1", result, console=con)
        output = con.export_text()
        # Penalty line should not appear when allowed
        assert "penalty applied" not in output


# ---------------------------------------------------------------------------
# display_threat_block tests
# ---------------------------------------------------------------------------


class TestDisplayThreatBlock:
    def test_renders_single_threat(self) -> None:
        con = _console_capture()
        threats = [_make_scored_threat(severity="CRITICAL", score=0.95)]
        display_threat_block("event-stream", "3.3.6", threats, console=con)
        output = con.export_text()
        assert "event-stream@3.3.6" in output
        assert "CRITICAL" in output
        assert "Threat Block" in output

    def test_renders_multiple_threats(self) -> None:
        con = _console_capture()
        threats = [
            _make_scored_threat(severity="CRITICAL", score=0.95, summary="Backdoor"),
            _make_scored_threat(severity="MEDIUM", score=0.55, summary="ReDoS"),
        ]
        display_threat_block("vuln-pkg", "1.0.0", threats, console=con)
        output = con.export_text()
        assert "vuln-pkg@1.0.0" in output
        assert "CRITICAL" in output

    def test_bypass_hint_shown(self) -> None:
        con = _console_capture()
        threats = [_make_scored_threat()]
        display_threat_block("pkg", "1.0.0", threats, console=con)
        output = con.export_text()
        assert "--bypass" in output

    def test_returns_expected_output_when_url_has_trailing_parenthesis(self) -> None:
        """URLs with trailing ) display without breaking the output.

        Regression test: OSV URLs like https://osv.dev/vulnerability/GHSA-xxxx
        with trailing ) should not cause Rich markup parsing errors or display
        corruption. The URL may be truncated for display purposes but should
        appear without breaking the table rendering.
        """
        con = _console_capture()
        # OSV URL with trailing ) - using a short URL that won't be truncated
        # Rich Table truncates the Details column which has max_width=not set
        # So we check that the output is properly formed and no errors occur
        url_with_paren = "https://osv.dev/v/GHSA-12)"
        threats = [
            _make_scored_threat(
                severity="HIGH",
                summary="Test vulnerability with URL",
            )
        ]
        # Manually set the detail_url on the first threat's record
        threats[0].record.detail_url = url_with_paren
        # Should not raise any exceptions - this is the main regression test
        display_threat_block("test-pkg", "1.0.0", threats, console=con)
        output = con.export_text()
        # The URL should appear in output - check for part of the URL
        assert "osv.dev" in output
        # Verify the table was rendered successfully (no corruption)
        assert "Threat Block" in output

    def test_display_threat_block_renders_markup_literally(self) -> None:
        """Rich markup tags in threat fields are rendered literally, not interpreted."""
        con = _console_capture()
        rec = ThreatRecord(
            id="test-id-1",
            ecosystem="npm",
            package_name="test-pkg",
            source="[bold red]EVIL_SOURCE[/bold red]",
            summary="[italic]malicious summary[/italic]",
            detail_url="[link=evil]click here[/link]",
        )
        scored = ScoredThreat(
            record=rec,
            final_score=0.85,
            display_severity="HIGH",
            version_match_type="[green]exact[/green]",
        )
        display_threat_block("test-pkg", "1.0.0", [scored], console=con)
        output = con.export_text()
        # Verify literal markup, not rendered styling
        # Content is split across column-wrapped lines, so check individual tokens
        assert "[bold" in output
        assert "EVIL_SOURCE" in output
        assert "[italic" in output
        assert "[link=" in output
        assert "[green]" in output


# ---------------------------------------------------------------------------
# display_both_block tests
# ---------------------------------------------------------------------------


class TestDisplayBothBlock:
    def test_renders_combined_panel(self) -> None:
        con = _console_capture()
        cooldown = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
            safe_version="2.0.0",
        )
        threats = [_make_scored_threat(severity="HIGH", score=0.80)]
        display_both_block("bad-pkg", "3.0.0", cooldown, threats, console=con)
        output = con.export_text()
        assert "bad-pkg@3.0.0" in output
        assert "Threats" in output
        assert "Cooldown" in output
        assert "2.0.0" in output

    def test_shows_threat_details(self) -> None:
        con = _console_capture()
        cooldown = CooldownResult(
            allowed=False,
            age=timedelta(hours=1),
            remaining=timedelta(hours=23),
        )
        threats = [
            _make_scored_threat(severity="CRITICAL", summary="Supply chain attack"),
        ]
        display_both_block("pkg", "1.0.0", cooldown, threats, console=con)
        output = con.export_text()
        assert "Supply chain attack" in output


# ---------------------------------------------------------------------------
# display_allowed tests
# ---------------------------------------------------------------------------


class TestDisplayAllowed:
    def test_renders_green_panel(self) -> None:
        from pkg_defender import display

        # Ensure quiet_mode is reset to avoid test pollution from other tests
        display._quiet_mode = False
        try:
            con = _console_capture()
            display_allowed("lodash", "4.17.21", console=con, force_display=True)
            output = con.export_text()
            assert "lodash@4.17.21" in output
            assert "passed all checks" in output
            assert "Allowed" in output
        finally:
            display._quiet_mode = False


# ---------------------------------------------------------------------------
# display_stale_db_warning tests
# ---------------------------------------------------------------------------


class TestDisplayStaleDbWarning:
    def test_with_last_sync(self) -> None:
        con = _console_capture()
        last_sync = datetime.now(tz=UTC) - timedelta(hours=36)
        display_stale_db_warning(last_sync, console=con)
        output = con.export_text()
        assert "stale" in output
        # The panel may wrap text; check the key parts separately (strip ANSI for accurate check)
        plain = output.strip()
        assert "intel" in plain
        assert "sync" in plain
        assert "day" in output or "hour" in output

    def test_never_synced(self) -> None:
        con = _console_capture()
        display_stale_db_warning(None, console=con)
        output = con.export_text()
        assert "never synced" in output
        # The output wraps text across lines due to panel width
        plain = output.strip()
        assert "intel" in plain
        assert "sync" in plain


# ---------------------------------------------------------------------------
# display_audit_results tests
# ---------------------------------------------------------------------------


class TestDisplayAuditResults:
    def test_renders_audit_table(self) -> None:
        con = _console_capture()
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="package-lock.json",
            total_packages=10,
            threats=[
                AuditThreatEntry(
                    package="vuln-pkg",
                    version="1.0.0",
                    ecosystem="npm",
                    lock_file="package-lock.json",
                    threats=[_make_scored_threat(severity="HIGH")],
                ),
            ],
            cooldown_pending=[
                AuditCooldownEntry(
                    package="new-pkg",
                    version="0.1.0",
                    ecosystem="npm",
                    lock_file="package-lock.json",
                    age=timedelta(hours=4),
                    clears_at=datetime(2026, 4, 1, 16, 0, tzinfo=UTC),
                ),
            ],
            passed=8,
            scan_time=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        assert "vuln-pkg" in output
        assert "new-pkg" in output
        assert "8" in output
        assert "packages scanned" in output
        # Source column shows lock file path
        # Source column shows lock file path (may be truncated with …)
        assert "package-lock" in output
        # Cooldown clears_at time appears in Details
        assert "2026-04-01 16:00" in output

    def test_summary_footer_counts(self) -> None:
        con = _console_capture()
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="package-lock.json",
            total_packages=5,
            threats=[
                AuditThreatEntry(
                    package="a",
                    version="1",
                    ecosystem="npm",
                    threats=[_make_scored_threat()],
                ),
                AuditThreatEntry(
                    package="b",
                    version="2",
                    ecosystem="npm",
                    threats=[_make_scored_threat()],
                ),
            ],
            cooldown_pending=[
                AuditCooldownEntry(
                    package="c",
                    version="3",
                    ecosystem="npm",
                    age=timedelta(hours=1),
                    clears_at=datetime.now(tz=UTC),
                ),
            ],
            passed=2,
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        assert "5 packages scanned" in output
        assert "2 threats found" in output
        assert "1 cooldown pending" in output

    def test_empty_audit(self) -> None:
        con = _console_capture()
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="package-lock.json",
            total_packages=3,
            passed=3,
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        assert "3 packages scanned" in output
        assert "0 threats found" in output

    def test_audit_table_shows_source_column(self) -> None:
        """The Source column shows the lock file path."""
        con = _console_capture()
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="uv.lock",
            total_packages=1,
            threats=[
                AuditThreatEntry(
                    package="vuln-pkg",
                    version="1.0.0",
                    ecosystem="npm",
                    lock_file="uv.lock",
                    threats=[_make_scored_threat(severity="HIGH")],
                ),
            ],
            passed=0,
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        assert "uv.lock" in output

    def test_audit_table_details_shows_multiline_threat_info(self) -> None:
        """Details column shows multiline threat info with source badge, date, version match."""
        con = _console_capture()
        threat = _make_scored_threat(
            severity="CRITICAL",
            summary="Prototype pollution in lodash",
            match_type="exact",
        )
        # Set published_at so the "Reported:" date line appears in the details
        threat.record.published_at = datetime(2024, 1, 15, tzinfo=UTC)
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="package-lock.json",
            total_packages=1,
            threats=[
                AuditThreatEntry(
                    package="lodash",
                    version="4.17.21",
                    ecosystem="npm",
                    lock_file="package-lock.json",
                    threats=[threat],
                ),
            ],
            passed=0,
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        # Source badge (osv → [OSV])
        assert "[OSV]" in output
        # Version specificity (exact → v4.17.21)
        assert "v4.17.21" in output
        # Severity
        assert "CRITICAL" in output
        # Summary
        assert "Prototype pollution" in output
        # Published_at date appears in output
        assert "Reported:" in output
        assert "2024-01-15" in output

    def test_display_audit_results_renders_markup_literally(self) -> None:
        """Rich markup in audit results table is rendered literally."""
        con = _console_capture()
        rec = ThreatRecord(
            id="test-id-1",
            ecosystem="npm",
            package_name="vuln-pkg",
            source="osv",
            summary="Test vulnerability",
            severity="HIGH",
        )
        scored = ScoredThreat(
            record=rec,
            final_score=0.85,
            display_severity="HIGH",
            version_match_type="exact",
        )
        result = PackageAuditResult(
            project_path="/tmp/test",
            lock_file="package-lock.json",
            total_packages=2,
            threats=[
                AuditThreatEntry(
                    package="[bold]vuln-pkg[/bold]",
                    version="[italic]1.0.0[/italic]",
                    ecosystem="npm",
                    lock_file="package-lock.json",
                    threats=[scored],
                ),
            ],
            cooldown_pending=[
                AuditCooldownEntry(
                    package="[bold]new-pkg[/bold]",
                    version="[italic]0.1.0[/italic]",
                    ecosystem="npm",
                    lock_file="package-lock.json",
                    age=timedelta(hours=4),
                    clears_at=datetime(2026, 4, 1, 16, 0, tzinfo=UTC),
                ),
            ],
            passed=0,
        )
        display_audit_results(result, console=con)
        output = con.export_text()
        # Verify literal markup in threat package/version columns
        assert "[bold]vuln-p" in output
        assert "[italic]1.0" in output
        # Verify literal markup in cooldown package/version columns
        assert "[bold]new-pk" in output
        assert "[italic]0.1" in output


# ---------------------------------------------------------------------------
# Quiet mode tests
# ---------------------------------------------------------------------------


class TestQuietMode:
    """Quiet mode suppresses display outputs appropriately."""

    def test_display_stale_db_warning_suppressed_in_quiet_mode(self) -> None:
        """display_stale_db_warning should produce no output in quiet mode."""
        import pkg_defender.display as display_mod

        display_mod._quiet_mode = True
        try:
            con = _console_capture()
            display_stale_db_warning(None, console=con)
            output = con.export_text()
            assert output == "", f"Expected no output in quiet mode, got: {output}"
        finally:
            display_mod._quiet_mode = False

    def test_display_stale_db_warning_shows_normally(self) -> None:
        """display_stale_db_warning should produce output when not quiet."""
        import pkg_defender.display as display_mod

        display_mod._quiet_mode = False
        try:
            con = _console_capture()
            display_stale_db_warning(None, console=con)
            output = con.export_text()
            assert "stale" in output.lower() or "never" in output.lower()
        finally:
            display_mod._quiet_mode = False

    def test_display_allowed_already_suppressed(self) -> None:
        """display_allowed already suppresses in quiet mode -- regression guard."""
        import pkg_defender.display as display_mod

        display_mod._quiet_mode = True
        try:
            con = _console_capture()
            display_allowed("pkg", "1.0.0", console=con)
            output = con.export_text()
            assert output == ""
        finally:
            display_mod._quiet_mode = False

    def test_block_notifications_not_suppressed(self) -> None:
        """Block notifications must NOT be suppressed in quiet mode."""
        import pkg_defender.display as display_mod

        display_mod._quiet_mode = True
        try:
            con = _console_capture()
            cooldown = CooldownResult(
                allowed=False,
                age=timedelta(hours=1),
                remaining=timedelta(hours=23),
                reason="too_new",
            )
            display_cooldown_block("pkg", "1.0.0", cooldown, console=con)
            output = con.export_text()
            assert "pkg@1.0.0" in output
        finally:
            display_mod._quiet_mode = False


# ---------------------------------------------------------------------------
# Console instantiation regression tests
# ---------------------------------------------------------------------------


class TestConsoleInstantiation:
    """Regression tests for Rich Console instantiation.

    Bug: The linkify parameter was removed in rich v13+, causing TypeError
    when creating Console with linkify=False.

    Fix: Removed linkify=False from Console() calls in display.py.

    This test verifies Console can be instantiated from pkg_defender.display
    without errors. Before the fix, this would raise:
    TypeError: Console.__init__() got an unexpected keyword argument 'linkify'
    """

    def test_get_console_instantiation_without_linkify_error(self) -> None:
        """Regression test: Console creation should not raise linkify TypeError."""
        import pkg_defender.display as display_mod

        # Reset module-level console to force re-creation
        display_mod._console = None

        # This should not raise TypeError about 'linkify' parameter
        console = display_mod._get_console()

        # Verify console was created successfully
        assert console is not None
        assert isinstance(console, Console)

        # Clean up
        display_mod._console = None

    def test_set_no_color_instantiation_without_linkify_error(self) -> None:
        """Regression test: set_no_color should not raise linkify TypeError."""
        import pkg_defender.display as display_mod

        # Reset module-level console
        display_mod._console = None

        # This should not raise TypeError about 'linkify' parameter
        display_mod.set_no_color()

        # Verify console was created successfully with no_color=True
        assert display_mod._console is not None
        assert display_mod._console.no_color is True

        # Clean up
        display_mod._console = None

    def test_module_import_does_not_raise_linkify_error(self) -> None:
        """Regression test: importing display module should not raise linkify error.

        This tests that the module-level Console instantiation (if any) doesn't
        fail on import.
        """
        # Re-import the module to ensure it's fully loadable
        import importlib

        import pkg_defender.display as display_mod

        # Force re-import to catch any module-level instantiation issues
        importlib.reload(display_mod)

        # Module should be importable without errors
        assert display_mod is not None

        # Clean up
        display_mod._console = None


class TestNoColor:
    def test_set_no_color_creates_console(self) -> None:
        set_no_color()
        from pkg_defender.display import _console

        assert _console is not None
        assert _console.no_color is True

    def test_env_no_color_respected(self) -> None:
        """When NO_COLOR env var is set, new console should be no_color."""
        import pkg_defender.display as display_mod

        # Reset module-level console
        display_mod._console = None
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            con = display_mod._get_console()
            assert con.no_color is True

        # Clean up
        display_mod._console = None

    def test_no_color_env_renders_without_ansi(self) -> None:
        """Output with NO_COLOR should have no ANSI escape codes."""
        import pkg_defender.display as display_mod

        display_mod._console = None
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            con = Console(record=True, no_color=True, width=80)
            display_allowed("test-pkg", "1.0.0", console=con, force_display=True)
            output = con.export_text()
            # Rich export_text with no_color should not contain escape sequences
            assert "\x1b[" not in output

        display_mod._console = None


# ---------------------------------------------------------------------------
# format_json tests
# ---------------------------------------------------------------------------


class TestFormatJsonOutput:
    def test_format_json_compact(self) -> None:
        """Test compact output when pretty=False."""
        data = {"package": "lodash", "version": "4.17.21", "blocked": False}
        result = format_json(data, pretty=False)
        # Compact JSON should have no newlines except at the end
        assert "\n" not in result.strip()
        # Should end with trailing newline
        assert result.endswith("\n")
        # Should be valid JSON when parsed
        parsed = json.loads(result)
        assert parsed == data

    def test_format_json_pretty(self) -> None:
        """Test indented output when pretty=True."""
        data = {"package": "lodash", "version": "4.17.21", "blocked": False}
        result = format_json(data, pretty=True)
        # Pretty JSON should contain newlines and indentation
        assert "\n" in result
        # Should end with trailing newline
        assert result.endswith("\n")
        # Should have 2-space indentation (default)
        assert "  " in result
        # Should be valid JSON when parsed
        parsed = json.loads(result)
        assert parsed == data

    def test_format_json_various_data(self) -> None:
        """Test format_json with different data structures."""
        # Test with dict
        dict_data = {"key": "value", "count": 42}
        compact_dict = format_json(dict_data, pretty=False)
        pretty_dict = format_json(dict_data, pretty=True)
        assert json.loads(compact_dict) == dict_data
        assert json.loads(pretty_dict) == dict_data

        # Test with list
        list_data = ["apple", "banana", "cherry"]
        compact_list = format_json(list_data, pretty=False)
        pretty_list = format_json(list_data, pretty=True)
        assert json.loads(compact_list) == list_data
        assert json.loads(pretty_list) == list_data

        # Test with nested structures
        nested_data = {
            "package": "test-pkg",
            "versions": ["1.0.0", "1.1.0"],
            "metadata": {
                "author": "Test Author",
                "license": "MIT",
            },
        }
        compact_nested = format_json(nested_data, pretty=False)
        pretty_nested = format_json(nested_data, pretty=True)
        assert json.loads(compact_nested) == nested_data
        assert json.loads(pretty_nested) == nested_data

    def test_format_json_compact_no_extra_whitespace(self) -> None:
        """Compact JSON should not contain any extra whitespace."""
        data = {"a": 1, "b": 2, "c": 3}
        result = format_json(data, pretty=False)
        # Should be exactly: {"a": 1, "b": 2, "c": 3}
        assert result == '{"a": 1, "b": 2, "c": 3}\n'

    def test_format_json_pretty_has_indentation(self) -> None:
        """Pretty JSON should have proper indentation structure."""
        data = {
            "outer": {
                "inner": "value",
            },
        }
        result = format_json(data, pretty=True)
        lines = result.split("\n")
        # Should have multiple lines due to indentation
        assert len(lines) > 1
        # First line should start with opening brace
        assert lines[0].startswith("{")
        # Last line should be closing brace
        assert lines[-2].strip() == "}"

    def test_format_json_empty_dict(self) -> None:
        """Test format_json with empty dict."""
        result = format_json({}, pretty=False)
        assert result == "{}\n"
        assert json.loads(result) == {}

        pretty_result = format_json({}, pretty=True)
        assert pretty_result.endswith("\n")
        assert json.loads(pretty_result) == {}

    def test_format_json_empty_list(self) -> None:
        """Test format_json with empty list."""
        result = format_json([], pretty=False)
        assert result == "[]\n"
        assert json.loads(result) == []

        pretty_result = format_json([], pretty=True)
        assert pretty_result.endswith("\n")
        assert json.loads(pretty_result) == []

    def test_format_json_none(self) -> None:
        """Test format_json with None."""
        result = format_json(None, pretty=False)
        assert result == "null\n"
        assert json.loads(result) is None

        pretty_result = format_json(None, pretty=True)
        assert pretty_result.endswith("\n")
        assert json.loads(pretty_result) is None

    def test_format_json_primitive_types(self) -> None:
        """Test format_json with primitive types."""
        # string
        result = format_json("hello", pretty=False)
        assert result == '"hello"\n'
        assert json.loads(result) == "hello"

        # number
        result = format_json(42, pretty=False)
        assert result == "42\n"
        assert json.loads(result) == 42

        # boolean
        result = format_json(True, pretty=False)
        assert result == "true\n"
        assert json.loads(result) is True

    def test_format_json_trailing_newline_always_present(self) -> None:
        """Regression: every format_json result must end with trailing newline.

        Root cause: src/pkg_defender/display.py:874-876 —
        prior to Item 11, ``format_json_output()`` did not append ``\\n``.
        All 14 call sites were updated to ``format_json(...)`` and changed
        from ``click.echo(result)`` to ``click.echo(result, nl=False)``.
        This test verifies the function contract: trailing newline is
        ALWAYS present regardless of data or pretty mode.
        """
        cases: list[Any] = [
            {"a": 1},
            [],
            [1, 2, 3],
            {"nested": {"deep": True}},
            None,
            "plain string",
            0,
            False,
        ]
        for data in cases:
            compact = format_json(data, pretty=False)
            assert compact.endswith("\n"), f"compact missing \\n for {data!r}"
            pretty = format_json(data, pretty=True)
            assert pretty.endswith("\n"), f"pretty missing \\n for {data!r}"


# ---------------------------------------------------------------------------
# Verbose mode tests
# ---------------------------------------------------------------------------


class TestVerboseMode:
    """Tests for verbose mode functions."""

    def test_set_verbose_mode_sets_flag(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_verbose_mode()

        try:
            display_mod.set_verbose_mode(True)
            assert display_mod.is_verbose_mode() is True

            display_mod.set_verbose_mode(False)
            assert display_mod.is_verbose_mode() is False
        finally:
            # Restore original state
            display_mod.set_verbose_mode(original)

    def test_set_verbose_mode_default_false(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_verbose_mode()

        try:
            # Module should default to False
            display_mod.set_verbose_mode(False)
            assert display_mod.is_verbose_mode() is False
        finally:
            # Restore original state
            display_mod.set_verbose_mode(original)

    def test_is_verbose_mode_reflects_set_value(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_verbose_mode()

        try:
            display_mod.set_verbose_mode(True)
            assert display_mod.is_verbose_mode() is True

            display_mod.set_verbose_mode(False)
            assert display_mod.is_verbose_mode() is False
        finally:
            # Restore original state
            display_mod.set_verbose_mode(original)


# ---------------------------------------------------------------------------
# ASCII mode tests
# ---------------------------------------------------------------------------


class TestAsciiMode:
    """Tests for ASCII mode functions."""

    def test_set_ascii_mode_sets_flag(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_ascii_mode()

        try:
            display_mod.set_ascii_mode(True)
            assert display_mod.is_ascii_mode() is True

            display_mod.set_ascii_mode(False)
            assert display_mod.is_ascii_mode() is False
        finally:
            # Restore original state
            display_mod.set_ascii_mode(original)

    def test_set_ascii_mode_default_false(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_ascii_mode()

        try:
            # Module should default to False
            display_mod.set_ascii_mode(False)
            assert display_mod.is_ascii_mode() is False
        finally:
            # Restore original state
            display_mod.set_ascii_mode(original)

    def test_is_ascii_mode_reflects_set_value(self) -> None:
        import pkg_defender.display as display_mod

        # Save original state
        original = display_mod.is_ascii_mode()

        try:
            display_mod.set_ascii_mode(True)
            assert display_mod.is_ascii_mode() is True

            display_mod.set_ascii_mode(False)
            assert display_mod.is_ascii_mode() is False
        finally:
            # Restore original state
            display_mod.set_ascii_mode(original)

    def test_severity_icon_returns_unicode_by_default(self) -> None:
        """When ASCII mode is disabled, should return Unicode emojis."""
        import pkg_defender.display as display_mod

        # Save original state and ensure ASCII mode is off
        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(False)

            result = display_mod._severity_icon("CRITICAL")
            assert result == "\U0001f6a8"  # 🚨

            result = display_mod._severity_icon("HIGH")
            assert result == "\u26a0"  # ⚠
        finally:
            display_mod.set_ascii_mode(original)

    def test_severity_icon_returns_ascii_when_enabled(self) -> None:
        """When ASCII mode is enabled, should return text icons."""
        import pkg_defender.display as display_mod

        # Save original state and ensure ASCII mode is on
        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(True)

            result = display_mod._severity_icon("CRITICAL")
            assert result == "[!!!!]"

            result = display_mod._severity_icon("HIGH")
            assert result == "[!!!]"

            result = display_mod._severity_icon("MEDIUM")
            assert result == "[!!]"

            result = display_mod._severity_icon("LOW")
            assert result == "[!]"

            result = display_mod._severity_icon("UNKNOWN")
            assert result == "[?]"
        finally:
            display_mod.set_ascii_mode(original)


# ---------------------------------------------------------------------------
# create_table tests
# ---------------------------------------------------------------------------


class TestCreateTable:
    """Tests for create_table() helper that applies ASCII borders."""

    def test_create_table_default_no_ascii(self) -> None:
        """Default mode (no --ascii) should use Rich's default box style."""
        from rich.box import HEAVY_HEAD

        import pkg_defender.display as display_mod

        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(False)
            table = display_mod.create_table("Test")
            assert table.box == HEAVY_HEAD
        finally:
            display_mod.set_ascii_mode(original)

    def test_create_table_ascii_mode_injects_ascii_box(self) -> None:
        """ASCII mode should inject box.ASCII when no explicit box=."""
        from rich.box import ASCII

        import pkg_defender.display as display_mod

        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(True)
            table = display_mod.create_table("Test")
            assert table.box is not None
            assert table.box == ASCII
        finally:
            display_mod.set_ascii_mode(original)

    def test_create_table_preserves_explicit_box_none(self) -> None:
        """ASCII mode should NOT override explicit box=None."""
        import pkg_defender.display as display_mod

        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(True)
            table = display_mod.create_table("Test", box=None)
            assert table.box is None
        finally:
            display_mod.set_ascii_mode(original)

    def test_create_table_preserves_explicit_box_choice(self) -> None:
        """ASCII mode should NOT override an explicit box= choice."""
        from rich.box import DOUBLE

        import pkg_defender.display as display_mod

        original = display_mod.is_ascii_mode()
        try:
            display_mod.set_ascii_mode(True)
            table = display_mod.create_table("Test", box=DOUBLE)
            assert table.box == DOUBLE
        finally:
            display_mod.set_ascii_mode(original)

    def test_create_table_returns_table_instance(self) -> None:
        """create_table should return a Table instance."""
        from rich.table import Table

        import pkg_defender.display as display_mod

        table = display_mod.create_table("Test")
        assert isinstance(table, Table)


# ---------------------------------------------------------------------------
# DS-001: display._check_single_condition regression tests
# ---------------------------------------------------------------------------


def test_display_check_single_condition_clean() -> None:
    """Verify the display.py copy also works correctly with clean conditions."""
    from pkg_defender.version import _check_single_condition

    assert _check_single_condition("1.2.0", ">=1.0.0") is True
    assert _check_single_condition("1.2.0", "[SEMVER] >=1.0.0") is False


# ── Resolver warning display tests ───────────────────────────────────


class TestDisplayResolverWarning:
    """Tests for ``display_resolver_warning()``."""

    def test_output_with_rate_limited(self) -> None:
        """Errors containing ``rate_limited`` renders a panel with the correct message."""
        from pkg_defender.display import display_resolver_warning

        console = Console(record=True, no_color=True, width=80)
        display_resolver_warning({"rate_limited"}, console=console)

        output = console.export_text()
        assert "Timestamp Resolution Notice" in output
        assert "PKGD_GITHUB_TOKEN" in output
        assert "github.com/settings/tokens" in output

    def test_empty_errors_no_output(self) -> None:
        """Empty errors set produces no output."""
        from pkg_defender.display import display_resolver_warning

        console = Console(record=True, no_color=True, width=80)
        display_resolver_warning(set(), console=console)

        output = console.export_text()
        assert output == ""

    def test_quiet_mode_suppresses_output(self) -> None:
        """Quiet mode suppresses the warning panel."""
        from pkg_defender.display import display_resolver_warning, set_quiet_mode

        set_quiet_mode(True)
        try:
            console = Console(record=True, no_color=True, width=80)
            display_resolver_warning({"rate_limited"}, console=console)

            output = console.export_text()
            assert output == ""
        finally:
            set_quiet_mode(False)

    def test_unknown_error_code_skipped_gracefully(self) -> None:
        """An unknown error code not in ``RESOLVER_ERROR_MESSAGES`` is silently skipped."""
        from pkg_defender.display import display_resolver_warning

        console = Console(record=True, no_color=True, width=80)
        display_resolver_warning({"unknown_code"}, console=console)

        output = console.export_text()
        assert output == ""

    def test_console_param_is_used(self) -> None:
        """A custom console is used when passed explicitly."""
        from pkg_defender.display import display_resolver_warning

        custom_console = Console(record=True, no_color=True, width=80)
        display_resolver_warning({"rate_limited"}, console=custom_console)

        output = custom_console.export_text()
        assert "PKGD_GITHUB_TOKEN" in output
