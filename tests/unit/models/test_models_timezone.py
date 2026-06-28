"""Regression tests for P0.1: timezone-naive datetime defaults.

Ensures all dataclass fields with datetime default factories produce
timezone-aware (UTC) datetimes, preventing TypeError when these values
are compared or subtracted with datetime.now(UTC) elsewhere in the codebase.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pkg_defender.models.models import AuditCooldownEntry, PackageAuditResult, ThreatRecord


class TestTimezoneAwareDefaults:
    """Every datetime default_factory must produce UTC-aware datetimes."""

    def test_threat_record_first_seen_is_utc(self) -> None:
        """ThreatRecord().first_seen is UTC-aware."""
        record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")
        assert record.first_seen.tzinfo is not None
        assert record.first_seen.tzinfo == UTC
        # Comparison with UTC datetime must not raise TypeError
        _ = record.first_seen >= datetime.now(UTC)

    def test_threat_record_last_seen_is_utc(self) -> None:
        """ThreatRecord().last_seen is UTC-aware."""
        record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")
        assert record.last_seen.tzinfo is not None
        assert record.last_seen.tzinfo == UTC
        _ = record.last_seen >= datetime.now(UTC)

    def test_threat_record_ingested_at_is_utc(self) -> None:
        """ThreatRecord().ingested_at is UTC-aware."""
        record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")
        assert record.ingested_at.tzinfo is not None
        assert record.ingested_at.tzinfo == UTC

    def test_audit_cooldown_entry_clears_at_is_utc(self) -> None:
        """AuditCooldownEntry().clears_at is UTC-aware."""
        entry = AuditCooldownEntry(package="test", version="1.0.0", ecosystem="pypi")
        assert entry.clears_at.tzinfo is not None
        assert entry.clears_at.tzinfo == UTC
        # Comparison with UTC datetime must not raise TypeError
        _ = entry.clears_at >= datetime.now(UTC)

    def test_audit_result_scan_time_is_utc(self) -> None:
        """PackageAuditResult().scan_time is UTC-aware."""
        result = PackageAuditResult(project_path="/tmp", lock_file="test.lock", total_packages=1)
        assert result.scan_time.tzinfo is not None
        assert result.scan_time.tzinfo == UTC
        # Comparison with UTC datetime must not raise TypeError
        _ = result.scan_time >= datetime.now(UTC)

    def test_mixed_comparison_no_type_error(self) -> None:
        """Default values can be compared with datetime.now(UTC) without TypeError.

        This is the actual crash scenario: naive default vs aware codebase.
        """
        record = ThreatRecord(id="test", ecosystem="pypi", package_name="test-pkg")
        now = datetime.now(UTC)
        # Subtraction — the exact operation that raises TypeError
        age = now - record.first_seen
        assert age.total_seconds() >= 0
