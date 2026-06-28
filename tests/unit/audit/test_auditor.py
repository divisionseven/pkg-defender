"""Tests for the lock file auditor."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from pkg_defender.config.settings import CooldownConfig, PKGDConfig
from pkg_defender.core.auditor import _check_cooldown_for_audit, audit_lock_file
from pkg_defender.db.schema import (
    get_version_timestamp,
    insert_threat,
    insert_version_timestamp,
)
from pkg_defender.models import ThreatRecord, VersionInfo

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "lock_files"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def project_with_lock(tmp_path: Path) -> Path:
    """Create a project directory with a package-lock.json (v3)."""
    import shutil

    src = FIXTURES_DIR / "package-lock-v3.json"
    dst = tmp_path / "package-lock.json"
    shutil.copy(src, dst)
    return tmp_path


@pytest.fixture()
def project_with_poetry_lock(tmp_path: Path) -> Path:
    """Create a project directory with a poetry.lock."""
    import shutil

    src = FIXTURES_DIR / "poetry.lock"
    dst = tmp_path / "poetry.lock"
    shutil.copy(src, dst)
    return tmp_path


@pytest.fixture()
def project_with_requirements(tmp_path: Path) -> Path:
    """Create a project directory with a requirements.txt."""
    import shutil

    src = FIXTURES_DIR / "requirements.txt"
    dst = tmp_path / "requirements.txt"
    shutil.copy(src, dst)
    return tmp_path


def _make_threat(
    *,
    id: str = "osv:TEST-001",
    ecosystem: str = "npm",
    package_name: str = "lodash",
    affected_versions: list[str] | None = None,
    affected_ranges: list[str] | None = None,
    severity: str = "HIGH",
    confidence: float = 0.85,
    source: str = "osv",
    source_id: str | None = "TEST-001",
    summary: str = "test threat",
) -> ThreatRecord:
    """Helper to build a ThreatRecord with sane defaults."""
    return ThreatRecord(
        id=id,
        ecosystem=ecosystem,
        package_name=package_name,
        affected_versions=affected_versions if affected_versions is not None else [],
        affected_ranges=affected_ranges if affected_ranges is not None else [],
        severity=severity,
        confidence=confidence,
        source=source,
        source_id=source_id,
        summary=summary,
        detail_url=None,
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 6, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# audit_lock_file tests
# ---------------------------------------------------------------------------


class TestAuditLockFile:
    """Tests for audit_lock_file."""

    def test_audit_clean_lock_file(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """A clean project with no threats passes all checks."""
        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_lock, config)

        assert result.total_packages > 0
        assert len(result.threats) == 0
        assert result.passed == result.total_packages
        assert result.lock_file == "package-lock.json"

    def test_audit_batch_miss_falls_back_to_single_check(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """When batch_results misses a key, fallback to individual threat_check_package."""
        config = PKGDConfig()
        with patch(
            "pkg_defender.core.auditor.check_packages_batch",
            return_value={},
        ):
            result = audit_lock_file(db_conn, project_with_lock, config)

        assert result.total_packages > 0
        assert len(result.threats) == 0
        assert result.passed == result.total_packages

    def test_audit_finds_threat(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """Packages with known threats are flagged."""
        threat = _make_threat(
            id="osv:LODASH-1",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.21"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, threat)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_lock, config)

        assert len(result.threats) == 1
        entry = result.threats[0]
        assert entry.package == "lodash"
        assert entry.version == "4.17.21"
        assert entry.ecosystem == "npm"
        assert entry.threats[0].record.id == "osv:LODASH-1"

    def test_audit_multiple_threats(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """Multiple threat entries are all reported."""
        t1 = _make_threat(
            id="osv:LODASH-1",
            package_name="lodash",
            affected_versions=["4.17.21"],
            severity="HIGH",
        )
        t2 = _make_threat(
            id="osv:EXPRESS-1",
            package_name="express",
            affected_versions=["4.18.2"],
            severity="MEDIUM",
        )
        insert_threat(db_conn, t1)
        insert_threat(db_conn, t2)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_lock, config)

        assert len(result.threats) == 2
        packages_with_threats = {te.package for te in result.threats}
        assert "lodash" in packages_with_threats
        assert "express" in packages_with_threats

    def test_audit_threat_not_counted_as_passed(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """Threat packages are not included in the passed count."""
        threat = _make_threat(
            id="osv:LODASH-1",
            package_name="lodash",
            affected_versions=["4.17.21"],
            severity="HIGH",
        )
        insert_threat(db_conn, threat)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_lock, config)

        assert result.passed == result.total_packages - 1

    def test_audit_deep_mode_with_cooldown(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """Deep mode flags packages within cooldown window."""
        # Insert a very recent publish time for lodash
        recent_time = datetime.now(UTC) - timedelta(hours=2)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="4.17.21",
                publish_time=recent_time,
                ecosystem="npm",
                package_name="lodash",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        result = audit_lock_file(
            db_conn,
            project_with_lock,
            config,
            deep=True,
            timestamp_lookup=get_version_timestamp,
        )

        assert len(result.cooldown_pending) >= 1
        cd_entry = next((e for e in result.cooldown_pending if e.package == "lodash"), None)
        assert cd_entry is not None
        assert cd_entry.version == "4.17.21"
        assert cd_entry.ecosystem == "npm"
        assert cd_entry.age < timedelta(days=1)

    def test_audit_deep_mode_old_package_passes_cooldown(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """Deep mode does not flag packages past their cooldown."""
        old_time = datetime.now(UTC) - timedelta(days=30)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="4.17.21",
                publish_time=old_time,
                ecosystem="npm",
                package_name="lodash",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        result = audit_lock_file(
            db_conn,
            project_with_lock,
            config,
            deep=True,
            timestamp_lookup=get_version_timestamp,
        )

        cd_entry = next((e for e in result.cooldown_pending if e.package == "lodash"), None)
        assert cd_entry is None

    def test_audit_deep_mode_skips_missing_timestamp(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deep mode skips packages with no cached timestamp."""
        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        caplog.set_level(logging.WARNING)
        result = audit_lock_file(
            db_conn,
            project_with_lock,
            config,
            deep=True,
            timestamp_lookup=get_version_timestamp,
        )

        # No timestamps in DB, so no cooldown entries should be produced.
        assert len(result.cooldown_pending) == 0
        assert "cooldown check skipped" in caplog.text

    def test_audit_poetry_lock(
        self,
        db_conn: sqlite3.Connection,
        project_with_poetry_lock: Path,
    ) -> None:
        """Poetry lock files are audited with ecosystem='pypi'."""
        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_poetry_lock, config)

        assert result.lock_file == "poetry.lock"
        assert result.total_packages > 0
        assert all(te.ecosystem == "pypi" for te in result.threats) or len(result.threats) == 0

    def test_audit_poetry_lock_finds_threat(
        self,
        db_conn: sqlite3.Connection,
        project_with_poetry_lock: Path,
    ) -> None:
        """Threats in poetry.lock packages are detected."""
        threat = _make_threat(
            id="osv:REQUESTS-1",
            ecosystem="pypi",
            package_name="requests",
            affected_versions=["2.31.0"],
            severity="CRITICAL",
            confidence=1.0,
        )
        insert_threat(db_conn, threat)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_poetry_lock, config)

        assert len(result.threats) == 1
        assert result.threats[0].package == "requests"

    def test_audit_requirements_txt(
        self,
        db_conn: sqlite3.Connection,
        project_with_requirements: Path,
    ) -> None:
        """requirements.txt files are audited with ecosystem='pypi'."""
        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_requirements, config)

        assert result.lock_file == "requirements.txt"
        assert result.total_packages > 0

    def test_audit_requirements_finds_threat(
        self,
        db_conn: sqlite3.Connection,
        project_with_requirements: Path,
    ) -> None:
        """Threats in requirements.txt packages are detected."""
        threat = _make_threat(
            id="osv:FLASK-1",
            ecosystem="pypi",
            package_name="flask",
            affected_versions=["3.0.0"],
            severity="HIGH",
            confidence=0.9,
        )
        insert_threat(db_conn, threat)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_requirements, config)

        assert len(result.threats) == 1
        assert result.threats[0].package == "flask"

    def test_audit_scan_time_is_utc(
        self,
        db_conn: sqlite3.Connection,
        project_with_lock: Path,
    ) -> None:
        """scan_time is a UTC datetime."""
        config = PKGDConfig()
        result = audit_lock_file(db_conn, project_with_lock, config)

        assert result.scan_time.tzinfo is not None
        assert result.scan_time.tzinfo == UTC


# ---------------------------------------------------------------------------
# audit_lock_file aggregation tests
# ---------------------------------------------------------------------------


class TestAuditProject:
    """Tests for audit_lock_file (aggregation function)."""

    def test_no_lock_files_raises(self, db_conn: sqlite3.Connection, tmp_path: Path) -> None:
        """Empty directory raises FileNotFoundError."""
        config = PKGDConfig()
        with pytest.raises(FileNotFoundError, match="No recognised lock file"):
            audit_lock_file(db_conn, tmp_path, config)

    def test_aggregates_multiple_lock_files(self, db_conn: sqlite3.Connection, tmp_path: Path) -> None:
        """Two lock files contribute to aggregate result with lock_file set."""
        import json

        # Lock file 1: package-lock.json with lodash
        lock1 = tmp_path / "package-lock.json"
        lock1.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/lodash": {"version": "4.17.21"}},
                }
            )
        )
        # Lock file 2: requirements.txt with requests
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        # Seed a threat for lodash
        threat = ThreatRecord(
            id="osv:LODASH-AGG-1",
            ecosystem="npm",
            package_name="lodash",
            affected_versions=["4.17.21"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="osv",
            source_id="GHSA-xxxx",
            summary="Prototype pollution in lodash",
            detail_url="https://osv.dev/GHSA-xxxx",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            hit_count=1,
            cvss_score=7.5,
            published_at=datetime(2024, 1, 15, tzinfo=UTC),
            ingested_at=datetime.now(UTC),
            is_malicious=False,
            is_unverified=False,
        )
        insert_threat(db_conn, threat)

        config = PKGDConfig()
        result = audit_lock_file(db_conn, tmp_path, config)

        assert result.total_packages == 2
        assert len(result.threats) == 1
        assert result.threats[0].lock_file == "package-lock.json"
        assert "package-lock.json" in result.lock_file
        assert "requirements.txt" in result.lock_file


# ---------------------------------------------------------------------------
# _check_cooldown_for_audit tests
# ---------------------------------------------------------------------------


class TestCheckCooldownForAudit:
    """Tests for _check_cooldown_for_audit."""

    def test_returns_entry_when_too_new(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns AuditCooldownEntry for packages within cooldown."""
        recent_time = datetime.now(UTC) - timedelta(hours=6)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0",
                publish_time=recent_time,
                ecosystem="npm",
                package_name="test-pkg",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        entry = _check_cooldown_for_audit(
            db_conn,
            "npm",
            "test-pkg",
            "1.0.0",
            config,
            timestamp_lookup=get_version_timestamp,
        )

        assert entry is not None
        assert entry.package == "test-pkg"
        assert entry.version == "1.0.0"
        assert entry.age < timedelta(days=1)

    def test_returns_none_when_old_enough(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns None for packages past cooldown."""
        old_time = datetime.now(UTC) - timedelta(days=30)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0",
                publish_time=old_time,
                ecosystem="npm",
                package_name="test-pkg",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        entry = _check_cooldown_for_audit(
            db_conn,
            "npm",
            "test-pkg",
            "1.0.0",
            config,
            timestamp_lookup=get_version_timestamp,
        )

        assert entry is None

    def test_returns_none_when_no_timestamp(
        self,
        db_conn: sqlite3.Connection,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Returns None when no cached timestamp exists."""
        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=True))
        caplog.set_level(logging.WARNING)
        entry = _check_cooldown_for_audit(
            db_conn,
            "npm",
            "nonexistent",
            "1.0.0",
            config,
            timestamp_lookup=get_version_timestamp,
        )
        assert entry is None
        assert "cooldown check skipped" in caplog.text

    def test_cooldown_disabled_returns_none(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """Returns None when cooldown is disabled."""
        recent_time = datetime.now(UTC) - timedelta(hours=1)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0",
                publish_time=recent_time,
                ecosystem="npm",
                package_name="test-pkg",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=1, enabled=False))
        entry = _check_cooldown_for_audit(
            db_conn,
            "npm",
            "test-pkg",
            "1.0.0",
            config,
            timestamp_lookup=get_version_timestamp,
        )

        assert entry is None

    def test_clears_at_equals_publish_time_plus_cooldown_days(
        self,
        db_conn: sqlite3.Connection,
    ) -> None:
        """clears_at is publish_time + cooldown_days."""
        publish_time = datetime(2099, 1, 1, tzinfo=UTC)
        insert_version_timestamp(
            db_conn,
            VersionInfo(
                version="1.0.0",
                publish_time=publish_time,
                ecosystem="npm",
                package_name="test-pkg",
            ),
        )

        config = PKGDConfig(cooldown=CooldownConfig(default_days=3, enabled=True))
        entry = _check_cooldown_for_audit(
            db_conn,
            "npm",
            "test-pkg",
            "1.0.0",
            config,
            timestamp_lookup=get_version_timestamp,
        )

        assert entry is not None
        expected_clears = publish_time + timedelta(days=3)
        assert entry.clears_at == expected_clears
