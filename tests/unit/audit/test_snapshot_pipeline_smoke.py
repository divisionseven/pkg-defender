"""Smoke tests for the production snapshot pipeline.

Tests the production build script at scripts/build_snapshot.py. All network
calls are mocked so these
tests run fast and offline.

The production pipeline performs:
1. Fetch threat data from Tier 1 feeds (OSV, GHSA, ossf_malicious)
2. Build SQLite database with batch inserts + VACUUM
3. PRAGMA integrity_check
4. Per-ecosystem minimum (>= 3 ecosystems with data)
5. Record count bounds check (vs. previous build)
"""

from __future__ import annotations

import gzip
import hashlib
import sqlite3
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

if TYPE_CHECKING:
    from pkg_defender.models import ThreatRecord

# ---------------------------------------------------------------------------
# Constants — valid values for schema CHECK constraints
# ---------------------------------------------------------------------------

_ECOSYSTEMS_4: list[str] = ["npm", "pypi", "cargo", "rubygems"]
_ECOSYSTEMS_2: list[str] = ["npm", "pypi"]
_SOURCES: list[str] = ["osv", "ghsa", "npm_advisory", "socket"]
_SEVERITIES: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_records(
    ecosystems: list[str] | None = None,
    count_per_ecosystem: int = 5,
) -> list[ThreatRecord]:
    """Create synthetic ThreatRecords that pass schema CHECK constraints.

    Uses values from ``VALID_ECOSYSTEMS``, ``VALID_SOURCES``, and
    ``VALID_SEVERITIES`` to ensure CHECK constraint compliance.

    Args:
        ecosystems: Ecosystem identifiers to use. Defaults to four ecosystems.
        count_per_ecosystem: Number of records per ecosystem.

    Returns:
        List of ThreatRecord objects.
    """
    # Import inside helper to avoid module-level side effects
    from pkg_defender.models import ThreatRecord

    ecosystems = ecosystems or _ECOSYSTEMS_4
    records: list[ThreatRecord] = []
    idx = 0
    for eco in ecosystems:
        for i in range(count_per_ecosystem):
            records.append(
                ThreatRecord(
                    id=f"{eco}:synth-pkg-{i}",
                    ecosystem=eco,
                    package_name=f"synth-pkg-{i}",
                    severity=_SEVERITIES[i % len(_SEVERITIES)],
                    confidence=0.8,
                    source=_SOURCES[idx % len(_SOURCES)],
                    summary=f"Synthetic threat record for {eco} ecosystem",
                )
            )
            idx += 1
    return records


def _load_build_snapshot() -> ModuleType:
    """Import and fully load the production build_snapshot module.

    Adds ``scripts`` to ``sys.path`` if not already present, then
    imports the production ``build_snapshot`` module. Must be called inside
    test functions (not at module level) to avoid ``sys.path`` side effects
    during test collection.

    Returns:
        The loaded production ``build_snapshot`` module.
    """
    # Path: tests/unit/audit/ -> project root -> scripts/
    project_root = Path(__file__).parent.parent.parent.parent
    scripts_dir = str(project_root / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)

    if "build_snapshot" not in sys.modules:
        import build_snapshot as _mod  # type: ignore[import-not-found]

        return cast(ModuleType, _mod)

    return sys.modules["build_snapshot"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestProductionSnapshotPipeline:
    """Smoke tests for scripts/build_snapshot.py production pipeline."""

    def test_build_snapshot_produces_valid_database(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """build_snapshot() creates a valid database with expected records.

        Mocks ``fetch_all_tier1()`` to return 20 synthetic records across
        4 ecosystems, then verifies:
        - Database file exists
        - ``SELECT COUNT(*) FROM threats`` returns expected count
        - ``PRAGMA integrity_check`` returns ``ok``
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=5)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "snapshot.db"
        count = build_snapshot.build_snapshot(db_path)

        assert db_path.exists(), "Database file was not created"
        assert count == len(records), f"Expected {len(records)} records, got {count}"

        conn = sqlite3.connect(str(db_path))
        try:
            row_count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            assert row_count == len(records), f"Database has {row_count} records, expected {len(records)}"

            integrity = conn.execute("PRAGMA integrity_check").fetchall()
            assert len(integrity) == 1 and integrity[0][0] == "ok", f"PRAGMA integrity_check failed: {integrity}"
        finally:
            conn.close()

    def test_integrity_check_passes_on_valid_db(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """PRAGMA integrity_check returns 'ok' for a well-formed database.

        Builds a database with mocked feeds, then independently verifies
        that ``PRAGMA integrity_check`` passes. This is a positive test —
        the integrity check is a critical gate (``sys.exit(1)`` on failure)
        in the production script.
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=3)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "integrity_test.db"
        build_snapshot.build_snapshot(db_path)

        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            assert len(rows) == 1, f"Expected 1 row, got {len(rows)}: {rows}"
            assert rows[0][0] == "ok", f"Expected 'ok', got '{rows[0][0]}'"
        finally:
            conn.close()

    def test_ecosystem_minimum_enforced(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """build_snapshot() exits with code 1 when fewer than 3 ecosystems have data.

        Production script lines 124-130 enforce ``eco_count < 3`` ->
        ``sys.exit(1)``. Mocks ``fetch_all_tier1()`` to return records from
        only 2 ecosystems.
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_2, count_per_ecosystem=5)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "eco_min_fail.db"
        with pytest.raises(SystemExit) as exc_info:
            build_snapshot.build_snapshot(db_path)

        assert exc_info.value.code == 1, f"Expected exit code 1, got {exc_info.value.code}"

    def test_ecosystem_minimum_passes_with_3_plus(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """build_snapshot() succeeds when 4 ecosystems have data (>= 3 required).

        Production script lines 124-130 enforce ``eco_count < 3`` ->
        ``sys.exit(1)``. With 4 ecosystems, the check passes.
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=3)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "eco_min_pass.db"
        count = build_snapshot.build_snapshot(db_path)

        assert count == len(records), f"Expected {len(records)} records, got {count}"

    def test_record_count_bounds_first_build(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """First build succeeds with no previous_record_count in db_metadata.

        Production script lines 133-160 — ``prev_row is not None`` guard
        skips the bounds check on first build. Verifies the build succeeds
        and sets ``previous_record_count`` after completion.
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=3)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "first_build.db"
        count = build_snapshot.build_snapshot(db_path)

        assert count == len(records), f"Expected {len(records)} records, got {count}"

        # Verify previous_record_count was set after successful build
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute("SELECT value FROM db_metadata WHERE key = 'previous_record_count'").fetchone()
            assert row is not None, "previous_record_count should be set after build"
            assert int(row[0]) == len(records), f"previous_record_count should be {len(records)}, got {row[0]}"
        finally:
            conn.close()

    def test_record_count_bounds_suspicious_inflation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """build_snapshot() exits when record count >5x previous count.

        Pre-populates ``db_metadata`` with ``previous_record_count = 10``,
        then builds with 100+ records (> 5x). Production script lines 137-144
        enforce ``record_count > 5 * prev_count`` -> ``sys.exit(1)``.
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=30)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        # Pre-create database with previous_record_count = 10
        db_path = tmp_path / "inflation.db"
        from pkg_defender.db.schema import init_db

        conn = init_db(db_path)
        conn.execute(
            "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
            ("previous_record_count", "10"),
        )
        conn.commit()
        conn.close()

        # build_snapshot should detect suspicious inflation and exit
        with pytest.raises(SystemExit) as exc_info:
            build_snapshot.build_snapshot(db_path)

        assert exc_info.value.code == 1, f"Expected exit code 1, got {exc_info.value.code}"

    def test_sha256_gzip_roundtrip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Database bytes survive gzip round-trip with matching SHA256.

        1. Build a database with mocked feeds
        2. Compute SHA256 of the database bytes
        3. Gzip compress the database
        4. Decompress and verify SHA256 matches
        5. Verify the decompressed database is valid SQLite
        """
        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=5)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "roundtrip.db"
        build_snapshot.build_snapshot(db_path)

        # Step 1: Read database bytes and compute SHA256
        db_bytes = db_path.read_bytes()
        original_sha = hashlib.sha256(db_bytes).hexdigest()

        # Step 2: Gzip compress
        compressed = gzip.compress(db_bytes)

        # Step 3: Decompress and verify SHA256
        decompressed = gzip.decompress(compressed)
        decompressed_sha = hashlib.sha256(decompressed).hexdigest()
        assert original_sha == decompressed_sha, (
            f"SHA256 mismatch: original={original_sha}, decompressed={decompressed_sha}"
        )

        # Step 4: Verify decompressed data is valid SQLite
        decompressed_path = tmp_path / "decompressed.db"
        decompressed_path.write_bytes(decompressed)

        conn = sqlite3.connect(str(decompressed_path))
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            assert len(rows) == 1 and rows[0][0] == "ok", f"Decompressed database integrity check failed: {rows}"

            count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            assert count == len(records), f"Decompressed DB has {count} records, expected {len(records)}"
        finally:
            conn.close()


@pytest.mark.smoke
class TestCLISnapshotVerify:
    """Tests for CLI ``pkgd db snapshot --verify`` against production-built databases."""

    def test_cli_snapshot_verify_with_real_db(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        runner: CliRunner,
    ) -> None:
        """``pkgd db snapshot --verify`` works against a production-built database.

        1. Build a database using the production ``build_snapshot()``
        2. Monkeypatch ``get_db_path()`` to point to it
        3. Invoke ``runner.invoke(cli, ["db", "snapshot", "--verify"])``
        4. Verify exit code 0 and output contains SHA256 hash + integrity OK
        """
        from pkg_defender.cli.main import cli

        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=5)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "cli_verify.db"
        build_snapshot.build_snapshot(db_path)

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda *args, **kwargs: db_path,
        )

        result = runner.invoke(cli, ["db", "snapshot", "--verify"])

        assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"
        # SHA256 is 64 hex characters — verify it appears in output
        assert "SHA256:" in result.output, f"Expected 'SHA256:' in output. Got: {result.output}"
        assert "integrity: OK" in result.output or "integrity OK" in result.output, (
            f"Expected integrity OK in output. Got: {result.output}"
        )


@pytest.mark.smoke
class TestCLIDbVerify:
    """Tests for CLI ``pkgd db verify`` against production-built databases."""

    def test_cli_db_verify_with_production_built_db(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        runner: CliRunner,
    ) -> None:
        """``pkgd db verify`` works against a production-built database.

        1. Build a database using the production ``build_snapshot()``
        2. Monkeypatch ``get_db_path()`` to point to it
        3. Invoke ``runner.invoke(cli, ["db", "verify"])``
        4. Verify exit code 0, output contains integrity check, threat count,
           file size
        """
        from pkg_defender.cli.main import cli

        build_snapshot = _load_build_snapshot()
        records = _make_records(ecosystems=_ECOSYSTEMS_4, count_per_ecosystem=5)

        monkeypatch.setattr(
            build_snapshot,
            "fetch_all_tier1",
            AsyncMock(return_value=records),
        )

        db_path = tmp_path / "cli_db_verify.db"
        build_snapshot.build_snapshot(db_path)

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda *args, **kwargs: db_path,
        )

        result = runner.invoke(cli, ["db", "verify"])

        assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"
        assert "PRAGMA integrity_check: ok" in result.output, (
            f"Expected 'PRAGMA integrity_check: ok' in output. Got: {result.output}"
        )
        assert "Threat records:" in result.output, f"Expected 'Threat records:' in output. Got: {result.output}"
        assert "File size:" in result.output, f"Expected 'File size:' in output. Got: {result.output}"
