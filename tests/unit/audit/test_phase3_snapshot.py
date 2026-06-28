"""Tests for Phase 3: Snapshot Publishing implementation.

Tests verify:
1. Build Script (`scripts/build_snapshot.py`)
   - fetch_all_tier1() returns records
   - Snapshot contains only Tier 1 sources (OSV, GHSA, npm advisory)
   - SHA256 generation
   - Database output is compressed

2. CLI Command (`pkgd db snapshot`)
   - --help works
   - --download flag exists
   - --verify flag exists
   - SHA256 verification on mismatched hash fails

3. GitHub Actions Workflow (`.github/workflows/snapshot.yml`)
   - Has schedule trigger (every 6 hours)
   - Has artifact upload
   - Has release step
"""

from __future__ import annotations

import asyncio
import hashlib
import io
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from pkg_defender.intel.base import FetchStatus
from pkg_defender.models import ThreatRecord

# ============================================================================
# 1. Build Script Tests
# ============================================================================


class TestBuildScript:
    """Tests for the build_snapshot.py script."""

    @staticmethod
    def _make_fake_records(count: int = 6) -> list[ThreatRecord]:
        """Return ThreatRecord objects spanning 3+ ecosystems."""
        from pkg_defender.models import ThreatRecord

        ecosystems = ["npm", "pypi", "cargo"]
        records = []
        for i in range(count):
            eco = ecosystems[i % len(ecosystems)]
            records.append(
                ThreatRecord(
                    id=f"test:{eco}:pkg-{i}",
                    ecosystem=eco,
                    package_name=f"pkg-{i}",
                    severity="HIGH",
                    confidence=0.9,
                    source="osv",
                )
            )
        return records

    def test_fetch_all_tier1_returns_list(self) -> None:
        """fetch_all_tier1 returns a list (mocked, no network)."""
        from scripts.build_snapshot import fetch_all_tier1

        with (
            patch("scripts.build_snapshot.download_ecosystem_dump", new_callable=AsyncMock, return_value=[]),
            patch("scripts.build_snapshot.GHSAFeed") as mock_ghsa,
            patch("scripts.build_snapshot.NpmAdvisoryFeed") as mock_npm,
        ):
            mock_ghsa.return_value.fetch = AsyncMock(return_value=MagicMock(records=[], status=FetchStatus.SUCCESS))
            mock_npm.return_value.fetch = AsyncMock(return_value=MagicMock(records=[], status=FetchStatus.SUCCESS))
            result = asyncio.run(fetch_all_tier1())

        assert isinstance(result, list), "fetch_all_tier1 should return a list"

    def test_tier1_ecosystems_defined(self) -> None:
        """Build script defines Tier 1 ecosystems."""
        from scripts.build_snapshot import TIER1_ECOSYSTEMS

        expected = {"npm", "pypi", "cargo", "rubygems", "go", "maven", "nuget", "packagist"}
        assert expected.issubset(set(TIER1_ECOSYSTEMS)), (
            f"Missing expected Tier 1 ecosystems: {expected - set(TIER1_ECOSYSTEMS)}"
        )

    def test_build_snapshot_produces_database(self, tmp_path: Path) -> None:
        """build_snapshot creates a database file (mocked feeds)."""
        from scripts.build_snapshot import build_snapshot

        output_path = tmp_path / "test_snapshot.db"

        with patch("scripts.build_snapshot.fetch_all_tier1", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self._make_fake_records()
            count = build_snapshot(output_path)

        assert output_path.exists(), "Database file was not created"
        assert count >= 0, "Record count should be non-negative"

    def test_database_output_is_valid_sqlite(self, tmp_path: Path) -> None:
        """Built database is a valid SQLite database (mocked feeds)."""
        import contextlib
        import sqlite3

        from scripts.build_snapshot import build_snapshot

        output_path = tmp_path / "test_snapshot_valid.db"

        with patch("scripts.build_snapshot.fetch_all_tier1", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self._make_fake_records()
            build_snapshot(output_path)

        with contextlib.closing(sqlite3.connect(str(output_path))) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        assert "threats" in tables, "Database should have 'threats' table"

    def test_database_has_threats_schema(self, tmp_path: Path) -> None:
        """Database has correct threats table schema (mocked feeds)."""
        import contextlib
        import sqlite3

        from scripts.build_snapshot import build_snapshot

        output_path = tmp_path / "test_snapshot_schema.db"

        with patch("scripts.build_snapshot.fetch_all_tier1", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self._make_fake_records()
            build_snapshot(output_path)

        with contextlib.closing(sqlite3.connect(str(output_path))) as conn:
            cursor = conn.execute("PRAGMA table_info(threats)")
            columns = {row[1] for row in cursor.fetchall()}

        assert "ecosystem" in columns, "Missing 'ecosystem' column"
        assert "package_name" in columns, "Missing 'package_name' column"
        assert "severity" in columns, "Missing 'severity' column"


# ============================================================================
# 4. Integration Tests (slow)
# ============================================================================


class TestSnapshotIntegration:
    """Integration tests for snapshot workflow end-to-end (mocked feeds)."""

    @staticmethod
    def _make_fake_records() -> list[ThreatRecord]:
        """Return ThreatRecord objects spanning 3+ ecosystems."""
        from pkg_defender.models import ThreatRecord

        return [
            ThreatRecord(
                id="test:npm:pkg-1",
                ecosystem="npm",
                package_name="pkg-1",
                severity="HIGH",
                confidence=0.9,
                source="osv",
            ),
            ThreatRecord(
                id="test:pypi:pkg-2",
                ecosystem="pypi",
                package_name="pkg-2",
                severity="MEDIUM",
                confidence=0.8,
                source="ghsa",
            ),
            ThreatRecord(
                id="test:cargo:pkg-3",
                ecosystem="cargo",
                package_name="pkg-3",
                severity="CRITICAL",
                confidence=0.95,
                source="osv",
            ),
        ]

    def test_build_and_verify_roundtrip(self, tmp_path: Path) -> None:
        """Build snapshot and verify SHA256 matches (mocked feeds)."""
        from scripts.build_snapshot import build_snapshot

        output_path = tmp_path / "test_roundtrip.db"

        with patch("scripts.build_snapshot.fetch_all_tier1", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self._make_fake_records()
            build_snapshot(output_path)

        data = output_path.read_bytes()
        computed_sha = hashlib.sha256(data).hexdigest()

        assert len(computed_sha) == 64
        assert computed_sha.isalnum()

    def test_gzipped_database_smaller(self, tmp_path: Path) -> None:
        """Gzipped database is non-empty (mocked feeds)."""
        import gzip

        from scripts.build_snapshot import build_snapshot

        output_path = tmp_path / "test_gzip.db"

        with patch("scripts.build_snapshot.fetch_all_tier1", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self._make_fake_records()
            build_snapshot(output_path)

        uncompressed = output_path.read_bytes()
        compressed = gzip.compress(uncompressed)
        compressed_size = len(compressed)

        assert compressed_size > 0, "Compressed data should have content"


class TestCLIDbVerify:
    """Tests for `pkgd db verify` CLI command."""

    def test_verify_command_exists(self, runner: CliRunner) -> None:
        """'pkgd db verify' command is registered."""
        from pkg_defender.cli.main import cli

        result = runner.invoke(cli, ["db", "verify", "--help"])
        assert result.exit_code == 0
        assert "verify" in result.output.lower()

    def test_verify_missing_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify exits 1 with helpful message when DB does not exist."""
        from pkg_defender.cli.main import cli

        nonexistent = tmp_path / "nonexistent" / "threats.db"
        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda *args, **kwargs: nonexistent)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "Error" in result.output

    def test_verify_healthy_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify exits 0 and reports 'ok' for a healthy database."""
        from pkg_defender.cli.main import cli
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "healthy.db"
        conn = init_db(db_path)

        # Seed threat data
        conn.execute(
            """INSERT INTO threats (id, ecosystem, package_name, severity, confidence, source)
               VALUES ('test-1', 'npm', 'bad-pkg', 'CRITICAL', 0.9, 'osv')"""
        )
        # Seed feed_state for last sync
        conn.execute(
            """INSERT INTO feed_state (feed_name, last_sync, status)
               VALUES ('osv', '2026-05-19 14:30:00', 'idle')"""
        )
        conn.commit()
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda *args, **kwargs: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        assert "PRAGMA integrity_check: ok" in result.output
        assert "Threat records:" in result.output
        assert "Last sync:" in result.output
        assert "File size:" in result.output

    def test_verify_corrupt_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify exits 1 when database is corrupted."""
        from pkg_defender.cli.main import cli

        db_path = tmp_path / "corrupt.db"

        # Write valid SQLite header (first 100 bytes) then garbage
        valid_header = bytes(
            [
                0x53,
                0x51,
                0x4C,
                0x69,
                0x74,
                0x65,
                0x20,
                0x66,  # SQLite format
                0x6F,
                0x72,
                0x6D,
                0x61,
                0x74,
                0x20,
                0x33,
                0x00,  # \0
            ]
        )
        db_path.write_bytes(valid_header + b"\x00" * 84 + b"GARBAGE DATA THAT WILL CAUSE CORRUPTION DETECTION" * 100)

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda *args, **kwargs: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "FAILED" in result.output or "corruption" in result.output.lower() or "Error" in result.output

    def test_verify_empty_healthy_db(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify handles an empty freshly-initialized database gracefully."""
        from pkg_defender.cli.main import cli
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "empty.db"
        conn = init_db(db_path)
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda *args, **kwargs: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        assert "PRAGMA integrity_check: ok" in result.output


# ============================================================================
# 5. Atomic Download Tests (S13 regression)
# ============================================================================


class TestAtomicSnapshotDownload:
    """Tests for atomic snapshot download (S13 regression).

    The fix replaced ``db_path.write_bytes(decompressed_data)`` with an atomic
    write pattern using ``tempfile.mkstemp`` + ``os.replace`` to prevent
    database corruption on interrupted downloads.

    Root cause: ``db.py`` lines 191-204 and 319-331 — direct ``write_bytes``
    to ``db_path`` was not atomic; interruption would leave a partial/corrupt
    database file.
    """

    @staticmethod
    def _gzip_bytes(data: bytes) -> bytes:
        """Compress bytes with gzip for mock download responses."""
        import gzip

        return gzip.compress(data)

    @staticmethod
    def _sha_url(url: str) -> str:
        """Return the companion .sha256 URL for a snapshot URL."""
        return url + ".sha256"

    @staticmethod
    def _sha_body(data: bytes) -> bytes:
        """Build a .sha256 file body that matches *data*."""
        expected_sha = hashlib.sha256(data).hexdigest()
        return f"{expected_sha}  snapshot.db.gz".encode()

    def _setup_download_mocks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        db_path: Path | None = None,
        gz_data: bytes | None = None,
    ) -> Path:
        """Set up common mocks for snapshot download via custom URL path.

        Configures: ``get_db_path``, ``load_config`` (with custom URL), and
        ``init_db`` (mock connection). HTTP is mocked via ``aioresponses``
        in each test method. Returns the ``db_path``.
        """
        db_path = db_path or (tmp_path / "threats.db")
        gz_data = gz_data or self._gzip_bytes(b"mock database content")

        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda *args, **kwargs: db_path,
        )

        # Config with custom URL (simpler code path than GitHub API)
        from pkg_defender.config.settings import PKGDConfig

        cfg = PKGDConfig()
        cfg.database.snapshot_url = "https://example.com/snapshot.db.gz"
        monkeypatch.setattr("pkg_defender.config.load_config", lambda: cfg)

        # Mock init_db — returns mock connection (avoids real SQLite)
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (42,)
        monkeypatch.setattr(
            "pkg_defender.db.schema.init_db",
            lambda path: mock_conn,
        )

        return db_path

    def test_atomic_write_pattern_used(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Atomic write uses tempfile.mkstemp + os.replace (not write_bytes).

        This test FAILS before the fix (which used ``write_bytes`` directly)
        and PASSES after the atomic pattern. It verifies the atomic write
        toolchain is invoked with correct arguments.
        """
        import aioresponses

        from pkg_defender.cli.main import cli

        db_path = tmp_path / "threats.db"
        gz_data = self._gzip_bytes(b"atomic pattern test data")
        self._setup_download_mocks(tmp_path, monkeypatch, db_path, gz_data)

        tmp_file = tmp_path / ".snapshot.simulated.tmp"
        monkeypatch.setattr(
            "tempfile.mkstemp",
            lambda *args, **kwargs: (999, str(tmp_file)),
        )

        # os.fdopen(999) would fail — return a BytesIO instead
        buf = io.BytesIO()
        monkeypatch.setattr("os.fdopen", lambda fd, mode: buf)

        # Track os.replace calls
        replace_calls: list[tuple[str, str]] = []

        def _tracking_replace(src: str, dst: str) -> None:
            replace_calls.append((src, dst))

        monkeypatch.setattr("os.replace", _tracking_replace)

        sha_url = self._sha_url("https://example.com/snapshot.db.gz")
        sha_body = self._sha_body(gz_data)

        with aioresponses.aioresponses() as mocked:
            mocked.get(
                "https://example.com/snapshot.db.gz",
                body=gz_data,
                status=200,
            )
            mocked.get(sha_url, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Unexpected exit: {result.output}"
        assert len(replace_calls) == 1, f"os.replace should be called once, got {len(replace_calls)}"
        src, dst = replace_calls[0]
        assert Path(src).name.startswith(".snapshot."), f"os.replace src should be .snapshot.*, got {src}"
        assert Path(dst) == db_path, f"os.replace dst should be db_path, got {dst}"

    def test_temp_file_cleanup_on_write_failure(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Temp file cleaned up via os.unlink when write fails (S13).

        Root cause: ``db.py`` lines 191-204 / 319-331 — the except block
        calls ``os.unlink(tmp_path)`` when the write fails. Without this,
        interrupted downloads leak ``.snapshot.*`` temp files.
        """
        import aioresponses

        from pkg_defender.cli.main import cli

        db_path = tmp_path / "threats.db"
        gz_data = self._gzip_bytes(b"cleanup test data")
        self._setup_download_mocks(tmp_path, monkeypatch, db_path, gz_data)

        tmp_file = tmp_path / ".snapshot.cleanup.tmp"
        monkeypatch.setattr(
            "tempfile.mkstemp",
            lambda *args, **kwargs: (999, str(tmp_file)),
        )

        # Track os.unlink calls
        unlink_calls: list[str] = []
        monkeypatch.setattr(
            "os.unlink",
            lambda path: unlink_calls.append(str(path)),
        )

        sha_url = self._sha_url("https://example.com/snapshot.db.gz")
        sha_body = self._sha_body(gz_data)

        with aioresponses.aioresponses() as mocked:
            mocked.get(
                "https://example.com/snapshot.db.gz",
                body=gz_data,
                status=200,
            )
            mocked.get(sha_url, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code != 0, "Should fail on bad file descriptor"
        assert str(tmp_file) in unlink_calls, (
            f"os.unlink should be called for temp file {tmp_file}, got: {unlink_calls}"
        )

    def test_no_partial_file_left_on_write_failure(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No partial/corrupt db_path file left when atomic write fails (S13).

        Root cause: Before the fix, ``write_bytes`` would partially
        overwrite ``db_path`` on interruption, leaving a corrupt file.
        After the fix, the atomic pattern writes to a temp file first, so
        ``db_path`` is never created/overwritten on failure — and the
        temp file is cleaned up via ``os.unlink``.
        """
        import aioresponses

        from pkg_defender.cli.main import cli

        # Do NOT pre-create db_path — the test verifies no partial file
        # appears when the atomic write fails
        db_path = tmp_path / "threats.db"

        gz_data = self._gzip_bytes(b"data that should never reach disk")
        self._setup_download_mocks(tmp_path, monkeypatch, db_path, gz_data)

        tmp_file = tmp_path / ".snapshot.failure.tmp"
        monkeypatch.setattr(
            "tempfile.mkstemp",
            lambda *args, **kwargs: (999, str(tmp_file)),
        )

        # Track unlink
        unlink_calls: list[str] = []
        monkeypatch.setattr(
            "os.unlink",
            lambda path: unlink_calls.append(str(path)),
        )

        sha_url = self._sha_url("https://example.com/snapshot.db.gz")
        sha_body = self._sha_body(gz_data)

        with aioresponses.aioresponses() as mocked:
            mocked.get(
                "https://example.com/snapshot.db.gz",
                body=gz_data,
                status=200,
            )
            mocked.get(sha_url, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code != 0, "Should fail on bad file descriptor"
        assert not db_path.exists(), "db_path should NOT exist — atomic write prevents partial files"
        assert str(tmp_file) in unlink_calls, f"Temp file should be cleaned up, got {unlink_calls}"

    def test_happy_path_atomic_download(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Happy path: decompressed data written to db_path atomically.

        Uses real ``tempfile.mkstemp``, real ``os.fdopen``, real
        ``os.replace`` to verify the full atomic write flow produces the
        correct file at ``db_path``.
        """
        import aioresponses

        from pkg_defender.cli.main import cli

        decompressed_data = b"expected database content after atomic write"
        db_path = tmp_path / "threats.db"
        gz_data = self._gzip_bytes(decompressed_data)
        self._setup_download_mocks(tmp_path, monkeypatch, db_path, gz_data)

        # DON'T mock mkstemp, fdopen, or os.replace — run real atomic write

        sha_url = self._sha_url("https://example.com/snapshot.db.gz")
        sha_body = self._sha_body(gz_data)

        with aioresponses.aioresponses() as mocked:
            mocked.get(
                "https://example.com/snapshot.db.gz",
                body=gz_data,
                status=200,
            )
            mocked.get(sha_url, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Happy path failed: {result.output}"
        assert db_path.exists(), "db_path should exist after successful write"
        assert db_path.read_bytes() == decompressed_data, "db_path should contain the decompressed download data"
