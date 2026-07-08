"""Tests for pkg_defender.cli.commands.db module.

Covers ``db snapshot`` (--download, --verify, --latest) and ``db verify``.
Targets 60%+ branch coverage for ``db.py``.

Mocking strategy
----------------
- ``get_db_path``, ``init_db``, ``get_connection``, ``load_config`` are
  monkeypatched at their **source** module path (``pkg_defender.cli.common``,
  ``pkg_defender.db.schema``, ``pkg_defender.config``), because ``db.py`` uses
  local imports (``from X import Y`` inside function bodies) which resolve at
  runtime.
- ``pkg_defender.cli.commands.db.subprocess.run`` is monkeypatched for
  backup calls inside inline async functions.
- ``aioresponses`` mocks ``aiohttp.ClientSession`` for all HTTP calls.
- Real file I/O (``tempfile.mkstemp``, ``os.fdopen``, ``os.replace``) is left
  un-mocked for download tests to verify the atomic write pattern works.
"""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import aiohttp
import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_DB_ERROR as _EXIT_DB_ERROR
from pkg_defender.cli.main import cli
from pkg_defender.config.settings import PKGDConfig

# ============================================================================
# Helpers
# ============================================================================

RELEASE_DATA: dict[str, Any] = {
    "tag_name": "snapshot-latest",
    "published_at": "2026-07-07T12:00:00Z",
    "assets": [
        {
            "name": "threats-latest.db.gz",
            "size": 1048576,
            "browser_download_url": (
                "https://github.com/divisionseven/pkg-defender/releases/download/snapshot-latest/threats-latest.db.gz"
            ),
        },
        {
            "name": "threats-latest.db.gz.sha256",
            "size": 128,
            "browser_download_url": (
                "https://github.com/divisionseven/pkg-defender/"
                "releases/download/snapshot-latest/threats-latest.db.gz.sha256"
            ),
        },
    ],
}

CUSTOM_URL = "https://example.com/snapshot.db.gz"
CUSTOM_URL_SHA256 = CUSTOM_URL + ".sha256"
SNAPSHOT_TAG = "snapshot-latest"
SNAPSHOT_DB_ASSET = "threats-latest.db.gz"
SNAPSHOT_SHA_ASSET = "threats-latest.db.gz.sha256"
SNAPSHOT_BASE_URL = f"https://github.com/divisionseven/pkg-defender/releases/download/{SNAPSHOT_TAG}"
DB_ASSET_URL = f"{SNAPSHOT_BASE_URL}/{SNAPSHOT_DB_ASSET}"
SHA_ASSET_URL = f"{SNAPSHOT_BASE_URL}/{SNAPSHOT_SHA_ASSET}"
API_TAGS_URL = f"https://api.github.com/repos/divisionseven/pkg-defender/releases/tags/{SNAPSHOT_TAG}"


def _gzip_bytes(data: bytes) -> bytes:
    """Compress bytes with gzip for mock download responses."""
    return gzip.compress(data)


def _expected_sha_hex(data: bytes) -> str:
    """Return hex digest of *data* for use in mock SHA responses."""
    return hashlib.sha256(data).hexdigest()


def _mock_config(
    monkeypatch: pytest.MonkeyPatch,
    snapshot_url: str = "",
) -> None:
    """Set ``load_config`` to return a config with the given *snapshot_url*."""
    cfg = PKGDConfig()
    cfg.database.snapshot_url = snapshot_url
    monkeypatch.setattr("pkg_defender.config.load_config", lambda: cfg)


def _mock_init_db(
    monkeypatch: pytest.MonkeyPatch,
    threat_count: int = 42,
) -> MagicMock:
    """Mock ``init_db`` to return a connection with controlled query results.

    Parameters
    ----------
    threat_count:
        Value returned by ``SELECT COUNT(*) FROM threats``.
    """
    mock_conn = MagicMock()
    mock_conn.execute.return_value.fetchone.return_value = (threat_count,)
    monkeypatch.setattr("pkg_defender.db.schema.init_db", lambda path: mock_conn)
    return mock_conn


def _setup_download_mocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    custom_url: str | None = CUSTOM_URL,
    threat_count: int = 42,
) -> Path:
    """Set up common mocks for snapshot download tests and return *db_path*."""
    db_path = tmp_path / "threats.db"
    monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)
    _mock_config(monkeypatch, snapshot_url=custom_url or "")
    _mock_init_db(monkeypatch, threat_count=threat_count)
    return db_path


# ============================================================================
# TestDbGroup — basic help / group behaviour
# ============================================================================


class TestDbGroup:
    """General ``pkgd db`` group tests."""

    def test_db_help(self, runner: CliRunner) -> None:
        """``pkgd db --help`` shows subcommands."""
        result = runner.invoke(cli, ["db", "--help"])
        assert result.exit_code == 0
        assert "snapshot" in result.output.lower()
        assert "verify" in result.output.lower()

    def test_db_snapshot_help(self, runner: CliRunner) -> None:
        """``pkgd db snapshot --help`` shows flag options."""
        result = runner.invoke(cli, ["db", "snapshot", "--help"])
        assert result.exit_code == 0
        assert "snapshot" in result.output.lower()
        assert "--download" in result.output

    def test_db_verify_help(self, runner: CliRunner) -> None:
        """``pkgd db verify --help`` shows usage."""
        result = runner.invoke(cli, ["db", "verify", "--help"])
        assert result.exit_code == 0
        assert "verify" in result.output.lower()

    def test_db_snapshot_no_flags_shows_help(self, runner: CliRunner) -> None:
        """``pkgd db snapshot`` without flags displays help text."""
        result = runner.invoke(cli, ["db", "snapshot"])
        assert result.exit_code == 0
        assert "--download" in result.output or "-d" in result.output


# ============================================================================
# TestDbSnapshotLatest — ``pkgd db snapshot --latest``
# ============================================================================


class TestDbSnapshotLatest:
    """Tests for the ``--latest`` flag on ``db snapshot``."""

    def test_latest_success(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--latest`` displays real snapshot metadata from GitHub API."""
        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--latest"])

        assert result.exit_code == 0
        assert SNAPSHOT_TAG in result.output
        assert "Published: 2026-07-07T12:00:00Z" in result.output
        assert SNAPSHOT_DB_ASSET in result.output
        assert SNAPSHOT_SHA_ASSET in result.output
        assert "MB" in result.output  # asset size formatting

    def test_latest_uses_hardcoded_repo(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--latest`` queries the hardcoded repo path on GitHub API."""
        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--latest"])

        assert result.exit_code == 0
        assert SNAPSHOT_TAG in result.output

    def test_latest_api_404(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--latest`` shows informative message on 404 (no snapshot release)."""
        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, status=404, body=b"Not Found")
            result = runner.invoke(cli, ["db", "snapshot", "--latest"])

        assert result.exit_code == 0
        assert "No snapshot release found" in result.output

    def test_latest_api_non_200(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--latest`` handles non-200 response from GitHub API."""
        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, status=500, body=b"Server Error")
            result = runner.invoke(cli, ["db", "snapshot", "--latest"])

        assert result.exit_code == 0
        assert "Error" in result.output
        assert "500" in result.output

    def test_latest_api_client_error(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--latest`` handles aiohttp.ClientError from GitHub API."""
        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(
                API_TAGS_URL,
                exception=aiohttp.ClientError("Connection refused"),
            )
            result = runner.invoke(cli, ["db", "snapshot", "--latest"])

        assert result.exit_code == 0
        assert "Error" in result.output


# ============================================================================
# TestDbSnapshotVerify — ``pkgd db snapshot --verify``
# ============================================================================


class TestDbSnapshotVerify:
    """Tests for the ``--verify`` flag on ``db snapshot``."""

    def test_verify_missing_db(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--verify`` exits 1 with message when no database exists."""
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: tmp_path / "nonexistent.db",
        )
        result = runner.invoke(cli, ["db", "snapshot", "--verify"])
        assert result.exit_code == 1
        assert "No local database" in result.output

    def test_verify_ok(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--verify`` prints SHA256 and reports integrity OK for a healthy DB."""
        db_path = tmp_path / "test.db"
        db_path.write_text("fake database content for hashing")

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (42,)
        monkeypatch.setattr("pkg_defender.db.schema.init_db", lambda path: mock_conn)

        result = runner.invoke(cli, ["db", "snapshot", "--verify"])
        assert result.exit_code == 0
        assert "SHA256" in result.output
        assert "integrity: OK" in result.output

    def test_verify_integrity_fail(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--verify`` exits 7 when integrity check raises."""
        db_path = tmp_path / "corrupt.db"
        db_path.write_text("some content")

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)
        monkeypatch.setattr(
            "pkg_defender.db.schema.init_db",
            lambda path: (_ for _ in ()).throw(Exception("Corrupt database")),
        )

        result = runner.invoke(cli, ["db", "snapshot", "--verify"])
        assert result.exit_code == 7
        assert "FAILED" in result.output


# ============================================================================
# TestDbSnapshotDownload — ``pkgd db snapshot --download``
# ============================================================================


class TestDbSnapshotDownload:
    """Tests for the ``--download`` flag on ``db snapshot``."""

    GZ_DATA = _gzip_bytes(b"mock database payload")

    # ---- Custom URL path ---------------------------------------------------

    def test_download_custom_url_success(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: download + atomic write + schema verify succeeds."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )

        expected_sha = _expected_sha_hex(self.GZ_DATA)
        sha_body = f"{expected_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "SHA256 verified" in result.output
        assert "Snapshot updated successfully" in result.output
        assert db_path.exists()

    def test_download_custom_url_db_exists_no_force(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: existing DB without ``--force`` skips with message."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )
        db_path.write_text("existing database")

        expected_sha = _expected_sha_hex(self.GZ_DATA)
        sha_body = f"{expected_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "already exists" in result.output
        assert "Use --force" in result.output

    def test_download_custom_url_with_force(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: existing DB with ``--force`` proceeds (backup + write)."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )
        db_path.write_text("old database")

        expected_sha = _expected_sha_hex(self.GZ_DATA)
        sha_body = f"{expected_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download", "--force"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output

    def test_download_custom_url_with_force_trash_fallback(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: trash fails, falls back to rename."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )
        db_path.write_text("old database")
        # Make ``subprocess.run(["trash", ...])`` fail → fallback to rename
        mock_run = MagicMock(side_effect=FileNotFoundError("No trash command"))
        monkeypatch.setattr(
            "pkg_defender.cli.commands.db.subprocess.run",
            mock_run,
        )

        expected_sha = _expected_sha_hex(self.GZ_DATA)
        sha_body = f"{expected_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download", "--force"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output
        # The old file should have been renamed to .db.backup
        assert (db_path.parent / "threats.db.backup").exists()

    def test_download_custom_url_http_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: non-200 HTTP response triggers error message."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=CUSTOM_URL)

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, status=404, body=b"Not Found")
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error" in result.output
        assert "404" in result.output

    def test_download_custom_url_client_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: aiohttp.ClientError is caught and reported."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=CUSTOM_URL)

        with aioresponses.aioresponses() as m:
            m.get(
                CUSTOM_URL,
                exception=aiohttp.ClientError("Connection timeout"),
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error downloading" in result.output

    def test_download_custom_url_error_verifying(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: init_db raises during verify step."""
        import aioresponses

        _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )
        # Override the init_db mock to raise
        monkeypatch.setattr(
            "pkg_defender.db.schema.init_db",
            lambda path: (_ for _ in ()).throw(Exception("Corrupt download")),
        )

        expected_sha = _expected_sha_hex(self.GZ_DATA)
        sha_body = f"{expected_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error verifying database" in result.output

    def test_download_custom_url_sha_mismatch(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: SHA256 mismatch fails and DB is NOT written."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )

        wrong_sha = "0" * 64
        sha_body = f"{wrong_sha}  snapshot.db.gz".encode()

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, body=sha_body, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "FAILED" in result.output
        assert not db_path.exists(), "DB must NOT be written on SHA mismatch"

    def test_download_custom_url_sha_fetch_http_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: SHA file 404 is a hard error — DB not written."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(CUSTOM_URL_SHA256, status=404, body=b"Not Found")
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error" in result.output
        assert "404" in result.output
        assert not db_path.exists(), "DB must NOT be written when SHA fetch fails"

    def test_download_custom_url_sha_fetch_client_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom URL: SHA fetch ClientError is a hard error — DB not written."""
        import aiohttp
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=CUSTOM_URL,
        )

        with aioresponses.aioresponses() as m:
            m.get(CUSTOM_URL, body=self.GZ_DATA, status=200)
            m.get(
                CUSTOM_URL_SHA256,
                exception=aiohttp.ClientError("SHA server timeout"),
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error" in result.output
        assert not db_path.exists(), "DB must NOT be written when SHA fetch fails"

    # ---- GitHub API path ---------------------------------------------------

    def test_download_github_api_success(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: full flow with SHA256 verification succeeds."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )

        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "SHA256 verified" in result.output
        assert "Snapshot updated successfully" in result.output
        assert db_path.exists()

    def test_download_github_api_sha_mismatch(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: SHA256 mismatch fails and reports the error."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )

        wrong_sha = "0" * 64

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{wrong_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "FAILED" in result.output
        assert not db_path.exists(), "DB should not be written on SHA mismatch"

    def test_download_github_api_http_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: non-200 on DB asset download."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=None)

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, status=500, body=b"Server Error")
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error" in result.output
        assert "500" in result.output

    def test_download_github_api_client_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: aiohttp.ClientError on DB asset download."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=None)

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(
                DB_ASSET_URL,
                exception=aiohttp.ClientError("Connection reset"),
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error downloading" in result.output

    def test_download_github_api_sha_http_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: non-200 on SHA download still succeeds (skips verify)."""
        import aioresponses

        _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(SHA_ASSET_URL, status=404)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Output: {result.output}"
        # When SHA download fails, expected_sha = None → no verification
        # message printed (neither success nor failure). The download proceeds
        # without a misleading success indicator.
        assert "Snapshot updated successfully" in result.output

    def test_download_github_api_sha_client_error(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: aiohttp.ClientError on SHA download."""
        import aioresponses

        _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                exception=aiohttp.ClientError("SHA server timeout"),
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output

    def test_download_github_api_db_exists_no_force(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: existing DB without ``--force`` skips."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )
        db_path.write_text("existing")
        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "already exists" in result.output

    def test_download_github_api_with_force(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: existing DB with ``--force`` proceeds with backup."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )
        db_path.write_text("old database")
        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download", "--force"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output

    def test_download_github_api_error_verifying(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: ``init_db`` raises during verify step."""
        import aioresponses

        _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )
        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        # Replace the normal mock_init_db with one that raises
        monkeypatch.setattr(
            "pkg_defender.db.schema.init_db",
            lambda path: (_ for _ in ()).throw(Exception("Corrupt download")),
        )

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Error verifying database" in result.output

    def test_download_github_api_backup_trash_fallback(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: trash fails, falls back to rename."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )
        db_path.write_text("old database")
        mock_run = MagicMock(side_effect=FileNotFoundError("No trash command"))
        monkeypatch.setattr(
            "pkg_defender.cli.commands.db.subprocess.run",
            mock_run,
        )
        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download", "--force"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output
        # Original file should be renamed to .db.backup
        assert (db_path.parent / "threats.db.backup").exists()

    def test_download_github_api_atomic_write_failure(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct URL: atomic write exception cleans up temp file."""
        import aioresponses

        _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )
        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        tmp_file = tmp_path / ".snapshot.fail.tmp"
        monkeypatch.setattr("tempfile.mkstemp", lambda *a, **kw: (999, str(tmp_file)))

        # Make os.fdopen raise so the atomic write exception fires
        monkeypatch.setattr("os.fdopen", lambda fd, mode: (_ for _ in ()).throw(OSError("Bad fd")))
        unlink_calls: list[str] = []
        monkeypatch.setattr("os.unlink", lambda path: unlink_calls.append(str(path)))

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code != 0, "Should exit with error on write failure"
        assert str(tmp_file) in unlink_calls, f"Temp file should be cleaned up: {unlink_calls}"

    def test_download_github_api_uses_hardcoded_repo(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--download`` uses hardcoded repo path when no custom URL is set."""
        _setup_download_mocks(monkeypatch, tmp_path, custom_url=None)

        import aioresponses

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            # Mock the DB download — SHA is computed on compressed data
            db_content = b"fake-sqlite-content"
            compressed = gzip.compress(db_content)
            m.get(DB_ASSET_URL, body=compressed)
            # Mock the SHA256 download (hash of compressed bytes)
            sha_content = hashlib.sha256(compressed).hexdigest()
            sha_body = f"{sha_content}  {SNAPSHOT_DB_ASSET}".encode()
            m.get(SHA_ASSET_URL, body=sha_body)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Snapshot updated" in result.output

    def test_download_github_api_uses_correct_snapshot_urls(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: download uses /releases/tags/snapshot-latest, not /releases/latest.

        The API endpoint must be called — if the code ever reverts to using
        /releases/latest or constructs direct URLs without an API call, this
        test catches it via the aioresponses assertion at the end.

        Only the correct API endpoint URL is mocked. If the old/wrong code
        path tries /releases/latest, aioresponses raises ConnectionError for
        the unmocked URL, causing the test to fail. Additionally, the
        ``m.count(API_TAGS_URL)`` assertion below explicitly verifies the
        API endpoint was contacted.
        """
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,  # Forces GitHub API discovery path
        )

        expected_sha = hashlib.sha256(self.GZ_DATA).hexdigest()

        with aioresponses.aioresponses() as m:
            # Only the CORRECT API endpoint is mocked
            m.get(API_TAGS_URL, payload=RELEASE_DATA, status=200)
            # DB and SHA download URLs must also be mocked
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            # SHA asset — must be the snapshot-latest URL
            m.get(
                SHA_ASSET_URL,
                body=f"{expected_sha}  {SNAPSHOT_DB_ASSET}".encode(),
                status=200,
            )
            # If old code tries /releases/latest, it hits an unmocked URL
            # and aioresponses raises ConnectionError → test failure
            result = runner.invoke(cli, ["db", "snapshot", "--download"])
            api_calls = [str(url) for (method, url) in m.requests]
            assert API_TAGS_URL in api_calls, (
                f"API endpoint /releases/tags/snapshot-latest was not called. Called URLs: {api_calls}"
            )

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "SHA256 verified" in result.output
        assert "Snapshot updated successfully" in result.output
        assert db_path.exists()

    def test_download_github_api_no_browser_url(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GitHub API: asset lacks ``browser_download_url`` prints error."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=None)

        no_url_release: dict[str, Any] = {
            "tag_name": "snapshot-latest",
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "name": "threats-latest.db.gz",
                    "size": 500,
                    # No browser_download_url key
                },
            ],
        }

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=no_url_release, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "Could not get download URL" in result.output

    def test_download_github_api_no_db_asset(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GitHub API: release missing .db.gz asset prints error."""
        import aioresponses

        _setup_download_mocks(monkeypatch, tmp_path, custom_url=None)

        no_db_release: dict[str, Any] = {
            "tag_name": "snapshot-latest",
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "name": "README.txt",
                    "size": 500,
                    "browser_download_url": "https://example.com/readme.txt",
                },
            ],
        }

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=no_db_release, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0
        assert "No database asset" in result.output

    def test_download_github_api_no_sha_asset(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GitHub API: release without .sha256 still succeeds (skip verify)."""
        import aioresponses

        db_path = _setup_download_mocks(
            monkeypatch,
            tmp_path,
            custom_url=None,
        )

        release_no_sha: dict[str, Any] = {
            "tag_name": "snapshot-latest",
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "name": "threats-latest.db.gz",
                    "size": 500000,
                    "browser_download_url": DB_ASSET_URL,
                },
            ],
        }

        with aioresponses.aioresponses() as m:
            m.get(API_TAGS_URL, payload=release_no_sha, status=200)
            m.get(DB_ASSET_URL, body=self.GZ_DATA, status=200)
            result = runner.invoke(cli, ["db", "snapshot", "--download"])

        assert result.exit_code == 0, f"Output: {result.output}"
        assert "Snapshot updated successfully" in result.output
        assert db_path.exists()


# ============================================================================
# TestDbVerify — ``pkgd db verify`` command
# ============================================================================


class TestDbVerify:
    """Tests for the ``db verify`` command."""

    def test_verify_no_db(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` exits 1 when database file does not exist."""
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: tmp_path / "nonexistent.db",
        )
        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_verify_connection_fails(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` exits 1 when get_connection raises."""
        db_path = tmp_path / "test.db"
        db_path.write_text("not a real sqlite db")
        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)
        monkeypatch.setattr(
            "pkg_defender.db.schema.get_connection",
            lambda path: (_ for _ in ()).throw(Exception("Can't open")),
        )
        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "Could not open" in result.output

    def test_verify_healthy_db(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` reports all summary fields for a healthy database."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "healthy.db"
        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, "
            "confidence, source) VALUES ('t-1', 'npm', 'bad', 'CRITICAL', 0.9, 'osv')",
        )
        conn.execute(
            "INSERT INTO feed_state (feed_name, last_sync, status) VALUES ('osv', '2026-05-29 10:00:00', 'idle')",
        )
        conn.commit()
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0, f"Output: {result.output}"
        assert "PRAGMA integrity_check: ok" in result.output
        assert "Threat records:" in result.output
        assert "Last sync:" in result.output
        assert "File size:" in result.output
        assert "Schema version:" in result.output

    def test_verify_integrity_failed(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` reports FAILED when PRAGMA indicates corruption."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "corrupt.db"
        conn = init_db(db_path)
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        data = bytearray(db_path.read_bytes())
        page_size = int.from_bytes(data[16:18], "big")

        for page_num in range(1, len(data) // page_size):
            offset = page_num * page_size
            page_type = data[offset]
            if page_type in (0x0A, 0x02):  # index leaf/interior page
                cell_count = int.from_bytes(data[offset + 3 : offset + 5], "big")
                data[offset + 3 : offset + 5] = (cell_count + 1).to_bytes(2, "big")
                db_path.write_bytes(data)
                break
        else:
            pytest.fail("No index page found to corrupt in test database")

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == _EXIT_DB_ERROR
        assert "FAILED" in result.output or "Error" in result.output

    def test_verify_integrity_detected(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` prints corruption details when PRAGMA fails.

        When integrity_ok is False, the code iterates over integrity_rows
        and prints each corruption message, then raises SystemExit(1).
        """
        db_path = tmp_path / "test.db"
        db_path.write_text("dummy content")
        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [
            ("not ok", "index corrupted in table threats"),
        ]
        monkeypatch.setattr(
            "pkg_defender.db.schema.get_connection",
            lambda path: mock_conn,
        )

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "FAILED" in result.output
        assert "Corruption" in result.output

    def test_verify_threat_query_fails(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` shows N/A when threats table is missing."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "no_threats.db"
        conn = init_db(db_path)
        conn.execute("DROP TABLE threats")
        conn.commit()
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        assert "N/A" in result.output
        assert "threats table" in result.output

    def test_verify_sync_query_fails(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` shows N/A for last sync when feed_state is missing."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "no_sync.db"
        conn = init_db(db_path)
        conn.execute("DROP TABLE feed_state")
        conn.commit()
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        assert "N/A" in result.output
        assert "feed_state table" in result.output

    def test_verify_file_size_mb(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` formats file size in MB for large DBs."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "big.db"
        conn = init_db(db_path)
        conn.close()

        with open(db_path, "ab") as f:
            f.write(b"\x00" * (1024 * 1024 + 1))

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        assert "MB" in result.output

    def test_verify_all_failing_queries(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` shows N/A for all query fields when tables are gone."""
        from pkg_defender.db.schema import init_db

        db_path = tmp_path / "bare.db"
        conn = init_db(db_path)
        for tbl in ("threats", "feed_state", "db_metadata", "schema_version"):
            conn.execute(f"DROP TABLE IF EXISTS {tbl}")
        conn.commit()
        conn.close()

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 0
        # Count occurrences of "N/A" — should be at least 2 (threats, sync)
        assert result.output.count("N/A") >= 2, f"Expected at least 2 'N/A' fields, got:\n{result.output}"

    def test_verify_general_exception(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``db verify`` exits 1 on unexpected error during verification."""
        db_path = tmp_path / "failing.db"
        db_path.write_text("data")
        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)

        mock_conn = MagicMock()
        mock_conn.execute.side_effect = Exception("Unexpected database error")
        monkeypatch.setattr(
            "pkg_defender.db.schema.get_connection",
            lambda path: mock_conn,
        )

        result = runner.invoke(cli, ["db", "verify"])
        assert result.exit_code == 1
        assert "Error during verification" in result.output
