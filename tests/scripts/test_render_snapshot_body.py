"""Tests for .github/scripts/render-snapshot-body.py.

The renderer reads a compressed SQLite snapshot database and a
``string.Template``-based template, then writes rendered markdown to an
output file.
"""

from __future__ import annotations

import gzip
import importlib.util
import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from typing import Any

# ---------------------------------------------------------------------------
# Module under test — loaded via importlib because .github/scripts/ is not a
# package.
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).parents[2] / ".github" / "scripts"
_SCRIPT_PATH = _SCRIPT_DIR / "render-snapshot-body.py"

_spec = importlib.util.spec_from_file_location(
    "render_snapshot_body",
    _SCRIPT_PATH,
)
if _spec is None:
    raise ImportError(f"Could not create module spec for {_SCRIPT_PATH}")
if _spec.loader is None:
    raise ImportError(f"Module spec for {_SCRIPT_PATH} has no loader")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
render_snapshot_body: Any = _module.render_snapshot_body

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_db(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temp SQLite DB with the ``threats`` table and known data.

    Inserts 5 npm records (source: osv), 3 pypi records (source: osv), and
    2 cargo records (source: ghsa). Cleans up via ``os.unlink()`` on teardown.
    """
    db_path = tmp_path / "threats.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE threats ("
        "  ecosystem TEXT,"
        "  source TEXT,"
        "  ingested_at TEXT,"
        "  pkg_name TEXT,"
        "  severity TEXT,"
        "  published_at TEXT"
        ")",
    )

    records: list[tuple[str, str, str, str, str | None, str | None]] = [
        # 5 npm records (source: osv)
        *[("npm", "osv", "2026-01-01T00:00:00", f"npm-pkg-{i}", "CRITICAL", "2026-01-01T00:00:00") for i in range(5)],
        # 3 pypi records (source: osv)
        *[("pypi", "osv", "2026-02-01T00:00:00", f"pypi-pkg-{i}", "HIGH", "2026-02-01T00:00:00") for i in range(3)],
        # 2 cargo records (source: ghsa)
        *[("cargo", "ghsa", "2026-03-01T00:00:00", f"cargo-pkg-{i}", None, None) for i in range(2)],
    ]

    conn.executemany(
        "INSERT INTO threats (ecosystem, source, ingested_at, pkg_name, severity, published_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        records,
    )
    conn.commit()
    conn.close()

    yield db_path

    if db_path.exists():
        os.unlink(str(db_path))


@pytest.fixture
def compressed_db(sample_db: Path, tmp_path: Path) -> Generator[Path, None, None]:
    """Compress ``sample_db`` to ``threats.db.gz``.

    Cleans up only the ``.db.gz`` file on teardown; ``.db`` cleanup is
    handled by ``sample_db`` to avoid double-unlink.
    """
    gz_path = tmp_path / "threats.db.gz"
    with gzip.open(gz_path, "wb") as gz:
        gz.write(sample_db.read_bytes())

    yield gz_path

    if gz_path.exists():
        gz_path.unlink()


@pytest.fixture
def empty_db(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a compressed SQLite DB with the ``threats`` table but 0 rows.

    Cleanup is automatic via ``tmp_path``.
    """
    db_path = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE threats ("
        "  ecosystem TEXT,"
        "  source TEXT,"
        "  ingested_at TEXT,"
        "  pkg_name TEXT,"
        "  severity TEXT,"
        "  published_at TEXT"
        ")",
    )
    conn.commit()
    conn.close()

    gz_path = tmp_path / "empty.db.gz"
    with gzip.open(gz_path, "wb") as gz:
        gz.write(db_path.read_bytes())

    yield gz_path
    # Cleanup handled by tmp_path — no explicit teardown needed.


@pytest.fixture
def minimal_template(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a minimal template file with all expected substitution variables."""
    template_path = tmp_path / "template.md"
    template_path.write_text(
        "# Snapshot Release\n\n"
        "Build time: $build_time\n"
        "Version: $pkgd_version\n"
        "Total threats: $threat_count\n"
        "Ecosystems: $ecosystem_count\n"
        "DB size: $db_size_compressed\n"
        "SHA256: $sha256\n"
        "\n"
        "## Ecosystem Breakdown\n"
        "$ecosystem_breakdown\n"
        "\n"
        "## Source Breakdown\n"
        "$source_breakdown\n",
        encoding="utf-8",
    )

    yield template_path
    # Cleanup handled by tmp_path — no explicit teardown needed.


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRenderSnapshotBody:
    """Tests for render_snapshot_body()."""

    def test_render_with_real_data(
        self,
        compressed_db: Path,
        minimal_template: Path,
        tmp_path: Path,
    ) -> None:
        """Render with a populated database and verify expected values."""
        # Arrange
        output_path = tmp_path / "output.md"

        # Act
        render_snapshot_body(
            template_path=minimal_template,
            db_path=compressed_db,
            output_path=output_path,
        )

        # Assert
        content = output_path.read_text(encoding="utf-8")

        # Total count
        assert "10" in content
        # Ecosystem names
        assert "npm" in content
        assert "pypi" in content
        assert "cargo" in content
        # Source names
        assert "osv" in content
        assert "ghsa" in content
        # Per-ecosystem counts
        assert "| npm | 5 |" in content
        assert "| pypi | 3 |" in content
        assert "| cargo | 2 |" in content
        # Per-source counts
        assert "| osv | 8 |" in content
        assert "| ghsa | 2 |" in content

    def test_render_empty_db(
        self,
        empty_db: Path,
        minimal_template: Path,
        tmp_path: Path,
    ) -> None:
        """Render with an empty database and verify zero counts."""
        # Arrange
        output_path = tmp_path / "output.md"

        # Act
        render_snapshot_body(
            template_path=minimal_template,
            db_path=empty_db,
            output_path=output_path,
        )

        # Assert
        content = output_path.read_text(encoding="utf-8")
        assert "Total threats: 0" in content
        assert "Ecosystems: 0" in content

    def test_render_fallback_version(
        self,
        compressed_db: Path,
        minimal_template: Path,
        tmp_path: Path,
    ) -> None:
        """Render with ``pkgd_version=None`` and verify auto-detection works.

        The real ``pyproject.toml`` at the project root should be found,
        so the version should not be ``"unknown"``.
        """
        # Arrange
        output_path = tmp_path / "output.md"

        # Act — pkgd_version=None triggers auto-detection from pyproject.toml
        render_snapshot_body(
            template_path=minimal_template,
            db_path=compressed_db,
            output_path=output_path,
            pkgd_version=None,
        )

        # Assert
        content = output_path.read_text(encoding="utf-8")
        assert "Version:" in content

        # Extract the version value
        match = re.search(r"Version:\s*(\S+)", content)
        assert match is not None, "Version line not found in output"
        version = match.group(1)

        # Must not be "unknown" since pyproject.toml is accessible
        assert version != "unknown"
        # Must contain at least one digit (e.g., "1.0.0")
        assert any(c.isdigit() for c in version)

    def test_render_output_is_valid_utf8(
        self,
        compressed_db: Path,
        minimal_template: Path,
        tmp_path: Path,
    ) -> None:
        """Render and verify the output file is valid UTF-8 with all sections."""
        # Arrange
        output_path = tmp_path / "output.md"

        # Act
        render_snapshot_body(
            template_path=minimal_template,
            db_path=compressed_db,
            output_path=output_path,
        )

        # Assert — read as UTF-8 (raises UnicodeDecodeError if invalid)
        content = output_path.read_text(encoding="utf-8")

        # Also verify from raw bytes (catches BOM/stray bytes issues)
        raw_bytes = output_path.read_bytes()
        raw_bytes.decode("utf-8")

        # All expected template sections are present
        assert "# Snapshot Release" in content
        assert "Build time:" in content
        assert "Version:" in content
        assert "Total threats:" in content
        assert "Ecosystems:" in content
        assert "DB size:" in content
        assert "SHA256:" in content
        assert "Ecosystem Breakdown" in content
        assert "Source Breakdown" in content

        # Data values
        assert "10" in content
        assert "npm" in content
        assert "pypi" in content
        assert "cargo" in content
        assert "osv" in content
        assert "ghsa" in content


class TestRenderViaCLI:
    """Tests for the CLI entry point (``main()`` via subprocess)."""

    def test_render_via_cli(
        self,
        compressed_db: Path,
        minimal_template: Path,
        tmp_path: Path,
    ) -> None:
        """Invoke the script via ``subprocess.run`` and verify exit code 0."""
        # Arrange
        output_path = tmp_path / "output.md"

        # Act
        result = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT_PATH),
                "--template",
                str(minimal_template),
                "--db",
                str(compressed_db),
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
        )

        # Assert
        assert result.returncode == 0, f"CLI exited with code {result.returncode}: stderr={result.stderr!r}"
        assert output_path.exists(), "Output file was not created"
        assert output_path.stat().st_size > 0, "Output file is empty"
