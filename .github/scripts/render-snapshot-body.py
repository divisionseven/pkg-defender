#!/usr/bin/env python3
"""
Render the snapshot release body from a template file and a compressed SQLite
snapshot database (.db.gz). Substitutes placeholders in the template with stats
extracted from the database, then writes the rendered markdown to an output file.

Usage:
    python3 .github/scripts/render-snapshot-body.py \
        --template .github/release-templates/snapshot-body.md \
        --db threats-latest.db.gz \
        --output /tmp/snapshot-body.md

Exit codes:
    0   Success
    1   Template or database error
"""

import argparse
import gzip
import hashlib
import re
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from string import Template
from typing import Any

# ── Formatting helpers ───────────────────────────────────────────────────────


def _format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string (KB or MB)."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _format_number(n: int) -> str:
    """Format an integer with thousands-separator commas."""
    return f"{n:,}"


# ── Version detection ────────────────────────────────────────────────────────


def _get_pkgd_version() -> str:
    """Read pkg-defender version from ``pyproject.toml`` in the current directory.

    Returns:
        Version string (e.g. ``"1.0.0"``) or ``"unknown"`` if the file is
        missing or cannot be parsed.
    """
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        return "unknown"
    try:
        content = pyproject.read_text(encoding="utf-8")
        match = re.search(
            r'^version\s*=\s*"([^"]+)"',
            content,
            re.MULTILINE,
        )
        return match.group(1) if match else "unknown"
    except OSError:
        return "unknown"


# ── Hashing ──────────────────────────────────────────────────────────────────


def _compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hex digest of a file."""
    sha = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


# ── Database queries ─────────────────────────────────────────────────────────


def _query_threat_stats(db_path: Path) -> dict[str, Any]:
    """Connect to the decompressed SQLite database and extract threat stats.

    Args:
        db_path: Path to the decompressed SQLite database file.

    Returns:
        A dictionary with keys ``threat_count``, ``ecosystem_count``,
        ``ecosystem_rows``, and ``source_rows``.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check that the threats table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='threats'",
    )
    if cursor.fetchone() is None:
        conn.close()
        return {
            "threat_count": 0,
            "ecosystem_count": 0,
            "ecosystem_rows": "_No ecosystem data available._",
            "source_rows": "_No source data available._",
        }

    # Total threats
    cursor.execute("SELECT COUNT(*) FROM threats")
    threat_count: int = cursor.fetchone()[0]

    # By ecosystem (ordered by count descending)
    cursor.execute(
        "SELECT ecosystem, COUNT(*) as c FROM threats GROUP BY ecosystem ORDER BY c DESC",
    )
    ecosystems = cursor.fetchall()
    ecosystem_count = len(ecosystems)
    if ecosystems:
        ecosystem_rows = "\n".join(f"| {row['ecosystem']} | {_format_number(row['c'])} |" for row in ecosystems)
    else:
        ecosystem_rows = "_No ecosystem data available._"

    # By source — check column existence first
    cursor.execute("PRAGMA table_info(threats)")
    columns = [row[1] for row in cursor.fetchall()]

    if "source" in columns:
        cursor.execute(
            "SELECT source, COUNT(*) as c FROM threats GROUP BY source ORDER BY c DESC",
        )
        sources = cursor.fetchall()
        if sources:
            source_rows = "\n".join(f"| {row['source']} | {_format_number(row['c'])} |" for row in sources)
        else:
            source_rows = "_No source data available._"
    else:
        source_rows = "_Source column not available._"

    conn.close()

    return {
        "threat_count": threat_count,
        "ecosystem_count": ecosystem_count,
        "ecosystem_rows": ecosystem_rows,
        "source_rows": source_rows,
    }


# ── Core renderer ────────────────────────────────────────────────────────────


def render_snapshot_body(
    template_path: Path | str,
    db_path: Path | str,
    output_path: Path | str,
    pkgd_version: str | None = None,
) -> str:
    """Render the snapshot release body from template and database.

    Args:
        template_path: Path to the markdown template.
        db_path: Path to the compressed ``.db.gz`` snapshot file.
        output_path: Path for the rendered markdown output.
        pkgd_version: Override version (``None`` = auto-detect from
            ``pyproject.toml`` in CWD).

    Returns:
        The rendered markdown string.

    Raises:
        FileNotFoundError: The template or database file is missing, or the
            database cannot be opened/decompressed.
    """
    template_path = Path(template_path)
    db_path = Path(db_path)
    output_path = Path(output_path)

    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    if not db_path.exists():
        raise FileNotFoundError(f"Snapshot database not found: {db_path}")

    # ── Read template ────────────────────────────────────────────────────
    template_content = template_path.read_text(encoding="utf-8")

    # ── Version ──────────────────────────────────────────────────────────
    resolved_version = _get_pkgd_version() if pkgd_version is None else pkgd_version

    # ── File metadata ────────────────────────────────────────────────────
    sha256_digest = _compute_sha256(db_path)
    db_size = db_path.stat().st_size
    db_size_compressed = _format_size(db_size)

    # ── Build timestamp ──────────────────────────────────────────────────
    build_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    # ── Decompress and query database ────────────────────────────────────
    tmp_db: Path | None = None
    try:
        with (
            gzip.open(db_path, "rb") as gz,
            tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".db",
            ) as tmp,
        ):
            tmp_db = Path(tmp.name)
            tmp.write(gz.read())

        stats = _query_threat_stats(tmp_db)

    except (gzip.BadGzipFile, sqlite3.DatabaseError, OSError) as exc:
        raise FileNotFoundError(
            f"Failed to open or query snapshot database '{db_path}': {exc}",
        ) from exc
    finally:
        if tmp_db is not None and tmp_db.exists():
            tmp_db.unlink()

    # ── Build substitution dictionary ────────────────────────────────────
    substitutions = {
        "build_time": build_time,
        "pkgd_version": resolved_version,
        "threat_count": _format_number(stats["threat_count"]),
        "ecosystem_count": str(stats["ecosystem_count"]),
        "db_size_compressed": db_size_compressed,
        "sha256": sha256_digest,
        "ecosystem_breakdown": stats["ecosystem_rows"],
        "source_breakdown": stats["source_rows"],
    }

    # ── Render and write output ──────────────────────────────────────────
    rendered = Template(template_content).safe_substitute(substitutions)
    output_path.write_text(rendered, encoding="utf-8")

    return rendered


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    """Parse CLI arguments and run the renderer."""
    parser = argparse.ArgumentParser(
        description="Render the snapshot release body from template and database.",
    )
    parser.add_argument(
        "--template",
        required=True,
        help="Path to the markdown template file",
    )
    parser.add_argument(
        "--db",
        required=True,
        help="Path to the compressed .db.gz snapshot file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the rendered markdown output",
    )
    parser.add_argument(
        "--pkgd-version",
        default=None,
        help="Override pkg-defender version (auto-detected from pyproject.toml if omitted)",
    )
    args = parser.parse_args()

    try:
        render_snapshot_body(
            template_path=args.template,
            db_path=args.db,
            output_path=args.output,
            pkgd_version=args.pkgd_version,
        )
    except FileNotFoundError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
