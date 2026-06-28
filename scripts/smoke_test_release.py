#!/usr/bin/env python3
"""Post-release smoke test: verify pkgd blocks a known malicious package.

Called from the release pipeline's smoke-test job (release.yml) after
publishing to PyPI. Uses only stdlib + the installed pkg_defender package
— no pytest or test dependencies.

Seeds a temp SQLite database with a blocking threat for requests==1.0.0,
then runs ``pkgd pip install requests==1.0.0`` via subprocess and asserts
exit code 4 (EXIT_THREAT_DETECTED) with "BLOCKED" in stderr.

Usage:
    python scripts/smoke_test_release.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _create_seeded_db(db_path: Path) -> None:
    """Create and seed a threat database for smoke testing."""
    from pkg_defender.db.schema import init_db

    conn = init_db(db_path)

    # Seed feed_state to skip network sync on first use
    conn.execute(
        "INSERT OR REPLACE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
        ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
    )

    # Seed version_timestamps 30 days ago to bypass pip's 5-day cooldown window
    # Ecosystem must be "pypi" — dispatcher._check_threats() uses the adapter's
    # ecosystem attribute (PyPIUnifiedAdapter.ecosystem == "pypi"), not
    # resolve_ecosystem("pip") which now correctly returns "pypi".
    conn.execute(
        "INSERT OR IGNORE INTO version_timestamps "
        "(ecosystem, package_name, version, publish_time, timestamp_type) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "pypi",
            "requests",
            "1.0.0",
            (datetime.now(UTC) - timedelta(days=30)).isoformat(),
            "verified",
        ),
    )

    # Seed blocking threat for requests==1.0.0
    # Ecosystem must be "pypi" — same adapter ecosystem resolution as above.
    conn.execute(
        """INSERT OR IGNORE INTO threats
        (id, ecosystem, package_name, affected_versions, severity, confidence,
         source, source_id, summary, first_seen, last_seen, hit_count, is_malicious)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "smoke-test:blocking-001",
            "pypi",
            "requests",
            '["1.0.0"]',
            "CRITICAL",
            0.95,
            "osv",
            "OSV-SMOKE-001",
            "Smoke test blocking threat for requests 1.0.0",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            1,
            1,
        ),
    )
    conn.commit()
    conn.close()


def main() -> None:
    """Run the smoke test."""
    db_dir = Path(tempfile.mkdtemp())
    db_path = db_dir / "threats.db"

    try:
        _create_seeded_db(db_path)

        # Run pkgd against the seeded database
        env = {**os.environ, "PKGD_DATABASE_PATH": str(db_dir)}
        pkgd_bin = str(Path(sys.executable).parent / "pkgd")
        result = subprocess.run(
            [pkgd_bin, "pip", "install", "requests==1.0.0"],
            capture_output=True,
            text=True,
            env=env,
        )

        assert result.returncode == 4, (
            f"Expected exit code 4 (EXIT_THREAT_DETECTED), got {result.returncode}\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )
        assert "BLOCKED" in result.stderr, f"Expected 'BLOCKED' in stderr. Got:\n{result.stderr[:500]}"

        print(f"✅ Threat blocking verified. Exit code: {result.returncode}")
    except Exception:
        raise
    finally:
        # Clean up temp directory
        import shutil

        shutil.rmtree(db_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
