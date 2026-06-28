"""End-to-end test for scoring threshold and CLI blocking pipeline.

Validates the complete pipeline from Click CLI invocation through to
exit code and output content:
1. Seed a known threat record in the test database
2. Invoke via CliRunner as ``pkgd pip install requests==1.0.0``
3. Assert exit code 4 (EXIT_THREAT_DETECTED)
4. Assert "BLOCKED" appears in stderr output
5. Assert "requests" appears in stderr output

Unlike test_ci_e2e.py, this test does NOT mock _print_threat_block —
it validates real output content. Unlike test_smoke_e2e.py, this test
goes through the full Click CLI path via runner.invoke().
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_THREAT_DETECTED
from pkg_defender.cli.main import cli


class TestScoringEndToEnd:
    """Full end-to-end test for threat blocking through the Click CLI."""

    # ------------------------------------------------------------------
    # Helper: seed a blocking threat in the test DB
    # ------------------------------------------------------------------

    def _seed_threat_db(self, db_path: Path) -> None:
        """Seed a single blocking threat for requests==1.0.0.

        The threat is CRITICAL severity from osv source. The scoring
        formula produces: 1.0 (CRITICAL) * 0.9 (osv) * ~0.99 (recency)
        ≈ 0.89 — well above the 0.3 BLOCK_SCORE_THRESHOLD.

        Also seeds feed_state to prevent _ensure_db_fresh() from
        triggering real network sync.
        """
        import sqlite3

        conn = sqlite3.connect(str(db_path))

        # Seed feed_state so _ensure_db_fresh() skips network sync
        conn.execute(
            "INSERT OR IGNORE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
            ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
        )

        # Seed a blocking threat for requests==1.0.0
        # Note: ecosystem="pypi" because the pip adapter class
        # (PyPIUnifiedAdapter) defines ecosystem: str = "pypi" in
        # pypi_unified.py:33. When routed through the real CLI path,
        # _check_threats() reads the adapter's ecosystem attribute,
        # so the threat DB query uses "pypi", not "pip".
        conn.execute(
            """INSERT OR IGNORE INTO threats
            (id, ecosystem, package_name, affected_versions,
             severity, confidence, source, source_id, summary,
             first_seen, last_seen, hit_count, is_malicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "test:p08-001",
                "pypi",
                "requests",
                '["1.0.0"]',
                "CRITICAL",
                0.95,
                "osv",
                "OSV-P08-001",
                "P0.8 end-to-end blocking threat",
                (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
                1,
                1,
            ),
        )

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Helper: patch get_db_path at all required module levels
    # ------------------------------------------------------------------

    def _patch_db_paths(
        self,
        monkeypatch: pytest.MonkeyPatch,
        db_path: Path,
    ) -> None:
        """Patch get_db_path at the two targets not covered by isolated_env.

        isolated_env patches:
          - pkg_defender.cli.main.get_db_path
          - pkg_defender.cli.common.get_db_path
          - pkg_defender.config.settings.get_db_path
          - pkg_defender.cli.commands.{intel,status,audit,...}.get_db_path

        Additional targets needed (not covered by isolated_env):
          - pkg_defender.config.get_db_path — re-export in config/__init__.py,
            used by dispatcher function-body imports
          - pkg_defender.cli.exec.get_db_path — module-level import at
            exec.py:22 (from pkg_defender.config import get_db_path)
        """
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args: db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda *args: db_path,
        )

    # ------------------------------------------------------------------
    # Helper: prevent network calls during async caching
    # ------------------------------------------------------------------

    def _patch_dispatcher_cache(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Replace _cache_version_timestamps_async with a no-op.

        The dispatcher's async caching step would make real network
        calls to PyPI to fetch publish timestamps, overwriting seeded
        data. This no-op ensures the code path runs without network.
        """

        async def _noop_cache(_self: Any, _parsed: Any) -> None:
            pass

        monkeypatch.setattr(
            "pkg_defender.cli.dispatcher.ManagerDispatcher._cache_version_timestamps_async",
            _noop_cache,
        )

    def _patch_feed_aggregator(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Replace FeedAggregator.sync_all with a no-op.

        Prevents real network calls during _ensure_db_fresh() which
        triggers sync_all() when ecosystems are resolved.
        """

        async def _noop_sync_all(
            _self: Any,
            ecosystems: list[str] | None = None,  # noqa: ARG001
            **kwargs: Any,
        ) -> None:
            pass

        monkeypatch.setattr(
            "pkg_defender.intel.aggregator.FeedAggregator.sync_all",
            _noop_sync_all,
        )

    # ------------------------------------------------------------------
    # Test: Full CLI threat block
    # ------------------------------------------------------------------

    def test_full_cli_threat_block(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A known threat seed must block through the real Click CLI.

        Full pipeline validated:
        1. runner.invoke(cli, ...) → Click parsing → ManagerGroup
        2. ManagerDispatcher resolved for "pip"
        3. _run_pre_install_check() → _check_threats()
        4. check_packages_batch() → score_threats() → 0.89 >= 0.3 → BLOCKED
        5. handle_blocked_command(THREAT) → _print_threat_block() → stderr
        6. sys.exit(EXIT_THREAT_DETECTED) → exit_code 4

        This test does NOT use --ci flag and does NOT mock
        _print_threat_block — both intentional. The goal is to validate
        the default (interactive) path with real output.
        """
        db_path = isolated_env["db_path"]
        self._patch_db_paths(monkeypatch, db_path)
        self._patch_dispatcher_cache(monkeypatch)
        self._patch_feed_aggregator(monkeypatch)
        self._seed_threat_db(db_path)

        result = runner.invoke(
            cli,
            ["pip", "install", "requests==1.0.0"],
            catch_exceptions=False,
        )

        # Exit code must be 4 (EXIT_THREAT_DETECTED)
        assert result.exit_code == EXIT_THREAT_DETECTED, (
            f"Expected exit code {EXIT_THREAT_DETECTED} (EXIT_THREAT_DETECTED), "
            f"got {result.exit_code}: {result.stderr[:500] if result.stderr else result.output[:500]}"
        )

        # Output must contain "BLOCKED" — _print_threat_block writes this to stderr
        stderr = result.stderr or ""
        assert "BLOCKED" in stderr, f"Expected 'BLOCKED' in stderr output. Got stderr:\n{stderr[:500]}"

        # Output must contain the blocked package name
        assert "requests" in stderr, f"Expected 'requests' in stderr output. Got stderr:\n{stderr[:500]}"
