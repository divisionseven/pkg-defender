"""End-to-end tests for --ci / --non-interactive flag through the full CLI path.

These tests exercise the complete invocation path from Click parsing
through to the dispatcher and exec module, unlike existing unit tests
that test individual layers in isolation.

Relevant code paths tested:
  - main.py:283-289  — --ci / --non-interactive flag parsing
  - main.py:344-347  — ctx.obj["ci"] = True; output_format = "json"
  - dispatcher.py:150-161 — ctx.obj merge into parsed.pkgd_flags
  - exec.py:224      — COOLDOWN guard: ci=True skips prompt
  - exec.py:143-170  — THREAT branch: ci flag NOT checked (intentional)
  - status.py:86     — reads ctx.obj.get("output_format") for JSON output
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli


class TestCiEndToEnd:
    """End-to-end tests verifying --ci flag behavior through the full CLI path.

    Each test uses runner.invoke(cli, [...]) to exercise the real Click
    invocation path with appropriate mocking for database and process
    isolation.
    """

    # ------------------------------------------------------------------
    # Helper: DB seeding
    # ------------------------------------------------------------------

    def _seed_db(
        self,
        db_path: Path,
        *,
        seed_cooldown: bool = True,
        seed_threat: bool = False,
    ) -> None:
        """Seed the test database with common test data.

        Args:
            db_path: Path to the test SQLite database.
            seed_cooldown: If True, seed a recent version_timestamp to
                trigger cooldown (1 hour ago < 7 day default window).
            seed_threat: If True, seed a matching threat to trigger the
                threat block path.
        """
        conn = sqlite3.connect(str(db_path))

        # Seed feed_state so _ensure_db_fresh() doesn't trigger
        # auto-refresh (which would hang on network calls).
        conn.execute(
            "INSERT OR IGNORE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
            ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
        )

        if seed_cooldown:
            conn.execute(
                "INSERT OR IGNORE INTO version_timestamps "
                "(ecosystem, package_name, version, publish_time, trust_level) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "pypi",
                    "requests",
                    "1.0.0",
                    (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "verified",
                ),
            )

        if seed_threat:
            conn.execute(
                """INSERT OR IGNORE INTO threats
                (id, ecosystem, package_name, affected_versions,
                 severity, confidence, source, source_id, summary,
                 first_seen, last_seen, hit_count, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "test:h4-threat-001",
                    "pypi",
                    "requests",
                    '["1.0.0"]',
                    "CRITICAL",
                    0.95,
                    "osv",
                    "OSV-H4-001",
                    "H4 test threat",
                    (datetime.now(UTC) - timedelta(days=7)).isoformat(),
                    (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                    1,
                    1,
                ),
            )

        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Helper: DB path patches
    # ------------------------------------------------------------------

    def _patch_db_paths(
        self,
        monkeypatch: pytest.MonkeyPatch,
        db_path: Path,
    ) -> None:
        """Patch get_db_path at all module levels needed by the CLI path.

        The isolated_env fixture already patches several get_db_path
        references (cli.main, cli.common, config.settings), but additional
        module-level bindings must be patched independently since Python
        resolves imports at module load time.

        Patched targets:
        - pkg_defender.config.get_db_path — re-export in config/__init__.py,
          used by dispatcher function-body imports
        - pkg_defender.cli.exec.get_db_path — module-level import in
          exec.py:22 (``from pkg_defender.config import get_db_path``)
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
    # Helper: prevent network calls during async caching step
    # ------------------------------------------------------------------

    def _patch_dispatcher_cache(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Replace _cache_version_timestamps_async with a no-op.

        The dispatcher's async caching step (called before the sync
        pre-install check) would make real network calls to PyPI to
        fetch publish timestamps. If the network call succeeds, it
        overwrites our seeded version_timestamp data with real publish
        times (years old for requests==1.0.0), causing the cooldown
        check to pass instead of block.

        This no-op ensures _build_release_date_map reads our seeded
        timestamps from the DB.
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
        """Replace FeedAggregator with a mock to prevent real network sync.

        The dispatcher's ``_ensure_db_fresh()`` method now passes
        ``ecosystems`` to ``sync_all()`` when an adapter ecosystem is
        resolved. When ``ecosystems`` is not None, the staleness check
        is bypassed entirely (to prevent cross-ecosystem false negatives),
        so ``sync_all()`` is always called. In tests that seed
        ``feed_state`` to avoid auto-refresh but also go through the
        full ``run()`` path, this patch prevents real network calls.
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
    # Test 1: --ci flag + COOLDOWN → prompt suppressed
    # ------------------------------------------------------------------

    def test_ci_flag_suppresses_cooldown_prompt(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--ci suppresses interactive prompt in COOLDOWN through full CLI path.

        Full path verified:
        --ci parsing → ctx.obj → ManagerGroup → dispatcher
        → adapter.parse → ctx.obj merge → parsed.pkgd_flags
        → handle_blocked_command → COOLDOWN branch → ci=True skips
        prompt → sys.exit(EXIT_COOLDOWN) → exit code 3.
        """
        db_path = isolated_env["db_path"]
        self._patch_db_paths(monkeypatch, db_path)
        self._patch_dispatcher_cache(monkeypatch)
        self._patch_feed_aggregator(monkeypatch)
        self._seed_db(db_path, seed_cooldown=True, seed_threat=False)

        with (
            mock.patch("pkg_defender.cli.exec._ask_bypass") as mock_ask,
            mock.patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            result = runner.invoke(
                cli,
                ["--ci", "pip", "install", "requests==1.0.0"],
                catch_exceptions=False,
            )

        assert result.exit_code == 3, f"Expected exit 3 (EXIT_COOLDOWN), got {result.exit_code}: {result.output}"
        mock_ask.assert_not_called()
        """PROVES: --ci suppressed the interactive bypass prompt."""
        mock_exec.assert_not_called()
        """PROVES: no execution occurred (cooldown blocked)."""

    # ------------------------------------------------------------------
    # Test 2: --non-interactive alias → identical behavior
    # ------------------------------------------------------------------

    def test_non_interactive_alias_identical(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--non-interactive alias produces identical behavior to --ci.

        main.py:285 defines ``--non-interactive`` as an alias for
        ``--ci``, both mapping to the same ``ci_mode`` parameter.
        This test verifies the alias triggers the same COOLDOWN
        prompt-suppression path.
        """
        db_path = isolated_env["db_path"]
        self._patch_db_paths(monkeypatch, db_path)
        self._patch_dispatcher_cache(monkeypatch)
        self._patch_feed_aggregator(monkeypatch)
        self._seed_db(db_path, seed_cooldown=True, seed_threat=False)

        with (
            mock.patch("pkg_defender.cli.exec._ask_bypass") as mock_ask,
            mock.patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            result = runner.invoke(
                cli,
                ["--non-interactive", "pip", "install", "requests==1.0.0"],
                catch_exceptions=False,
            )

        assert result.exit_code == 3, f"Expected exit 3 (EXIT_COOLDOWN), got {result.exit_code}: {result.output}"
        mock_ask.assert_not_called()
        mock_exec.assert_not_called()

    # ------------------------------------------------------------------
    # Test 3: PKGD_CI=1 env var → prompt suppressed
    # ------------------------------------------------------------------

    def test_pkgd_ci_env_var_suppresses_prompt(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """PKGD_CI=1 env var sets ci_mode via main.py:344.

        main.py:344 reads ``os.environ.get("PKGD_CI", "")`` and sets
        ``ctx.obj["ci"] = True`` when the value is ``"1"``, ``"true"``,
        or ``"yes"``. No explicit flag is needed.
        """
        db_path = isolated_env["db_path"]
        self._patch_db_paths(monkeypatch, db_path)
        self._patch_dispatcher_cache(monkeypatch)
        self._patch_feed_aggregator(monkeypatch)
        self._seed_db(db_path, seed_cooldown=True, seed_threat=False)

        with (
            mock.patch("pkg_defender.cli.exec._ask_bypass") as mock_ask,
            mock.patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            result = runner.invoke(
                cli,
                ["pip", "install", "requests==1.0.0"],
                env={"PKGD_CI": "1"},
                catch_exceptions=False,
            )

        assert result.exit_code == 3, f"Expected exit 3 (EXIT_COOLDOWN), got {result.exit_code}: {result.output}"
        mock_ask.assert_not_called()
        """PROVES: PKGD_CI=1 suppressed prompt (same as --ci flag)."""
        mock_exec.assert_not_called()

    # ------------------------------------------------------------------
    # Test 4: --ci does NOT suppress THREAT blocks (safety guard)
    # ------------------------------------------------------------------

    # NOTE: Flaky under xdist parallel execution (-n auto).
    # This test depends on DB state and environment isolation that can
    # collide under parallel execution; worker starvation causes timeouts.
    # See: https://github.com/pytest-dev/pytest-xdist/issues/1051
    # Flaky tests: test_ci_does_not_suppress_threat_block
    def test_ci_does_not_suppress_threat_block(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--ci does NOT accidentally suppress threat detection.

        exec.py:143-170 (THREAT branch) checks ``bypass_threat`` and
        ``json`` flags — it NEVER checks ``parsed.pkgd_flags.get("ci")``.
        This test verifies that threats are always blocked regardless
        of CI mode.

        The threat is seeded in the DB and the CLI is invoked with
        --ci. The THREAT branch should be reached (not the JSON path,
        not the bypass path) and exit with code 4.
        """
        db_path = isolated_env["db_path"]
        self._patch_db_paths(monkeypatch, db_path)
        self._patch_dispatcher_cache(monkeypatch)
        # Seed both cooldown data AND a matching threat.
        # Threat check runs before cooldown check in FULL tier,
        # so the threat blocks before cooldown is evaluated.
        self._seed_db(db_path, seed_cooldown=True, seed_threat=True)

        with (
            mock.patch("pkg_defender.cli.exec._print_threat_block") as mock_print,
            mock.patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            result = runner.invoke(
                cli,
                ["--ci", "pip", "install", "requests==1.0.0"],
                catch_exceptions=False,
            )

        assert result.exit_code == 4, f"Expected exit 4 (EXIT_THREAT_DETECTED), got {result.exit_code}: {result.output}"
        mock_print.assert_called_once()
        """PROVES: threat block was displayed (non-JSON, non-bypass path)."""
        mock_exec.assert_not_called()
        """PROVES: no execution occurred (threat blocked)."""

    # ------------------------------------------------------------------
    # Test 5: --ci + native command → valid JSON output
    # ------------------------------------------------------------------

    def test_ci_native_command_json_output(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--ci with native command produces valid JSON output.

        main.py:347 sets ``ctx.obj["output_format"] = "json"`` when
        --ci is active. The status command reads this at status.py:86:
        ``output_format = ctx.obj.get("output_format") or output_format``.
        This test verifies the output is parseable JSON with the expected
        structure (``summary`` contains ``active_bypasses``).
        """
        # No additional patching needed for native commands:
        # isolated_env already patches cli.commands.status.get_db_path
        # and cli.common.get_db_path for the status command.
        result = runner.invoke(
            cli,
            ["--ci", "status"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}: {result.output}"

        # Verify trailing newline in raw output (format_json contract)
        assert result.output.endswith("\n"), f"Expected trailing newline in JSON output, got: {result.output[-20:]!r}"

        raw = result.output.strip()
        assert raw.startswith("{"), f"Expected JSON object, got: {raw[:200]}"

        data = json.loads(raw)
        assert "summary" in data, f"Expected 'summary' in status JSON, got keys: {list(data.keys())}"
        assert "active_bypasses" in data["summary"], (
            f"Expected 'active_bypasses' in summary, got: {data.get('summary', {})}"
        )
        # Verify the top-level active_bypasses key also exists (structure check)
        assert "active_bypasses" in data, (
            f"Expected top-level 'active_bypasses' in status JSON, got keys: {list(data.keys())}"
        )
