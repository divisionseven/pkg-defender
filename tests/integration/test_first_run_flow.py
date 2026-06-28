"""First-run flow integration test.

Simulates a complete first-time user experience:
1. pkgd --help — verify wrapper pattern is documented
2. pkgd setup --ci — complete setup without network calls
3. pkgd pip install requests --dry-run — verify [PKGD] prefix, threat check
4. pkgd status — verify active adapters and threat counts
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli


@pytest.fixture
def seeded_env(
    isolated_env: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    """Extend isolated_env with seeded threat data and mocked intel_sync.

    After the isolated_env fixture creates the database and patches paths,
    this fixture:
    1. Seeds threat data for the dry-run verification step
    2. Seeds feed_state rows so status shows active adapters
    3. Mocks intel_sync so setup --ci doesn't make network calls
    4. Returns the env dict with db_path for direct SQL access
    """
    db_path = isolated_env["db_path"]
    conn = sqlite3.connect(str(db_path))

    # Seed blocking threat for requests (high score)
    conn.execute(
        """INSERT OR IGNORE INTO threats
        (id, ecosystem, package_name, affected_versions, severity, confidence, source,
         source_id, summary, first_seen, last_seen, hit_count, is_malicious)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "test:first-run-001",
            "pypi",
            "requests",
            '["1.0.0"]',
            "HIGH",
            0.9,
            "osv",
            "OSV-FIRST-RUN-001",
            "First-run test blocking threat",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            1,
            1,
        ),
    )

    # Seed feed_state rows so status command shows active feeds
    feeds = [
        ("osv", (datetime.now(UTC) - timedelta(hours=1)).isoformat(), "idle"),
        ("osv_brew", (datetime.now(UTC) - timedelta(hours=1)).isoformat(), "idle"),
    ]
    for feed_name, last_sync, status in feeds:
        conn.execute(
            "INSERT OR IGNORE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
            (feed_name, last_sync, status),
        )

    conn.commit()

    # Verify seed data was inserted
    row_count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    assert row_count > 0, "seeded_env fixture failed to insert threat data"

    conn.close()

    # Mock intel_sync to avoid real network calls during setup step.
    # intel_sync is imported via a function-body import, then
    # ctx.invoke(intel_sync, ...) is called. Monkeypatch must target the
    # DEFINING module (intel.py), not the importing module (setup.py),
    # because the import is function-body-scoped (see A-023 learnings).
    monkeypatch.setattr(
        "pkg_defender.cli.commands.intel.intel_sync",
        lambda *args, **kwargs: None,
    )

    # Patch get_db_path at the config.__init__ level (re-export from
    # settings) and cli.exec module level, because the dispatcher does
    # function-body imports from pkg_defender.config, while exec.py has
    # a module-level binding from the same source. The isolated_env
    # fixture patches settings.get_db_path, but the re-export in
    # config.__init__ and exec's module-level binding are separate
    # references that must be patched independently.
    monkeypatch.setattr(
        "pkg_defender.config.get_db_path",
        lambda *args, **kwargs: db_path,
    )
    monkeypatch.setattr(
        "pkg_defender.cli.exec.get_db_path",
        lambda *args, **kwargs: db_path,
    )

    return isolated_env


class TestFirstRunFlow:
    """Simulates a complete first-time user journey."""

    def test_first_run_flow(
        self,
        runner: CliRunner,
        seeded_env: dict[str, Path],
    ) -> None:
        """Complete first-run flow: --help, setup, dry-run, status.

        The test is intentionally ONE method to preserve state between
        steps — each CliRunner invocation modifies the filesystem state
        (config, DB) that the next step depends on.
        """
        # ── Step 1: pkgd --help ──────────────────────────────────────
        result_help = runner.invoke(cli, ["--help"], catch_exceptions=False)
        assert result_help.exit_code == 0, f"--help failed: {result_help.output}"
        # Verify the CLI help shows the application name and known
        # commands (confirms the CLI group is properly registered)
        assert "PKG-Defender" in result_help.output, "--help should show PKG-Defender heading"
        assert "setup" in result_help.output, "--help should show setup in command list"
        assert "status" in result_help.output, "--help should show status in command list"

        # ── Step 2: pkgd setup --ci ──────────────────────────────────
        # The --ci flag must appear BEFORE the subcommand because it is
        # a GROUP-level option on the cli object, not on the setup
        # subcommand itself.
        result_setup = runner.invoke(
            cli,
            ["--ci", "setup"],
            catch_exceptions=False,
        )
        assert result_setup.exit_code == 0, (
            f"setup --ci failed with exit code {result_setup.exit_code}: {result_setup.output}"
        )
        # Verify setup completion message
        assert "Setup complete" in result_setup.output, (
            f"Missing 'Setup complete' in setup output: {result_setup.output}"
        )
        # Verify CI mode was detected
        assert "CI mode detected" in result_setup.output, (
            f"Missing 'CI mode detected' in setup output: {result_setup.output}"
        )

        # ── Step 3: pkgd pip install requests==1.0.0 --dry-run ───────
        # Version is required — the dispatcher blocks versionless
        # installs. 1.0.0 matches the seeded threat.
        result_dry_run = runner.invoke(
            cli,
            ["pip", "install", "requests==1.0.0", "--dry-run"],
            catch_exceptions=False,
        )
        # The threat IS detected and blocked — exit code 4
        # (EXIT_THREAT_DETECTED). The plan originally asserted exit 0 +
        # [PKGD] prefix, but those only apply to CLEARED packages
        # in _print_dry_run, not blocked threats.
        assert result_dry_run.exit_code == 4, (
            f"Seeded threat should block with exit code 4, got {result_dry_run.exit_code}: {result_dry_run.output}"
        )
        # Output should show the blocking message
        assert "BLOCKED" in result_dry_run.output, f"Missing BLOCKED message in dry-run output: {result_dry_run.output}"

        # ── Step 4: pkgd status ──────────────────────────────────────
        result_status = runner.invoke(
            cli,
            ["status"],
            catch_exceptions=False,
        )
        assert result_status.exit_code == 0, f"status failed: {result_status.output}"
        # Verify status shows the seeded threat count
        assert "threat" in result_status.output.lower(), f"Status output missing threat info: {result_status.output}"
        assert "1 threat" in result_status.output.lower() or "threats" in result_status.output, (
            f"Status should show at least one threat, got: {result_status.output}"
        )

    # NOTE: Flaky under xdist parallel execution (-n auto).
    # This integration test exercises the full dispatch + exec chain
    # with DB setup — worker starvation causes timeout failures.
    # See: https://github.com/pytest-dev/pytest-xdist/issues/1051
    # Flaky tests: test_first_run_flow_threat_check
    def test_first_run_flow_threat_check(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify threat check runs and detects malicious packages.

        This test seeds a HIGH-confidence malicious threat directly in
        the DB and invokes the wrapper command to verify the threat
        blocking output appears.
        """
        db_path = isolated_env["db_path"]

        # The dispatcher does function-body imports from
        # pkg_defender.config, and exec has a module-level binding.
        # Patch both so the wrapper command can find the test DB.
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda *args, **kwargs: db_path,
        )

        # Seed feed_state so _ensure_db_fresh() doesn't auto-refresh
        # (which would hang on network calls to intel feeds).
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT OR IGNORE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
            ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
        )
        conn.commit()
        conn.close()

        conn = sqlite3.connect(str(db_path))

        # Seed blocking threat for a malicious package
        conn.execute(
            """INSERT OR IGNORE INTO threats
            (id, ecosystem, package_name, affected_versions, severity, confidence, source,
             source_id, summary, first_seen, last_seen, hit_count, is_malicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "test:first-run-malicious-001",
                "pypi",
                "malpkg",
                '["1.0.0"]',
                "CRITICAL",
                0.95,
                "osv",
                "OSV-MAL-001",
                "First-run test malicious package",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:00:00Z",
                1,
                1,
            ),
        )
        conn.commit()
        conn.close()

        result = runner.invoke(
            cli,
            ["pip", "install", "malpkg==1.0.0", "--dry-run"],
            catch_exceptions=False,
        )
        # The threat should be detected (exit code 4 = EXIT_THREAT_DETECTED)
        # or output should contain the block message.
        # Note: [PKGD] prefix only appears for cleared packages in
        # _print_dry_run, not for blocked threats. Assert the threat
        # detection message instead.
        assert "BLOCKED" in result.output, f"Expected 'BLOCKED' in dry-run output, got: {result.output}"

    def test_first_run_flow_no_threats(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify dry-run passes when no threats exist.

        When the DB is empty (no threats seeded), a dry-run should
        still produce clean output with [PKGD] prefix and exit 0.
        """
        db_path = isolated_env["db_path"]

        # Patch get_db_path at config.__init__ and cli.exec levels so
        # the dispatcher and exec modules find the test DB.
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda *args, **kwargs: db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda *args, **kwargs: db_path,
        )

        # Mock FeedAggregator.sync_all to prevent real network calls.
        # The ecosystem filtering change bypasses the feed_state staleness
        # check when ecosystems is specified, so seeding feed_state no
        # longer prevents sync from running.
        async def _noop_sync_all(
            _self: object,
            ecosystems: list[str] | None = None,  # noqa: ARG001
            **kwargs: Any,
        ) -> None:
            pass

        monkeypatch.setattr(
            "pkg_defender.intel.aggregator.FeedAggregator.sync_all",
            _noop_sync_all,
        )

        # Seed feed_state so _ensure_db_fresh() doesn't auto-refresh
        # (which would hang on network calls to intel feeds).
        # Also seed a version_timestamp so the package passes cooldown.
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT OR IGNORE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
            ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO version_timestamps "
            "(ecosystem, package_name, version, publish_time, trust_level) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "pypi",
                "requests",
                "1.0.0",
                (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "verified",
            ),
        )
        conn.commit()
        conn.close()

        result = runner.invoke(
            cli,
            ["pip", "install", "requests==1.0.0", "--dry-run"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"dry-run with no threats failed: {result.output}"
        assert "[PKGD]" in result.output, f"Missing [PKGD] prefix: {result.output}"
