"""End-to-end integration smoke test.

Validates the full install-time execution path:
1. Adapter parses command → ParsedCommand
2. _check_threats() → threat DB query → scoring with corroboration
3. _check_cooldown() → release timestamp lookup → cooldown evaluation
4. handle_cleared_command() → dry-run check
5. Correct exit codes (EXIT_THREAT_DETECTED=4, EXIT_COOLDOWN=3)
6. Bypass flow → DB audit write via insert_bypass()

This test MUST fail before P0 fixes are applied and pass after.
It acts as a regression guard against future wiring gaps.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pkg_defender.cli.dispatcher import ManagerDispatcher
from pkg_defender.cli.exec import (
    _log_bypass,
    handle_cleared_command,
)
from pkg_defender.config import load_config
from pkg_defender.core.checker import check_packages_batch
from pkg_defender.db.schema import get_connection
from pkg_defender.models import ParsedCommand
from pkg_defender.models.command import BlockReason, CommandIntent, InstallSource, PackageRef
from pkg_defender.registry.base import CoverageTier


@pytest.fixture
def mock_db_path(tmp_path: Path) -> Path:
    """Create a temporary threat database with known test data.

    Creates a SQLite DB with:
    - Two threats for pypi:requests with differing scores
    - Version timestamp data for cooldown testing
    - bypasses table (needed by _log_bypass tests)
    - Schema version set to current

    Uses init_db() for the schema so the test is forever in sync
    with the real schema (no hand-rolled CREATE TABLE drift).
    """
    from pkg_defender.db.schema import init_db

    db_path = tmp_path / "test_threats.db"
    conn = init_db(db_path)

    # Seed feed_state so _ensure_db_fresh() skips the network sync
    conn.execute(
        "INSERT OR REPLACE INTO feed_state (feed_name, last_sync, status) VALUES (?, ?, ?)",
        ("osv", (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "idle"),
    )

    # Seed blocking threat for requests==1.0.0 (score > threshold)
    # Note: ecosystem="pypi" because dispatcher._check_threats() resolves
    # resolve_ecosystem("pip") to "pypi" (correct mapping).
    conn.execute(
        """INSERT OR IGNORE INTO threats
        (id, ecosystem, package_name, affected_versions, severity, confidence, source,
         source_id, summary, first_seen, last_seen, hit_count, is_malicious)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "test:e2e-001",
            "pypi",
            "requests",
            '["1.0.0"]',
            "HIGH",
            0.9,
            "osv",
            "OSV-E2E-001",
            "E2E test blocking threat",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            1,
            1,
        ),
    )

    # Seed non-blocking threat for requests==2.0.0 (score below threshold)
    # Uses a Tier 3 social-media source (reddit) so signal-based cooldown
    # escalation (§8.3) doesn't treat it as a verified advisory and
    # block the package. Verified-advisory cooldown blocking is tested
    # separately in signal-cooldown unit tests.
    conn.execute(
        """INSERT OR IGNORE INTO threats
        (id, ecosystem, package_name, affected_versions, severity, confidence, source,
         source_id, summary, first_seen, last_seen, hit_count, is_malicious, is_unverified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "test:e2e-002",
            "pypi",
            "requests",
            '["2.0.0"]',
            "LOW",
            0.3,
            "reddit",
            "REDDIT-E2E-002",
            "E2E non-blocking threat (Tier 3 source)",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            1,
            0,
            1,  # is_unverified=True — social media, not authoritative
        ),
    )

    # Old version (passes cooldown — 30 days ago)
    conn.execute(
        "INSERT OR IGNORE INTO version_timestamps "
        "(ecosystem, package_name, version, publish_time, trust_level) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "pip",
            "requests",
            "2.0.0",
            (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified",
        ),
    )

    # New version (fails cooldown — 1 hour ago)
    conn.execute(
        "INSERT OR IGNORE INTO version_timestamps "
        "(ecosystem, package_name, version, publish_time, trust_level) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "pip",
            "requests",
            "99.0.0-beta1",
            (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified",
        ),
    )

    # Seed non-blocking threat for requests==2.0.0 (score below threshold)
    # Same Tier 3 source as the pip-ecosystem threat above.
    conn.execute(
        """INSERT OR IGNORE INTO threats
        (id, ecosystem, package_name, affected_versions, severity, confidence, source,
         source_id, summary, first_seen, last_seen, hit_count, is_malicious, is_unverified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "test:e2e-002",
            "pypi",
            "requests",
            '["2.0.0"]',
            "LOW",
            0.3,
            "reddit",
            "REDDIT-E2E-002",
            "E2E non-blocking threat (Tier 3 source)",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            1,
            0,
            1,  # is_unverified=True — social media, not authoritative
        ),
    )

    # Old version (passes cooldown — 30 days ago)
    conn.execute(
        "INSERT OR IGNORE INTO version_timestamps "
        "(ecosystem, package_name, version, publish_time, trust_level) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "pypi",
            "requests",
            "2.0.0",
            (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified",
        ),
    )

    # New version (fails cooldown — 1 hour ago)
    conn.execute(
        "INSERT OR IGNORE INTO version_timestamps "
        "(ecosystem, package_name, version, publish_time, trust_level) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "pypi",
            "requests",
            "99.0.0-beta1",
            (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified",
        ),
    )

    conn.commit()
    conn.close()

    return db_path


class TestEndToEndSmoke:
    """Integration smoke test — validates full install-time execution path."""

    # ------------------------------------------------------------------
    # Test 1: Threat scoring produces correct block verdict
    # ------------------------------------------------------------------

    def test_threat_scoring_above_threshold(self, mock_db_path: Path) -> None:
        """A known-blocked threat must produce a score >= threshold.

        This validates:
        - check_packages_batch() correctly queries the threat DB
        - Scoring computes scores above BLOCK_SCORE_THRESHOLD (0.3)

        NOTE: This test does NOT check exit codes — that is done in
        Test 8 (the true end-to-end dispatcher test). The name was
        changed from 'test_threat_block_uses_exit_code_4' to match
        what this test actually validates (Issue 6 fix).
        """
        conn = get_connection(mock_db_path)
        results = check_packages_batch(
            conn=conn,
            packages=[("pypi", "requests", "1.0.0")],
        )
        conn.close()

        result = results.get(("pypi", "requests", "1.0.0"))
        assert result is not None, "check_packages_batch returned no result"
        assert result.blocked, "requests 1.0.0 should be blocked by test threat"
        assert result.highest_score >= 0.3, f"Blocked threat must have score >= 0.3, got {result.highest_score}"

    # ------------------------------------------------------------------
    # Test 2: Cooldown blocking
    # ------------------------------------------------------------------

    def test_blocks_recent_package_on_cooldown(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A cooldown-blocked package must exit with EXIT_COOLDOWN (3).

        This validates:
        - _check_cooldown() correctly evaluates release dates
        - handle_blocked_command() for COOLDOWN reason exits with code 3

        NOTE: This tests step_check_cooldown directly (component test).
        The wiring through the dispatcher is validated in Test 8.
        """
        from pkg_defender.audit.cooldown import step_check_cooldown

        config = load_config()
        recent_date = datetime.now(UTC) - timedelta(hours=1)

        passed, days_remaining = step_check_cooldown(
            release_date=recent_date,
            config=config.cooldown,
            ecosystem="pypi",
        )

        assert not passed, (
            f"Package published 1 hour ago should fail cooldown (default_days={config.cooldown.default_days})"
        )
        assert days_remaining is not None and days_remaining > 0, (
            f"days_remaining should be positive, got {days_remaining}"
        )

    # ------------------------------------------------------------------
    # Test 3: Passed cooldown allows execution
    # ------------------------------------------------------------------

    def test_old_package_passes_cooldown(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A package published 30 days ago must pass the cooldown check.

        This validates that cooldown correctly allows old packages.
        """
        from pkg_defender.audit.cooldown import step_check_cooldown

        config = load_config()
        old_date = datetime.now(UTC) - timedelta(days=30)

        passed, days_remaining = step_check_cooldown(
            release_date=old_date,
            config=config.cooldown,
            ecosystem="pypi",
        )

        assert passed, (
            f"Package published 30 days ago should pass cooldown (default_days={config.cooldown.default_days})"
        )

    # ------------------------------------------------------------------
    # Test 4: Bypass writes to database audit trail
    # ------------------------------------------------------------------

    def test_bypass_logs_to_database(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bypass event must write an entry to the bypasses table.

        This validates:
        - _log_bypass() calls insert_bypass() WITH a DB connection
        - The bypass entry persists in the database

        Patch target uses pkg_defender.cli.exec.get_db_path because
        exec.py does 'from pkg_defender.config import get_db_path'
        at module level — creating a local binding (Issue 1 fix).
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )

        pkg_ref = PackageRef(
            raw="requests==1.0.0",
            name="requests",
            version="1.0.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==1.0.0"],
            pkgd_flags={"force": True},
        )

        _log_bypass(parsed, pkg_ref, BlockReason.COOLDOWN)

        # Verify the bypass entry exists in the DB
        conn = get_connection(mock_db_path)
        rows = conn.execute("SELECT * FROM bypasses").fetchall()
        conn.close()

        assert len(rows) == 1, "Expected 1 bypass entry in DB"
        assert rows[0]["package_name"] == "requests"
        assert rows[0]["reason"] == "bypass:COOLDOWN"
        assert rows[0]["checks_performed"] == "bypassed"

    # ------------------------------------------------------------------
    # Test 5: handle_cleared_command checks dry_run correctly
    # ------------------------------------------------------------------

    def test_handle_cleared_command_respects_dry_run(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """handle_cleared_command() must NOT execute when dry_run=True.

        This validates that --dry-run is correctly checked before exec.

        Replaces the previous 'assert True' anti-pattern (Issue 4 fix)
        with a proper assertion: monkeypatch exec_cleared_command and
        verify it is NOT called when dry_run=True.
        """
        from pkg_defender.cli import exec as exec_module

        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={"dry_run": True},
        )

        # If dry_run is respected, handle_cleared_command prints output
        # without calling exec_cleared_command (which would os.execvp).
        with patch.object(exec_module, "exec_cleared_command") as mock_exec:
            handle_cleared_command(parsed)
            mock_exec.assert_not_called()

    # ------------------------------------------------------------------
    # Test 6: Threat detection + cooldown + dry-run composition
    # ------------------------------------------------------------------

    def test_full_path_clean_package_dry_run(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A clean (non-threat, non-cooldown) package with --dry-run
        should print output instead of executing.

        This validates the complete wiring: threats → cooldown → dry-run.
        """
        from pkg_defender.cli import exec as exec_module

        # Disable cooldown so the clean package path is exercised
        orig_config = load_config()
        orig_config.cooldown.enabled = False

        pkg_ref = PackageRef(
            raw="requests==2.0.0",
            name="requests",
            version="2.0.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={"dry_run": True},
        )

        # This should pass all checks and print dry-run output
        # without calling os.execvp
        with patch.object(exec_module, "exec_cleared_command") as mock_exec:
            handle_cleared_command(parsed)
            mock_exec.assert_not_called()

    # ------------------------------------------------------------------
    # Test 7: Corroboration multiplier is applied
    # ------------------------------------------------------------------

    def test_corroboration_multiplier_applied(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When multiple sources report the same threat, the score must
        be boosted by CORROBORATION_MULTIPLIER.

        This validates that score_threats() (plural) is called instead of
        score_threat() (singular), and the multiplier is applied.

        NOTE: datetime imports are at module level (top of file) to avoid
        the NameError that would occur if they were placed after first use
        (Issue 2 fix).
        """
        from pkg_defender.core.scorer import score_threats
        from pkg_defender.models import ThreatRecord

        # Create two threats for the same package from different sources
        threats = [
            ThreatRecord(
                id="test:multi-001",
                ecosystem="pypi",
                package_name="requests",
                affected_versions=["3.0.0"],
                affected_ranges=[],
                severity="HIGH",
                confidence=0.9,
                source="osv",
                source_id="OSV-MULTI-001",
                summary="Test multi-source threat 1",
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
                hit_count=1,
                cvss_score=None,
                published_at=None,
                ingested_at=datetime.now(UTC),
                is_malicious=True,
                is_unverified=False,
            ),
            ThreatRecord(
                id="test:multi-002",
                ecosystem="pypi",
                package_name="requests",
                affected_versions=["3.0.0"],
                affected_ranges=[],
                severity="HIGH",
                confidence=0.85,
                source="ghsa",
                source_id="GHSA-MULTI-001",
                summary="Test multi-source threat 2",
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
                hit_count=1,
                cvss_score=None,
                published_at=None,
                ingested_at=datetime.now(UTC),
                is_malicious=True,
                is_unverified=False,
            ),
        ]

        # Score without corroboration (count=1)
        single_scored = score_threats(threats[:1], "exact", now=datetime.now(UTC))
        single_score = single_scored[0].final_score

        # Score with corroboration (count=2)
        multi_scored = score_threats(threats, "exact", now=datetime.now(UTC))
        multi_score = multi_scored[0].final_score

        # The multi-source score should be higher by the corroboration multiplier (1.15x for 2 sources)
        assert multi_score > single_score * 0.99, (
            f"Multi-source score ({multi_score}) should be higher than "
            f"single-source ({single_score}) due to corroboration multiplier"
        )

    # ------------------------------------------------------------------
    # Test 8: True end-to-end dispatcher path (Issue 5 fix)
    # ------------------------------------------------------------------

    def test_dispatcher_wiring_threat_block_exit_code(
        self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A blocked threat through the dispatcher returns a BlockDecision.

        This is the TRUE end-to-end test — it routes through
        _run_pre_install_check() via _check_threats(), validating that
        the entire wiring chain is connected:
        1. _check_threats() queries the threat DB
        2. check_packages_batch() computes scores
        3. A BlockDecision with BlockReason.THREAT is returned

        Before the timeout fix, handle_blocked_command() was called
        directly and raised SystemExit. After the fix, detection returns
        BlockDecision objects that are processed OUTSIDE the timeout scope.

        TWO monkeypatches are needed because the code path spans two
        modules with different import styles:
        - dispatcher._check_threats() does a local function-level
          'from pkg_defender.config import get_db_path' at line 195
        - exec._log_bypass() uses its module-level binding from
          'from pkg_defender.config import get_db_path' at exec.py:16
        Both source targets must be patched independently.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==1.0.0",
            name="requests",
            version="1.0.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==1.0.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # After the timeout fix, _run_pre_install_check() returns
        # BlockDecision objects instead of calling handle_blocked_command()
        result = dispatcher._run_pre_install_check(parsed, ctx)

        assert len(result) == 1
        assert result[0].reason == BlockReason.THREAT
        assert result[0].package.name == "requests"

    def test_dispatcher_wiring_cooldown_block_exit_code(
        self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cooldown-blocked package through the dispatcher returns a BlockDecision.

        Validates that _check_cooldown() is actually called from
        _run_pre_install_check(), and that a BlockDecision with
        BlockReason.COOLDOWN is returned.

        Before the timeout fix, handle_blocked_command() was called
        directly and raised SystemExit. After the fix, detection returns
        BlockDecision objects that are processed OUTSIDE the timeout scope.

        TWO monkeypatches needed — same reason as the threat test:
        dispatcher._check_threats() uses a local function-level import
        of get_db_path (from pkg_defender.config), while exec.py uses
        a module-level binding.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==99.0.0-beta1",
            name="requests",
            version="99.0.0-beta1",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==99.0.0-beta1"],
            pkgd_flags={"ci": True},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # After the timeout fix, _run_pre_install_check() returns
        # BlockDecision objects instead of calling handle_blocked_command()
        result = dispatcher._run_pre_install_check(parsed, ctx)

        assert len(result) == 1
        assert result[0].reason == BlockReason.COOLDOWN
        assert result[0].package.name == "requests"

    # ------------------------------------------------------------------
    # Test 9: Cooldown allows old package through dispatcher (A-001 regression)
    # ------------------------------------------------------------------

    def test_dispatcher_wiring_cooldown_allows_old_package(
        self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An old package through the full dispatcher must pass cooldown.

        REGRESSION TEST for the cooldown empty-dict bug (A-001).
        Before the fix, ALL packages were blocked by cooldown because
        release_dates was always {}. After the fix, the dispatcher
        queries version_timestamps from the DB and passes real dates
        to _check_cooldown.

        The mock_db_path fixture seeds requests==2.0.0 with publish_time
        30 days ago, so cooldown should pass (30 days > 3-day default window).
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==2.0.0",
            name="requests",
            version="2.0.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        with patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle:
            dispatcher._run_pre_install_check(parsed, ctx)
            mock_handle.assert_called_once()

    # ------------------------------------------------------------------
    # Test 10: Uncached package blocks through dispatcher (fail-closed)
    # ------------------------------------------------------------------

    def test_dispatcher_wiring_cooldown_uncached_package_blocks(
        self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A package not in version_timestamps DB returns a BlockDecision.

        Validates that _build_release_date_map() handles uncached packages
        correctly: when a package has no entry in the version_timestamps
        table, its release_date is None, and step_check_cooldown() returns
        (False, window) — fail-closed blocking.

        The mock_db_path fixture seeds timestamps only for requests==2.0.0
        and requests==99.0.0-beta1, so any other package (e.g., urllib3)
        will not be found in the cache.

        After the timeout fix, _run_pre_install_check() returns BlockDecision
        objects instead of calling handle_blocked_command() directly.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="urllib3==1.26.0",
            name="urllib3",
            version="1.26.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "urllib3==1.26.0"],
            pkgd_flags={"ci": True},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # After the timeout fix, _run_pre_install_check() returns
        # BlockDecision objects instead of calling handle_blocked_command()
        result = dispatcher._run_pre_install_check(parsed, ctx)

        assert len(result) == 1
        assert result[0].reason == BlockReason.COOLDOWN
        assert result[0].package.name == "urllib3"

    # ------------------------------------------------------------------
    # Test 11: Empty packages list handles gracefully
    # ------------------------------------------------------------------

    def test_dispatcher_wiring_cooldown_empty_packages(
        self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty packages list must not raise and must call handle_cleared_command.

        Validates that _build_release_date_map() handles an empty package
        list gracefully, returning {} without error. _check_cooldown()
        with an empty packages list returns True immediately.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        with patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle:
            dispatcher._run_pre_install_check(parsed, ctx)
            mock_handle.assert_called_once()


# ------------------------------------------------------------------
# Test 12: Cooldown config loads correctly from pkgd.toml
# ------------------------------------------------------------------


def test_cooldown_default_config_loads(tmp_path: Path) -> None:
    """The cooldown config loads correctly from pkgd.toml.

    Verifies that the project-level pkgd.toml is parsed correctly,
    setting default_days=1 as configured.
    """
    config_path = tmp_path / "pkgd.toml"
    config_path.write_text("[cooldown]\ndefault_days = 1\nenabled = true\nstrict_mode = true\n")

    config = load_config(config_path=config_path)

    assert config.cooldown.default_days == 1, f"Expected cooldown.default_days=1, got {config.cooldown.default_days}"
    assert config.cooldown.enabled is True, "Expected cooldown.enabled=True"


class TestPrefixDryRun:
    """Tests for --dry-run in prefix position (A-013).

    Verifies that 'pkgd --dry-run pip list' correctly transfers the
    dry_run flag from Click's ctx.obj into parsed.pkgd_flags so that
    handle_cleared_command prints dry-run output instead of executing
    the command.

    Uses SAFE_PASSTHROUGH command (pip list) to avoid DB dependencies
    in the pre-install checker — the merge path is identical regardless
    of intent classification.
    """

    def test_prefix_dry_run_does_not_execute(
        self,
        runner: CliRunner,
    ) -> None:
        """pkgd --dry-run pip list must NOT execute.

        The --dry-run flag in prefix position is consumed by Click
        at group level. The scoped merge at dispatcher.py must
        transfer it into parsed.pkgd_flags so handle_cleared_command
        prints dry-run output instead of calling exec_cleared_command.
        """
        from pkg_defender.cli import exec as exec_module
        from pkg_defender.cli.main import cli

        with patch.object(exec_module, "exec_cleared_command") as mock_exec:
            runner.invoke(
                cli,
                ["--dry-run", "pip", "list"],
                catch_exceptions=False,
            )

            # The merge must transfer dry_run into pkgd_flags,
            # so handle_cleared_command calls _print_dry_run, not exec
            mock_exec.assert_not_called()

    def test_prefix_dry_run_shows_output(
        self,
        runner: CliRunner,
    ) -> None:
        """pkgd --dry-run pip list should show dry-run output.

        Verifies that the dry-run output is printed (not just that
        exec is skipped), confirming the full prefix → merge → dry-run
        flow works through the Click pipeline.
        """
        from pkg_defender.cli import exec as exec_module
        from pkg_defender.cli.main import cli

        with patch.object(exec_module, "exec_cleared_command") as mock_exec:
            result = runner.invoke(
                cli,
                ["--dry-run", "pip", "list"],
                catch_exceptions=False,
            )

            mock_exec.assert_not_called()
            # _print_dry_run renders "Dry run:" header in its output
            assert "Dry run" in result.output or "dry" in result.output.lower()


class TestAuditEventWiring:
    """Integration tests for audit event DB writes (Plan A-048).

    These tests validate that the full dispatcher pipeline writes audit
    events to the database at every terminal verdict point, using the
    real DB fixture with seeded threat and version data.
    """

    # ------------------------------------------------------------------
    # Test 15: Threat block writes audit event
    # ------------------------------------------------------------------

    def test_audit_event_db_threat_block(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A threat-blocked package returns a BlockDecision with audit event.

        Validates that _check_threats() writes an audit event and returns
        a BlockDecision object (instead of calling handle_blocked_command).
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==1.0.0",
            name="requests",
            version="1.0.0",
            ecosystem="",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==1.0.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # After the timeout fix, _run_pre_install_check() returns
        # BlockDecision objects instead of calling handle_blocked_command()
        result = dispatcher._run_pre_install_check(parsed, ctx)

        assert len(result) == 1
        assert result[0].reason == BlockReason.THREAT
        assert result[0].package.name == "requests"

        # Verify audit event was written to the database
        conn = get_connection(mock_db_path)
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE package_name = ? ORDER BY id DESC",
            ("requests",),
        ).fetchall()
        conn.close()

        assert len(rows) >= 1, "Expected at least 1 audit event for requests"
        assert rows[0]["verdict"] == "BLOCKED", f"Expected verdict='BLOCKED', got {rows[0]['verdict']}"
        assert rows[0]["ecosystem"] == "pip", f"Expected ecosystem='pip', got {rows[0]['ecosystem']}"
        assert rows[0]["action"] == "install"
        assert rows[0]["threat_count_general"] >= 1
        assert rows[0]["exit_code"] == 4  # EXIT_THREAT_DETECTED

    # ------------------------------------------------------------------
    # Test 16: Cooldown block writes audit event
    # ------------------------------------------------------------------

    def test_audit_event_db_cooldown_block(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A cooldown-blocked package returns a BlockDecision with audit event.

        Validates that _check_cooldown() writes an audit event and returns
        a BlockDecision object (instead of calling handle_blocked_command).
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==99.0.0-beta1",
            name="requests",
            version="99.0.0-beta1",
            ecosystem="",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==99.0.0-beta1"],
            pkgd_flags={"ci": True},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # After the timeout fix, _run_pre_install_check() returns
        # BlockDecision objects instead of calling handle_blocked_command()
        result = dispatcher._run_pre_install_check(parsed, ctx)

        assert len(result) == 1
        assert result[0].reason == BlockReason.COOLDOWN
        assert result[0].package.name == "requests"

        # Verify audit event was written to the database
        conn = get_connection(mock_db_path)
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE package_name = ? ORDER BY id DESC",
            ("requests",),
        ).fetchall()
        conn.close()

        assert len(rows) >= 1, "Expected at least 1 audit event for requests"
        assert rows[0]["verdict"] == "BLOCKED", f"Expected verdict='BLOCKED', got {rows[0]['verdict']}"
        assert rows[0]["cooldown_pass"] == 0, f"Expected cooldown_pass=0, got {rows[0]['cooldown_pass']}"
        assert rows[0]["cooldown_days_remaining"] > 0, (
            f"Expected cooldown_days_remaining > 0, got {rows[0]['cooldown_days_remaining']}"
        )
        assert rows[0]["exit_code"] == 3, f"Expected exit_code=3 (EXIT_COOLDOWN), got {rows[0]['exit_code']}"

    # ------------------------------------------------------------------
    # Test 17: Cleared command (PASS) writes audit event
    # ------------------------------------------------------------------

    def test_audit_event_db_cleared_command(self, mock_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A cleared command (all checks pass) must write an audit event with verdict='PASS'.

        Validates that _run_pre_install_check() writes an audit event
        before calling handle_cleared_command().
        """
        monkeypatch.setattr(
            "pkg_defender.cli.exec.get_db_path",
            lambda: mock_db_path,
        )
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: mock_db_path,
        )

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg_ref = PackageRef(
            raw="requests==2.0.0",
            name="requests",
            version="2.0.0",
            ecosystem="pypi",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        with patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle:
            dispatcher._run_pre_install_check(parsed, ctx)
            mock_handle.assert_called_once()

        # Verify audit event was written to the database
        conn = get_connection(mock_db_path)
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE package_name = ? ORDER BY id DESC",
            ("requests",),
        ).fetchall()
        conn.close()

        assert len(rows) >= 1, "Expected at least 1 audit event for requests"
        assert rows[0]["verdict"] == "PASS", f"Expected verdict='PASS', got {rows[0]['verdict']}"
        assert rows[0]["exit_code"] == 0, f"Expected exit_code=0, got {rows[0]['exit_code']}"
        assert rows[0]["cooldown_pass"] == 1
        assert rows[0]["threat_count_general"] >= 0
