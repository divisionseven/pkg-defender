"""Tests for ManagerDispatcher._ensure_db_fresh()."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import click
import pytest

from pkg_defender.cli._exit_codes import EXIT_DB_ERROR
from pkg_defender.cli.dispatcher import CooldownCheckResult, ManagerDispatcher, ThreatCheckResult
from pkg_defender.config.settings import PKGDConfig
from pkg_defender.models.command import CommandIntent, InstallSource, PackageRef, ParsedCommand
from pkg_defender.models.models import CheckResult
from pkg_defender.registry.base import CoverageTier, PipelineAdapterProtocol


class TestEnsureDbFresh:
    """Tests for ManagerDispatcher._ensure_db_fresh().

    Coverage:
      - test_db_fresh_no_refresh_needed       Fresh DB → no sync
      - test_db_stale_triggers_refresh        Stale DB → sync_all() called
      - test_db_never_synced_triggers_refresh No feed_state → sync triggered
      - test_db_malformed_timestamp_treated_as_stale  Bad timestamp → sync triggered
      - test_db_non_string_timestamp_treated_as_stale Non-string value → sync triggered
      - test_db_stale_refresh_fails_blocks    Sync failure → SystemExit(EXIT_DB_ERROR)
      - test_db_not_exists_skips_check        No DB file → skip
      - test_db_path_is_none_skips_check      None path → skip
      - test_db_stale_connection_io_error     DB I/O error → graceful return
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a dispatcher instance without going through ``__init__``."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_config(self, threshold_hours: int = 8) -> PKGDConfig:
        """Create a config with a specific staleness threshold.

        Args:
            threshold_hours: Staleness threshold in hours.

        Returns:
            PKGDConfig with the given staleness threshold.
        """
        config = PKGDConfig()
        config.feeds.staleness_threshold_hours = threshold_hours
        return config

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    # ------------------------------------------------------------------
    # Fresh DB — no refresh needed
    # ------------------------------------------------------------------

    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_fresh_no_refresh_needed(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
    ) -> None:
        """Fresh DB (recent sync) → returns True, no sync triggered."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        recent_sync = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": recent_sync}

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_get_feed_state.assert_called_once()
        # FeedAggregator was never imported/created — use the fact that
        # get_connection was called but no aggregator code path ran
        mock_get_connection.assert_called_once()

    # ------------------------------------------------------------------
    # Stale DB — triggers refresh
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_stale_triggers_refresh(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Stale DB (10h ago, threshold 8h) → triggers sync, returns True."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_feed_aggregator.assert_called_once()
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # Never synced — triggers refresh
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_never_synced_triggers_refresh(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """No ``feed_state`` records → triggers sync, returns True."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        mock_get_feed_state.return_value = None  # No records at all

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_feed_aggregator.assert_called_once()
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # Malformed timestamp — treated as stale, triggers refresh
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_malformed_timestamp_treated_as_stale(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Malformed ``last_sync`` timestamp → treated as stale, triggers sync.

        The ``_ensure_db_fresh`` method catches ``ValueError`` (bad format)
        and ``TypeError`` (non-string value) during timestamp parsing and
        treats those cases as stale, triggering a full feed refresh.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        # Malformed ISO timestamp — datetime.fromisoformat raises ValueError
        mock_get_feed_state.return_value = {"last_sync": "not-a-valid-timestamp"}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_feed_aggregator.assert_called_once()
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # Non-string timestamp (TypeError) — treated as stale, triggers refresh
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_non_string_timestamp_treated_as_stale(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Non-string ``last_sync`` value (e.g. integer) → TypeError → treated as stale.

        Verifies the ``TypeError`` branch of the timestamp parsing catch block.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        # Integer value — datetime.fromisoformat raises TypeError
        mock_get_feed_state.return_value = {"last_sync": 12345}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_feed_aggregator.assert_called_once()
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # Stale DB with ecosystem filter — triggers refresh with filter
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_stale_triggers_refresh_with_ecosystem(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """ecosystems=["pypi"] passed to _ensure_db_fresh → sync_all(ecosystems=["pypi"])."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(
            config,
            self._make_ctx(),
            ecosystems=["pypi"],
        )

        assert result is True
        mock_feed_aggregator.assert_called_once()
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=["pypi"],
            progress_callback=ANY,
            error_callback=ANY,
        )

    # ------------------------------------------------------------------
    # Fresh feed_state with ecosystem filter — runs staleness check
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_fresh_with_ecosystem_skips_sync(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Fresh feed_state with ecosystems filter → staleness check skips sync.

        Before the fix, this branch always synced (no staleness check).
        After the fix: feed_state.last_sync is fresh (< threshold), so the
        staleness check returns True early without calling sync_all.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        # Feed state is FRESH — would skip sync for ecosystems=None
        fresh_sync = datetime.now(UTC).isoformat()
        mock_get_feed_state.return_value = {"last_sync": fresh_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock()
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        result = dispatcher._ensure_db_fresh(
            config,
            self._make_ctx(),
            ecosystems=["pypi"],
        )

        assert result is True
        # Fresh data → sync should NOT be called
        mock_aggregator_instance.sync_all.assert_not_called()
        # get_feed_state SHOULD be called (staleness check runs)
        mock_get_feed_state.assert_called_once()

    # ------------------------------------------------------------------
    # Timeout: sync_all raises TimeoutError → SystemExit(EXIT_DB_ERROR)
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_stale_refresh_timed_out(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Stale DB + sync_all raises TimeoutError → SystemExit(EXIT_DB_ERROR).

        The ``except TimeoutError`` in ``_ensure_db_fresh`` must catch the
        async ``TimeoutError`` raised by ``asyncio.wait_for`` (when
        aggregator.sync_all does not complete before the timeout) and
        convert it to ``SystemExit(EXIT_DB_ERROR)``.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(side_effect=TimeoutError("sync timed out"))
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with pytest.raises(SystemExit) as exc_info:
            dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert exc_info.value.code == EXIT_DB_ERROR
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # feed_sync_timeout=0 means no timeout (passes None to wait_for)
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_stale_timeout_zero_no_timeout(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """``feed_sync_timeout=0`` → ``wait_for`` receives ``timeout=None`` (no timeout).

        When the config sets ``feed_sync_timeout=0``, the implementation passes
        ``timeout=None`` to ``asyncio.wait_for``, meaning no timeout wrapping.
        The sync should complete normally.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(return_value={"osv": 10})
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)
        config.feeds.feed_sync_timeout = 0  # Disable timeout

        result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )

    # ------------------------------------------------------------------
    # Sync failure (generic Exception) → SystemExit(EXIT_DB_ERROR)
    # ------------------------------------------------------------------

    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_db_stale_refresh_fails_blocks(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
    ) -> None:
        """Stale DB + generic sync error → SystemExit(EXIT_DB_ERROR).

        The ``except Exception`` catch-all in ``_ensure_db_fresh`` handles
        non-timeout errors (e.g., network issues, API failures) and converts
        them to ``SystemExit(EXIT_DB_ERROR)``, blocking the install.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(side_effect=RuntimeError("Network unreachable"))
        mock_feed_aggregator.return_value = mock_aggregator_instance

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with pytest.raises(SystemExit) as exc_info:
            dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert exc_info.value.code == EXIT_DB_ERROR
        mock_aggregator_instance.sync_all.assert_called_once_with(
            ecosystems=None, progress_callback=ANY, error_callback=ANY
        )


class TestCoverageTierGating:
    """Tests for CoverageTier-based gating in _run_pre_install_check().

    Coverage:
      - test_adapter_is_none_returns_early                    Guard clause returns None
      - test_audit_tier_runs_threat_skips_cooldown             AUDIT runs threat, skips cooldown
      - test_audit_tier_prints_warning                         AUDIT prints note to stderr
      - test_audit_tier_suppressed_in_quiet_mode               AUDIT warning suppressed on --quiet
      - test_audit_tier_suppressed_in_quiet_and_json           AUDIT warning + success suppressed (--quiet + --json)
      - test_audit_tier_dedup_records_even_when_quiet_suppresses_warning  Dedup records manager under --quiet
      - test_audit_tier_multiple_managers_all_suppressed_in_quiet        3 AUDIT managers, all suppressed
      - test_audit_tier_same_manager_twice_in_quiet_mode       Same manager × 2, dedup has exactly 1 entry
      - test_audit_tier_warning_routed_to_stderr               AUDIT warning routed to stderr (err=True)
      - test_partial_tier_runs_threat_check                    PARTIAL runs threat + cooldown (was: skipped)
      - test_partial_tier_prints_note                          PARTIAL prints note about threats checked
      - test_partial_tier_note_not_suppressed_in_quiet_mode    PARTIAL note not suppressed on --quiet (out-of-scope)
      - test_full_tier_runs_both_checks                        FULL runs threat + cooldown
      - test_audit_tier_threat_fails_blocks                    AUDIT threat fails → blocks
      - test_partial_tier_cooldown_fails_blocks                PARTIAL cooldown fails → blocks (threat passes)
      - test_full_tier_threat_fails_shortcircuits_cooldown     FULL threat fail → cooldown skipped
      - test_full_tier_threat_passes_cooldown_fails            FULL threat OK, cooldown fails → blocked
      - test_partial_tier_threat_fails_blocks                  PARTIAL threat fail → cooldown skipped (NEW)
      - test_partial_tier_threat_counts_in_audit_event         PARTIAL PASS includes threat counts (NEW)
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self) -> ParsedCommand:
        """Create a ParsedCommand with no packages (skips local/VCS checks)."""
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags={},
        )

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    def test_adapter_is_none_returns_early(self) -> None:
        """Guard clause: self.adapter is None → return early without checks."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = None

        result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_runs_threat_skips_cooldown(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """AUDIT tier: threat check is called, cooldown check is skipped."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

        with patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle:
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_not_called()
        mock_handle.assert_called_once()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_prints_warning(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """AUDIT tier: cooldown-skipped note and per-package success messages printed."""
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[PackageRef(name="requests")],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        # Resolved + Threat pass + cooldown-skipped = 3 calls
        assert mock_echo.call_count == 3
        call_args_list = [args[0][0] for args in mock_echo.call_args_list]
        cooldown_text = next(a for a in call_args_list if "Cooldown check skipped" in a)
        assert "AUDIT-tier support" in cooldown_text
        resolved_text = next(a for a in call_args_list if "Resolved" in a)
        assert "requests" in resolved_text
        threat_text = next(a for a in call_args_list if "Threat check passed" in a)
        assert "requests" in threat_text

    def test_audit_tier_warning_once_per_session(self) -> None:
        """AUDIT cooldown-skipped note prints only on first dispatch per manager, per session."""
        ManagerDispatcher._warned_audit_managers.clear()

        with (
            patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh") as mock_db,
            patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats") as mock_threats,
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            mock_db.return_value = True
            mock_threats.return_value = ThreatCheckResult(passed=True, threat_count_general=0, threat_count_versioned=0)

            # First dispatch for "pip" → cooldown-skipped note should print
            d1 = self._make_dispatcher()
            d1.adapter = MagicMock()
            d1.adapter.coverage_tier = CoverageTier.AUDIT
            d1._run_pre_install_check(self._make_parsed(), self._make_ctx())

            # Second dispatch for "pip" → note should NOT print
            d2 = self._make_dispatcher()
            d2.adapter = MagicMock()
            d2.adapter.coverage_tier = CoverageTier.AUDIT
            d2._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # Note should have been printed exactly once
        # (no package loop output since packages=[])
        assert mock_echo.call_count == 1
        call_args_list = [args[0][0] for args in mock_echo.call_args_list]
        note_count = sum(1 for a in call_args_list if "Cooldown check skipped" in a)
        assert note_count == 1, f"Expected 1 cooldown-skipped note, got {note_count}"

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_suppressed_in_quiet_mode(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--quiet suppresses the AUDIT-tier cooldown-skipped note.

        The cooldown-skipped note is informational and must be suppressed
        in quiet mode. Resolution and threat pass messages are NOT suppressed
        by --quiet (they are structural pass output).
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT
        parsed = self._make_parsed()

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        # The cooldown-skipped note must be suppressed when --quiet is active.
        call_args_list = [args[0][0] for args in mock_echo.call_args_list]
        note_count = sum(1 for a in call_args_list if "Cooldown check skipped" in a)
        assert note_count == 0, (
            f"--quiet must suppress the AUDIT cooldown-skipped note, got {note_count} note(s) in: {call_args_list!r}"
        )

    # ------------------------------------------------------------------
    # Plan C: --quiet interaction edge cases (added by tester)
    #
    # The builder's `test_audit_tier_suppressed_in_quiet_mode` proves the
    # happy path: --quiet alone suppresses the AUDIT warning. The tests
    # below prove the unhappy paths: --quiet combined with --json, dedup
    # state under --quiet, multiple managers, the same manager called
    # twice, the PARTIAL-tier asymmetry that Plan C intentionally leaves
    # intact, and the err=True stream routing.
    # ------------------------------------------------------------------

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_suppressed_in_quiet_and_json(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--quiet + --json together: all AUDIT pass messages are suppressed.

        Under (--quiet, --json) all messages are suppressed — the
        cooldown-skipped note by either guard, and the per-package
        pass messages by --json alone. The combined behavior is
        ``mock_echo.assert_not_called()``.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags={"json": True},
        )

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        # Under (--json, --quiet) the warning is suppressed by the
        # combined guard and the success message is suppressed by the
        # --json-only guard. No click.echo call should fire.
        mock_echo.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_dedup_records_even_when_quiet_suppresses_warning(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """Dedup set records the manager even when --quiet suppresses the note.

        Edge case: the ``self._warned_audit_managers.add(self.manager_name)``
        call runs BEFORE the suppression check.
        This means a manager encountered in quiet mode is still added
        to the dedup set. A subsequent non-quiet dispatch for the same
        manager must therefore NOT print the cooldown-skipped note, because the
        manager is already in the set.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        # First dispatch: --quiet → warning suppressed, but manager
        # MUST be added to the dedup set.
        d_quiet = self._make_dispatcher()
        d_quiet.adapter = MagicMock()
        d_quiet.adapter.coverage_tier = CoverageTier.AUDIT

        with (
            patch.object(click, "echo") as mock_echo_quiet,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            d_quiet._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # The warning must be suppressed on --quiet.
        quiet_call_args = [args[0][0] for args in mock_echo_quiet.call_args_list]
        quiet_warning_count = sum(1 for a in quiet_call_args if "Cooldown check skipped" in a)
        assert quiet_warning_count == 0, (
            f"--quiet must suppress the AUDIT-tier warning, got {quiet_warning_count} warning(s)"
        )
        # The dedup set MUST record the manager even when the
        # message is suppressed (add() happens before the guard).
        assert "pip" in ManagerDispatcher._warned_audit_managers, (
            "Dedup set must record the manager even when --quiet "
            "suppresses the warning — add() must run "
            "before the suppression guard."
        )
        assert len(ManagerDispatcher._warned_audit_managers) == 1, (
            f"Expected exactly 1 entry in _warned_audit_managers, "
            f"got {len(ManagerDispatcher._warned_audit_managers)}: "
            f"{ManagerDispatcher._warned_audit_managers!r}"
        )

        # Second dispatch: NOT --quiet → warning MUST still NOT print
        # because the manager is already in the dedup set.
        d_loud = self._make_dispatcher()
        d_loud.adapter = MagicMock()
        d_loud.adapter.coverage_tier = CoverageTier.AUDIT

        with (
            patch.object(click, "echo") as mock_echo_loud,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=False),
        ):
            d_loud._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # The warning must NOT print — the dedup already has 'pip'
        # from the suppressed first dispatch.
        loud_call_args = [args[0][0] for args in mock_echo_loud.call_args_list]
        loud_warning_count = sum(1 for a in loud_call_args if "Cooldown check skipped" in a)
        assert loud_warning_count == 0, (
            f"Dedup from --quiet dispatch must carry over to "
            f"non-quiet dispatch; got {loud_warning_count} warning(s) "
            f"on the second call: {loud_call_args!r}"
        )

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_multiple_managers_all_suppressed_in_quiet(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """Multiple AUDIT managers under --quiet: all warnings suppressed, all in dedup.

        Edge case: 3 different AUDIT-tier managers (brew, port, scoop)
        in quiet mode. None of them should print the warning, and all
        3 must be recorded in the dedup set so a subsequent
        non-quiet dispatch won't re-print any of them.

        Previously: The builder's quiet-mode test only exercised a
        single manager. A regression that broke the dedup for any
        subset of managers (e.g., by short-circuiting early on
        manager mismatch) would not be caught.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        manager_names = ["brew", "port", "scoop"]

        for name in manager_names:
            dispatcher = self._make_dispatcher()
            dispatcher.manager_name = name
            dispatcher.adapter = MagicMock()
            dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

            with (
                patch.object(click, "echo") as mock_echo,
                patch("pkg_defender.cli.exec.handle_cleared_command"),
                patch("pkg_defender.display.is_quiet_mode", return_value=True),
            ):
                dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

            # Each manager's warning must be suppressed.
            call_args = [args[0][0] for args in mock_echo.call_args_list]
            warning_count = sum(1 for a in call_args if "Cooldown check skipped" in a)
            assert warning_count == 0, (
                f"--quiet must suppress the AUDIT-tier warning for "
                f"manager {name!r}, got {warning_count} warning(s) in: "
                f"{call_args!r}"
            )

        # All 3 managers must be in the dedup set after the loop,
        # even though no warning was emitted. This proves the add()
        # ran for every manager (it runs before the suppression guard).
        assert ManagerDispatcher._warned_audit_managers == set(manager_names), (
            f"All 3 AUDIT managers must be in _warned_audit_managers even "
            f"when --quiet suppressed all warnings. Expected "
            f"{set(manager_names)!r}, got "
            f"{ManagerDispatcher._warned_audit_managers!r}"
        )

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_same_manager_twice_in_quiet_mode(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """Same manager called twice under --quiet: dedup set has exactly 1 entry, no warnings.

        Edge case: the same AUDIT manager dispatched twice in quiet
        mode. The dedup set must NOT double-add (it's a set, not a
        list), and no warning should print on either call. The set
        must end with exactly 1 entry — the manager name — proving
        the dedup is functioning correctly under --quiet.

        Previously: The existing
        ``test_audit_tier_warning_once_per_session`` exercises the
        dedup WITHOUT --quiet. It would not catch a regression
        specific to the --quiet code path (e.g., if --quiet
        somehow re-added the manager to a separate set, or cleared
        the set on each call).
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh") as mock_db,
            patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats") as mock_threats,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            mock_db.return_value = True
            mock_threats.return_value = ThreatCheckResult(passed=True, threat_count_general=0, threat_count_versioned=0)

            # First dispatch under --quiet.
            d1 = self._make_dispatcher()
            d1.adapter = MagicMock()
            d1.adapter.coverage_tier = CoverageTier.AUDIT
            d1._run_pre_install_check(self._make_parsed(), self._make_ctx())

            # Second dispatch under --quiet, same manager.
            d2 = self._make_dispatcher()
            d2.adapter = MagicMock()
            d2.adapter.coverage_tier = CoverageTier.AUDIT
            d2._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # No warning should have printed on either call.
        call_args = [args[0][0] for args in mock_echo.call_args_list]
        warning_count = sum(1 for a in call_args if "Cooldown check skipped" in a)
        assert warning_count == 0, (
            f"--quiet must suppress the AUDIT-tier warning on every "
            f"call; got {warning_count} warning(s) in: {call_args!r}"
        )

        # The dedup set must contain exactly 1 entry — the manager
        # name — not 0 (no add) and not 2 (double-add via a buggy
        # path).
        assert len(ManagerDispatcher._warned_audit_managers) == 1, (
            f"Dedup set must contain exactly 1 entry after 2 quiet "
            f"dispatches, got {len(ManagerDispatcher._warned_audit_managers)}: "
            f"{ManagerDispatcher._warned_audit_managers!r}"
        )
        assert "pip" in ManagerDispatcher._warned_audit_managers

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_warning_routed_to_stderr(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """AUDIT-tier warning is routed to stderr (``err=True``), not stdout.

        Edge case: ``click.echo`` defaults to ``err=False`` (stdout).
        The AUDIT-tier warning explicitly passes ``err=True`` so
        the warning goes to stderr. This test pins that contract
        — a regression that removed the ``err=True`` kwarg would
        silently route the warning to stdout, breaking the contract
        that ``pkgd ... > output.json`` keeps the warning out of
        the JSON output stream.

        Previously: No existing test verified the stream routing of
        the AUDIT-tier warning. The plan documents ``err=True``, but
        the test suite never asserted on it.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=False),
        ):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # Find the warning call and verify it was passed err=True.
        warning_calls = [call for call in mock_echo.call_args_list if "Cooldown check skipped" in call.args[0]]
        assert len(warning_calls) == 1, (
            f"Expected exactly 1 AUDIT-tier warning call, got {len(warning_calls)}: {mock_echo.call_args_list!r}"
        )
        warning_call = warning_calls[0]
        assert warning_call.kwargs.get("err") is True, (
            f"AUDIT-tier warning must be routed to stderr via err=True, got kwargs: {warning_call.kwargs!r}"
        )

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_note_not_suppressed_in_quiet_mode(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL-tier "Note:" is NOT suppressed on --quiet (documented Plan C out-of-scope).

        Edge case: Plan C intentionally adds ``is_quiet_mode()`` to
        the AUDIT-tier warning guard but NOT to the PARTIAL-tier
        "Note:" guard or the success-message guards. The
        design rationale is that the PARTIAL "Note:" is a
        user-confirmation that the threat + cooldown checks both
        ran — the user wants to see it even on --quiet. The
        asymmetry is documented in the plan's "Concerns for the
        Plan-Reviewer" item #4 and is flagged for a future plan.

        This test LOCKS IN the current behavior so that any
        future change (e.g., a follow-up plan that decides to
        also suppress PARTIAL on --quiet) must update the test as
        part of the change. A regression that accidentally added
        ``is_quiet_mode()`` to the PARTIAL guard would fail this
        test.

        Previously: The builder's test added ``is_quiet_mode()`` to
        the AUDIT guard but did not test that the PARTIAL guard
        was NOT similarly modified. A copy-paste error that
        applied the same fix to PARTIAL would have gone unnoticed.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[PackageRef(name="requests")],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with (
            patch.object(dispatcher, "_build_release_date_map") as mock_map,
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            mock_map.return_value = {
                "requests": (datetime.now(UTC), "pypi_json"),
            }
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        # Per-package messages (Resolved + Threat + Cooldown) are all
        # expected to fire even under --quiet. Plan C explicitly leaves
        # the PARTIAL guard at ``if not parsed.pkgd_flags.get("json"):``
        # only, with no ``is_quiet_mode()`` check.
        call_args = [args[0][0] for args in mock_echo.call_args_list]

        resolved_count = sum(1 for a in call_args if "Resolved" in a)
        assert resolved_count == 1, (
            f"PARTIAL-tier 'Resolved' must print even under --quiet "
            f"(Plan C out-of-scope); got {resolved_count} "
            f"note(s) in: {call_args!r}"
        )

        cooldown_passed_count = sum(1 for a in call_args if "Cooldown check passed" in a)
        assert cooldown_passed_count == 1, (
            f"PARTIAL 'Cooldown check passed' must print even "
            f"under --quiet (Plan C out-of-scope); got "
            f"{cooldown_passed_count} success message(s) in: "
            f"{call_args!r}"
        )

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_runs_threat_check(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier: threat check is now called (same as FULL tier)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        with patch("pkg_defender.cli.exec.handle_cleared_command"):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_called_once()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_prints_note(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier: per-package resolved/threat/cooldown messages printed."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[PackageRef(name="requests")],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with (
            patch.object(dispatcher, "_build_release_date_map") as mock_map,
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            mock_map.return_value = {
                "requests": (datetime.now(UTC), "pypi_json"),
            }
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        # Resolved + Threat check passed + Cooldown check passed = 3 calls
        assert mock_echo.call_count == 3
        call_args_list = [args[0][0] for args in mock_echo.call_args_list]
        resolved_text = next(a for a in call_args_list if "Resolved" in a)
        assert "requests" in resolved_text
        threat_text = next(a for a in call_args_list if "Threat check passed" in a)
        assert "requests" in threat_text
        cooldown_text = next(a for a in call_args_list if "Cooldown check passed" in a)
        assert "cooldown window" in cooldown_text

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_full_tier_runs_both_checks(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """FULL tier: both threat and cooldown checks are called (existing behavior)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        with patch("pkg_defender.cli.exec.handle_cleared_command"):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_called_once()

    # ------------------------------------------------------------------
    # Failure-path tests
    # ------------------------------------------------------------------

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_tier_threat_fails_blocks(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """AUDIT tier: threat check fails → blocks install (returns None)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(passed=False)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

        result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []
        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_cooldown_fails_blocks(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier: cooldown fails → blocks install (returns None)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(
            passed=False,
            cooldown_pass=False,
            cooldown_days_remaining=5,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []
        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_called_once()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_full_tier_threat_fails_shortcircuits_cooldown(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """FULL tier: threat fails → cooldown is NOT called (short-circuit AND)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(passed=False)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []
        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_full_tier_threat_passes_cooldown_fails(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """FULL tier: threat passes but cooldown fails → blocked, handle_cleared_command NOT called."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(
            passed=False,
            cooldown_pass=False,
            cooldown_days_remaining=5,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        with patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle:
            result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []
        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_called_once()
        mock_handle.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_threat_fails_blocks(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier: threat fails → blocks install, cooldown NOT called (short-circuit)."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(passed=False)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        result = dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        assert result == []
        mock_check_threats.assert_called_once()
        mock_check_cooldown.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_partial_tier_threat_counts_in_audit_event(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier PASS: audit event includes threat counts from threat check."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=3,
            threat_count_versioned=2,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        pkg = PackageRef(name="requests", version="2.31.0", ecosystem="pip")
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.31.0"],
            pkgd_flags={},
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count >= 1
        for call_args in mock_log.call_args_list:
            assert call_args.kwargs["verdict"] == "PASS"
            assert call_args.kwargs["threat_count_general"] == 3
            assert call_args.kwargs["threat_count_versioned"] == 2

    # ------------------------------------------------------------------
    # Audit event wiring tests (A-048)
    # ------------------------------------------------------------------

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_wired_pass_full_tier(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """A PASS for FULL tier calls _log_audit_event with verdict='PASS'."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        pkg = PackageRef(name="requests", version="2.31.0", ecosystem="pip")
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.31.0"],
            pkgd_flags={},
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count >= 1
        for call_args in mock_log.call_args_list:
            assert call_args.kwargs["verdict"] == "PASS"
            assert "fail_on_threat_enabled" in call_args.kwargs
            assert "cooldown_enabled" in call_args.kwargs
            assert "coverage_tier" in call_args.kwargs

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_wired_pass_audit_tier(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """A PASS for AUDIT tier calls _log_audit_event with verdict='PASS'."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        pkg = PackageRef(name="requests", version="2.31.0", ecosystem="pip")
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.31.0"],
            pkgd_flags={},
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count >= 1
        for call_args in mock_log.call_args_list:
            assert call_args.kwargs["verdict"] == "PASS"
            assert "fail_on_threat_enabled" in call_args.kwargs
            assert "cooldown_enabled" in call_args.kwargs
            assert "coverage_tier" in call_args.kwargs

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_wired_pass_partial_tier(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """A PASS for PARTIAL tier calls _log_audit_event with verdict='PASS' and threat counts."""
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=3,
            threat_count_versioned=2,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(passed=True, cooldown_pass=True)

        pkg = PackageRef(name="requests", version="2.31.0", ecosystem="pip")
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.31.0"],
            pkgd_flags={},
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count >= 1
        for call_args in mock_log.call_args_list:
            assert call_args.kwargs["verdict"] == "PASS"
            assert call_args.kwargs["threat_count_general"] == 3
            assert call_args.kwargs["threat_count_versioned"] == 2
            assert "fail_on_threat_enabled" in call_args.kwargs
            assert "cooldown_enabled" in call_args.kwargs
            assert "coverage_tier" in call_args.kwargs

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_wired_blocked_local_path(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """LOCAL_PATH writes audit event with verdict='PASS'."""
        mock_ensure_db_fresh.return_value = True

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg = PackageRef(name="mypkg", version="1.0.0", ecosystem="pip", source=InstallSource.LOCAL_PATH)
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "./mypkg"],
            pkgd_flags={},
        )

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_blocked_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count == 1
        assert mock_log.call_args.kwargs["verdict"] == "PASS"
        assert mock_log.call_args.kwargs["exit_code"] == 0

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_audit_wired_blocked_vcs_source(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """VCS_SOURCE writes audit event with verdict='WARN'."""
        mock_ensure_db_fresh.return_value = True

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg = PackageRef(name="mypkg", version="1.0.0", ecosystem="pip", source=InstallSource.VCS)
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "git+https://example.com/mypkg"],
            pkgd_flags={},
        )

        with (
            patch.object(dispatcher, "_log_audit_event") as mock_log,
            patch("pkg_defender.cli.exec.handle_blocked_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_log.call_count == 1
        assert mock_log.call_args.kwargs["verdict"] == "WARN"
        assert mock_log.call_args.kwargs["exit_code"] == 0

    def test_pkgd_disabled_env_var_has_no_effect(self) -> None:
        """PKGD_DISABLED=1 must NOT bypass security checks."""
        dispatcher = self._make_dispatcher()
        mock_adapter = MagicMock()
        mock_adapter.parse.return_value = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[PackageRef(name="requests", version="1.0.0")],
            raw_args=["pip", "install", "requests"],
            manager="pip",
            pkgd_flags={},
        )
        mock_adapter.coverage_tier = CoverageTier.AUDIT
        dispatcher.adapter = mock_adapter

        ctx = self._make_ctx()

        with (
            patch.dict("os.environ", {"PKGD_DISABLED": "1"}),
            patch.object(dispatcher, "_ensure_db_fresh") as mock_db,
            patch.object(dispatcher, "_check_threats", return_value=ThreatCheckResult(passed=True)),
            patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            dispatcher.run(["pip", "install", "requests"], ctx)

        # Normal security path MUST run
        mock_db.assert_called_once()  # DB freshness checked
        # Command follows normal path (not bypass exec)
        mock_exec.assert_not_called()
        # handle_cleared_command is called after security checks pass
        mock_handle.assert_called_once()

    # ------------------------------------------------------------------
    # checks_performed value verification
    # ------------------------------------------------------------------

    @patch("pkg_defender.audit.cooldown.step_check_cooldown")
    def test_partial_tier_cooldown_block_sets_checks_performed_full(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """PARTIAL tier: cooldown block passes checks_performed='full' (both checks run)."""
        mock_step_check.return_value = (False, 5)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.28.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (datetime.now(UTC), "verified"),
        }

        result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False
        assert result.block_decision is not None
        assert result.block_decision.checks_performed == "full"

    @patch("pkg_defender.audit.cooldown.step_check_cooldown")
    def test_full_tier_cooldown_block_sets_checks_performed_full(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """FULL tier: cooldown block passes checks_performed='full'."""
        mock_step_check.return_value = (False, 5)

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.28.0"],
            pkgd_flags={},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (datetime.now(UTC), "verified"),
        }

        result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False
        assert result.block_decision is not None
        assert result.block_decision.checks_performed == "full"


class TestReleaseDateWiring:
    """Tests that _build_release_date_map() feeds real dates into cooldown.

    Coverage:
      - test_release_date_map_feeds_into_cooldown  _build_release_date_map() produces
        non-empty dict → _check_cooldown() receives real dates → cooldown passes
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self) -> ParsedCommand:
        """Create a ParsedCommand with a known package (matches seeded timestamps)."""
        pkg_ref = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    def test_release_date_map_feeds_into_cooldown(self, tmp_path: Path) -> None:
        """_build_release_date_map() queries DB and passes real dates to cooldown.

        REGRESSION TEST for A-001 cooldown empty-dict bug.
        Before the fix, release_dates was always {} (all packages blocked).
        After the fix, _build_release_date_map() queries version_timestamps
        from the DB and passes real dates to _check_cooldown().

        This test FAILS if _build_release_date_map() is removed from the
        _run_pre_install_check() chain or returns empty dict.
        """
        from datetime import UTC, datetime, timedelta

        from pkg_defender.db.schema import init_db

        # Create temp DB with version_timestamps seeded for requests==2.0.0
        # Use a timestamp 30 days ago — well past the 3-day default cooldown
        db_path = tmp_path / "test_timestamps.db"
        conn = init_db(db_path)
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
        conn.commit()
        conn.close()

        with (
            patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh", return_value=True),
            patch(
                "pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats",
                return_value=ThreatCheckResult(passed=True, threat_count_general=0, threat_count_versioned=0),
            ),
            patch("pkg_defender.cli.exec.handle_cleared_command") as mock_handle,
            patch("pkg_defender.config.get_db_path", return_value=db_path),
        ):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = MagicMock()
            dispatcher.adapter.coverage_tier = CoverageTier.FULL

            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

            # If _build_release_date_map() returned real dates and cooldown
            # passed, handle_cleared_command was called.
            mock_handle.assert_called_once()


class TestEnsureDbFreshWiring:
    """Tests that _ensure_db_fresh() triggers feed sync on stale DB.

    Coverage:
      - test_stale_db_triggers_refresh_from_ensure_db_fresh  Stale feed_state
        in the DB causes _ensure_db_fresh() to call FeedAggregator.sync_all()
        when called directly.
      - test_pre_install_check_calls_ensure_db_fresh_before_async  Call-ordering
        regression test for PLAN-01 timeout fix.
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses ``__init__``)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_config(self, threshold_hours: int = 8) -> PKGDConfig:
        """Create a config with a specific staleness threshold.

        Args:
            threshold_hours: Staleness threshold in hours.

        Returns:
            PKGDConfig with the given staleness threshold.
        """
        config = PKGDConfig()
        config.feeds.staleness_threshold_hours = threshold_hours
        return config

    def _make_parsed(self) -> ParsedCommand:
        """Create a minimal ParsedCommand (no packages — skips cooldown/threat)."""
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags={},
        )

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    def test_stale_db_triggers_refresh_from_ensure_db_fresh(
        self,
        tmp_path: Path,
    ) -> None:
        """_ensure_db_fresh() syncs stale DB when called directly.

        REGRESSION TEST for A-003 stale DB refresh wiring.
        After PLAN-01, _ensure_db_fresh() is called from ManagerDispatcher.run()
        instead of _run_pre_install_check(). This test verifies the underlying
        method still works correctly.

        This test FAILS if _ensure_db_fresh() stops syncing stale DBs.
        """
        from datetime import UTC, datetime, timedelta

        from pkg_defender.db.schema import init_db

        # Create temp DB with stale feed_state
        db_path = tmp_path / "test_stale.db"
        conn = init_db(db_path)
        conn.execute(
            "INSERT OR REPLACE INTO feed_state "
            "(feed_name, last_sync, cursor, status, error_message, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "osv",
                (datetime.now(UTC) - timedelta(hours=30)).isoformat(),
                None,
                "idle",
                None,
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch("pkg_defender.intel.aggregator.FeedAggregator") as mock_feed_agg,
        ):
            mock_aggregator_instance = MagicMock()
            mock_aggregator_instance.sync_all = AsyncMock()
            mock_feed_agg.return_value = mock_aggregator_instance

            dispatcher = self._make_dispatcher()
            config = self._make_config(threshold_hours=8)
            ctx = self._make_ctx()

            # Call _ensure_db_fresh directly (new call site)
            dispatcher._ensure_db_fresh(config, ctx)

            # Verify sync was triggered
            mock_feed_agg.assert_called_once()
            mock_aggregator_instance.sync_all.assert_called_once()

    @patch("pkg_defender.registry.get_adapter_class_for_manager")
    def test_pre_install_check_calls_ensure_db_fresh_before_async(
        self,
        mock_get_adapter: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_ensure_db_fresh() is called BEFORE _run_pre_install_check_async().

        REGRESSION TEST for PLAN-01 timeout fix. Before the fix,
        _ensure_db_fresh() was called inside asyncio.wait_for, so a slow
        feed sync could trigger a 30s TimeoutError. After the fix,
        _ensure_db_fresh() completes BEFORE the wait_for scope begins.

        This test FAILS if _ensure_db_fresh() is moved back inside the
        async timeout scope, or if the call order in run() is changed.
        """
        # Track call order via side effects on mocked methods
        call_order: list[str] = []

        mock_adapter = MagicMock()
        mock_parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[],
        )
        mock_adapter.parse.return_value = mock_parsed
        mock_get_adapter.return_value = MagicMock(return_value=mock_adapter)

        db_path = tmp_path / "threats.db"
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: db_path,
        )

        dispatcher = ManagerDispatcher("pip")

        def record_ensure_db_fresh(*args: object, **kwargs: object) -> bool:
            call_order.append("ensure_db_fresh")
            return True

        async def record_async_check(*args: object, **kwargs: object) -> None:
            call_order.append("pre_install_check_async")

        with (
            patch.object(
                dispatcher,
                "_ensure_db_fresh",
                side_effect=record_ensure_db_fresh,
            ),
            patch.object(
                dispatcher,
                "_run_pre_install_check_async",
                side_effect=record_async_check,
            ),
            patch("pkg_defender.cli.exec.exec_cleared_command"),
        ):
            dispatcher.run(["install", "requests"], MagicMock())

        assert call_order == ["ensure_db_fresh", "pre_install_check_async"], (
            f"_ensure_db_fresh must be called before pre-install check. Got call order: {call_order}"
        )

    @patch("pkg_defender.registry.get_adapter_class_for_manager")
    def test_run_injects_ecosystem_to_ensure_db_fresh(
        self,
        mock_get_adapter: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """run() resolves adapter.ecosystem and passes it to _ensure_db_fresh().

        Verifies that ecosystems=["pypi"] is passed when the pip adapter
        has ecosystem="pypi".
        """
        mock_adapter = MagicMock()
        mock_adapter.ecosystem = "pypi"
        mock_parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[],
        )
        mock_adapter.parse.return_value = mock_parsed
        mock_get_adapter.return_value = MagicMock(return_value=mock_adapter)

        db_path = tmp_path / "threats.db"
        monkeypatch.setattr(
            "pkg_defender.config.get_db_path",
            lambda: db_path,
        )

        dispatcher = ManagerDispatcher("pip")

        with (
            patch.object(dispatcher, "_ensure_db_fresh") as mock_ensure_db,
            patch("pkg_defender.cli.exec.exec_cleared_command"),
        ):
            dispatcher.run(["install", "requests"], MagicMock())

        mock_ensure_db.assert_called_once()
        call_kwargs = mock_ensure_db.call_args.kwargs
        assert call_kwargs.get("ecosystems") == ["pypi"], (
            f"Expected ecosystems=['pypi'], got {call_kwargs.get('ecosystems')}"
        )


# ---------------------------------------------------------------------------
# Tests: dispatcher metric wiring
# ---------------------------------------------------------------------------


class TestThreatCheckDurationMetric:
    """Tests that ``_check_threats()`` correctly times operations."""

    def _make_dispatcher(self) -> ManagerDispatcher:
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self) -> ParsedCommand:
        pkg_ref = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

    def _make_ctx(self, fail_on_threat: bool = True) -> MagicMock:
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": fail_on_threat}
        return ctx

    @patch("pkg_defender.core.checker.check_packages_batch")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.cli.dispatcher.get_connection")
    def test_threat_check_observes_duration(
        self,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_check_batch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """``_check_threats()`` returns a result with correct timing."""
        mock_db_path = tmp_path / "test.db"
        mock_db_path.touch()  # Ensure exists
        mock_get_db_path.return_value = mock_db_path

        # Return a non-blocking CheckResult for the parsed package
        mock_check_batch.return_value = {
            ("pypi", "requests", "2.0.0"): CheckResult(
                blocked=False,
                highest_score=0.0,
                highest_severity="UNKNOWN",
            ),
        }

        dispatcher = self._make_dispatcher()
        result = dispatcher._check_threats(self._make_parsed(), self._make_ctx(fail_on_threat=True))

        # With non-blocking results, the method returns True
        assert result.passed is True


class TestCooldownCheckDurationMetric:
    """Tests that ``_check_cooldown()`` correctly validates cooldown checks."""

    def _make_dispatcher(self) -> ManagerDispatcher:
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self) -> ParsedCommand:
        pkg_ref = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

    def _make_ctx(self) -> MagicMock:
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    @patch("pkg_defender.audit.cooldown.step_check_cooldown", return_value=(True, 0))
    def test_cooldown_check_observes_duration(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """``_check_cooldown()`` returns a passing result."""
        dispatcher = self._make_dispatcher()
        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (datetime.now(UTC), "verified"),
        }
        result = dispatcher._check_cooldown(self._make_parsed(), self._make_ctx(), release_dates)

        assert result.passed is True

    @patch("pkg_defender.audit.cooldown.step_check_cooldown", return_value=(True, 0))
    def test_cooldown_check_falls_back_to_manager_ecosystem_when_packages_empty(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """When ``parsed.packages`` is empty, ecosystem falls back to ``self.manager_name``."""
        dispatcher = self._make_dispatcher()
        empty_parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags={},
        )
        result = dispatcher._check_cooldown(empty_parsed, self._make_ctx(), {})

        assert result.passed is True


class TestCooldownFlagOverride:
    """Tests for ``--cooldown`` flag wiring through ``_check_cooldown()``.

    Validates that ``parsed.pkgd_flags["cooldown"]`` is extracted, converted
    to an int, and passed as ``override_hours`` to ``step_check_cooldown()``.
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    @patch("pkg_defender.audit.cooldown.step_check_cooldown", return_value=(True, 0))
    def test_cooldown_flag_wired_to_step_check(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """``--cooldown`` flag value is extracted and passed as ``override_hours``."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        pkg = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0", "--cooldown", "48"],
            pkgd_flags={"cooldown": "48"},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        release_dates: dict[str, tuple[datetime | None, str]] = {
            "requests": (datetime.now(UTC), "verified"),
        }

        with patch("pkg_defender.cli.exec.handle_blocked_command"):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is True

        # Verify step_check_cooldown was called with override_hours=48
        mock_step_check.assert_called()
        _, call_kwargs = mock_step_check.call_args
        assert call_kwargs.get("override_hours") == 48

    @patch("pkg_defender.audit.cooldown.step_check_cooldown", return_value=(True, 0))
    def test_cooldown_flag_invalid_value_ignored(
        self,
        mock_step_check: MagicMock,
    ) -> None:
        """Invalid ``--cooldown`` value (non-numeric) is silently ignored."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        pkg = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        parsed = ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests", "--cooldown", "abc"],
            pkgd_flags={"cooldown": "abc"},
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        with patch("pkg_defender.cli.exec.handle_blocked_command"):
            result = dispatcher._check_cooldown(parsed, ctx, {})

        assert result.passed is True

        # override_hours should be None (invalid value silently ignored)
        _, call_kwargs = mock_step_check.call_args
        override = call_kwargs.get("override_hours")
        assert override is None, f"Expected None for invalid cooldown value, got {override}"


class TestThreatContextPipeline:
    """Pipeline integration tests for threat context threading.

    Validates that ``threat_context_map`` from ``_check_threats()`` is
    forwarded through ``_check_cooldown()`` to ``step_check_cooldown()``
    for both PARTIAL and FULL tiers.
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self) -> ParsedCommand:
        pkg = PackageRef(
            name="requests",
            version="2.0.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

    def _make_ctx(self) -> MagicMock:
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._build_release_date_map")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    def test_threat_context_threaded_through_partial_tier(
        self,
        mock_check_threats: MagicMock,
        mock_build_release_date_map: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """PARTIAL tier: threat context forwarded to step_check_cooldown."""
        from pkg_defender.audit.cooldown import ThreatCooldownContext

        mock_ensure_db_fresh.return_value = True
        mock_build_release_date_map.return_value = {"requests": (datetime.now(UTC), "verified")}

        # Mock _check_threats to return a result with threat_context_map
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=1,
            threat_count_versioned=1,
            threat_context_map={
                "requests": ThreatCooldownContext(has_tier3_signals=True),
            },
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL

        with (
            patch(
                "pkg_defender.audit.cooldown.step_check_cooldown",
                return_value=(True, 0),
            ) as mock_step_check,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # Verify step_check_cooldown was called with correct threat_context
        mock_step_check.assert_called()
        _, call_kwargs = mock_step_check.call_args
        ctx_for_pkg = call_kwargs.get("threat_context")
        assert ctx_for_pkg is not None
        assert ctx_for_pkg.has_tier3_signals is True
        assert ctx_for_pkg.has_verified_advisory is False

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._build_release_date_map")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    def test_threat_context_threaded_through_full_tier(
        self,
        mock_check_threats: MagicMock,
        mock_build_release_date_map: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """FULL tier: threat context forwarded to step_check_cooldown."""
        from pkg_defender.audit.cooldown import ThreatCooldownContext

        mock_ensure_db_fresh.return_value = True
        mock_build_release_date_map.return_value = {"requests": (datetime.now(UTC), "verified")}

        # Mock _check_threats to return a result with threat_context_map
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=1,
            threat_count_versioned=1,
            threat_context_map={
                "requests": ThreatCooldownContext(has_tier3_signals=True),
            },
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL

        with (
            patch(
                "pkg_defender.audit.cooldown.step_check_cooldown",
                return_value=(True, 0),
            ) as mock_step_check,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # Verify step_check_cooldown was called with correct threat_context
        mock_step_check.assert_called()
        _, call_kwargs = mock_step_check.call_args
        ctx_for_pkg = call_kwargs.get("threat_context")
        assert ctx_for_pkg is not None
        assert ctx_for_pkg.has_tier3_signals is True
        assert ctx_for_pkg.has_verified_advisory is False

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    def test_threat_context_map_is_none_when_no_threats(
        self,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """When threat_context_map is None, step_check_cooldown receives None.

        AUDIT-tier path: no cooldown check, but verifies that a missing
        threat_context_map doesn't cause errors and cooldown is skipped.
        """
        mock_ensure_db_fresh.return_value = True

        # Mock _check_threats to return a result WITHOUT threat_context_map
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
            threat_context_map=None,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT

        with (
            patch(
                "pkg_defender.audit.cooldown.step_check_cooldown",
            ) as mock_step_check,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(self._make_parsed(), self._make_ctx())

        # AUDIT tier does not call _check_cooldown, so step_check_cooldown
        # should NOT be called
        mock_step_check.assert_not_called()


class TestLogAuditEvent:
    """Unit tests for ``ManagerDispatcher._log_audit_event()``.

    Validates the fail-open behavior and correct DB insertion of audit events.
    Uses an in-memory SQLite database for isolation.
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self, **overrides: object) -> ParsedCommand:
        """Create a minimal ParsedCommand for audit event testing."""
        pkg_ref = PackageRef(
            name="requests",
            version="2.31.0",
            ecosystem="pip",
            source=InstallSource.REGISTRY,
        )
        params: dict[str, object] = {
            "manager": "pip",
            "manager_subcommand": "install",
            "intent": CommandIntent.INSTALL,
            "packages": [pkg_ref],
            "raw_args": ["pip", "install", "requests==2.31.0"],
            "pkgd_flags": {},
        }
        params.update(overrides)
        return ParsedCommand(**params)  # type: ignore[arg-type]

    def _make_ctx(self) -> MagicMock:
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_written_on_pass(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A PASS verdict writes a row to audit_events with verdict='PASS', exit_code=0."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["verdict"] == "PASS"
            assert events[0]["exit_code"] == 0
            assert events[0]["package_name"] == "requests"
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_written_on_threat_block(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A BLOCKED threat verdict writes a row with threat counts."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="BLOCKED",
            exit_code=1,
            threat_count_general=3,
            threat_count_versioned=2,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["verdict"] == "BLOCKED"
            assert events[0]["exit_code"] == 1
            assert events[0]["threat_count_general"] == 3
            assert events[0]["threat_count_versioned"] == 2
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_written_on_cooldown_block(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A BLOCKED cooldown verdict writes a row with cooldown data."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="BLOCKED",
            exit_code=2,
            cooldown_pass=False,
            cooldown_days_remaining=3,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["verdict"] == "BLOCKED"
            assert events[0]["exit_code"] == 2
            assert events[0]["cooldown_pass"] == 0
            assert events[0]["cooldown_days_remaining"] == 3
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_fail_open_on_db_error(
        self,
        mock_get_db_path: MagicMock,
    ) -> None:
        """_log_audit_event catches exception and does not raise (fail-open)."""
        # Simulate a DB error by returning a path that can't be connected to
        mock_get_db_path.return_value = Path("/nonexistent/db/path.db")

        dispatcher = self._make_dispatcher()
        # This should NOT raise any exception
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
        )
        # If we get here without an exception, fail-open works

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_ci_mode_sets_exit_code_2(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """CI mode sets exit_code=2 for blocked cooldown."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        parsed = self._make_parsed(pkgd_flags={"ci": True})
        dispatcher._log_audit_event(
            parsed=parsed,
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="BLOCKED",
            exit_code=2,
            cooldown_pass=False,
            cooldown_days_remaining=3,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["exit_code"] == 2
            assert events[0]["ci_mode"] == 1
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_supports_multiple_packages(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Multiple packages produce one audit event row per package."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        parsed = self._make_parsed()
        packages = [
            PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            PackageRef(name="urllib3", version="1.26.0", ecosystem="pip"),
        ]

        for pkg in packages:
            dispatcher._log_audit_event(
                parsed=parsed,
                package=pkg,
                verdict="PASS",
                exit_code=0,
            )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 2
            event_names = [e["package_name"] for e in events]
            assert "requests" in event_names
            assert "urllib3" in event_names
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_with_versionless_package(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Versionless package writes audit event with version=None successfully."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version=None, ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["version"] is None or events[0]["version"] == ""
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_ecosystem_from_package_ref(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Ecosystem is taken from PackageRef when set."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()

        # PackageRef with explicit ecosystem
        pkg = PackageRef(name="requests", version="2.31.0", ecosystem="pypi")
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=pkg,
            verdict="PASS",
            exit_code=0,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            # ecosystem should be "pypi" (from PackageRef), not "pip" (from manager)
            assert events[0]["ecosystem"] == "pypi"
        finally:
            conn.close()

    @patch("pkg_defender.cli.dispatcher.get_connection")
    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_written_via_get_connection_wrapper(
        self,
        mock_get_db_path: MagicMock,
        mock_get_connection: MagicMock,
        tmp_path: Path,
    ) -> None:
        """_log_audit_event uses get_connection() instead of raw sqlite3.connect()."""
        db_path = tmp_path / "test_audit.db"
        # Create the file so _log_audit_event passes its guard clause
        db_path.touch()
        mock_get_db_path.return_value = db_path
        mock_conn = MagicMock()
        mock_get_connection.return_value = mock_conn

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
        )

        mock_get_connection.assert_called_once_with(db_path)

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_stores_fail_on_threat_enabled(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """fail_on_threat_enabled column is stored as 1/0 in the DB row."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
            fail_on_threat_enabled=False,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["fail_on_threat_enabled"] is False
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_stores_cooldown_enabled(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """cooldown_enabled column is stored as 1/0 in the DB row."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
            cooldown_enabled=False,
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["cooldown_enabled"] is False
        finally:
            conn.close()

    @patch("pkg_defender.config.get_db_path")
    def test_audit_event_stores_coverage_tier(
        self,
        mock_get_db_path: MagicMock,
        tmp_path: Path,
    ) -> None:
        """coverage_tier column stores the tier string value."""
        from pkg_defender.db.schema import get_audit_events, get_connection, init_db

        db_path = tmp_path / "test_audit.db"
        conn = init_db(db_path)
        conn.close()
        mock_get_db_path.return_value = db_path

        dispatcher = self._make_dispatcher()
        dispatcher._log_audit_event(
            parsed=self._make_parsed(),
            package=PackageRef(name="requests", version="2.31.0", ecosystem="pip"),
            verdict="PASS",
            exit_code=0,
            coverage_tier="audit",
        )

        conn = get_connection(db_path)
        try:
            events = get_audit_events(conn)
            assert len(events) == 1
            assert events[0]["coverage_tier"] == "audit"
        finally:
            conn.close()


class TestResolveLatestVersionsAsync:
    """Tests for ManagerDispatcher._resolve_latest_versions_async().

    Coverage:
      - test_resolve_latest_version_sets_version   Resolution succeeds → version set
      - test_resolve_latest_version_skips_existing  Package already has version → unchanged
      - test_resolve_latest_version_ci_mode_fails   CI mode resolution fails → SystemExit(1)
      - test_resolve_latest_version_interactive_warns Interactive mode resolution fails → warns
      - test_resolve_latest_version_timeout         Timeout → graceful handling, version stays None
      - test_resolve_latest_version_skips_if_no_adapter_capability  No resolve_latest_version → skip
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    @pytest.mark.asyncio
    async def test_resolve_latest_version_sets_version(self) -> None:
        """Resolution succeeds → pkg.version is set to resolved version."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(return_value="2.34.2")
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version == "2.34.2"

    @pytest.mark.asyncio
    async def test_resolve_latest_version_skips_existing(self) -> None:
        """Package with existing version → version unchanged."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(return_value="9.9.9")
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==1.0.0"],
            pkgd_flags={},
        )

        await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version == "1.0.0"
        dispatcher.adapter.resolve_latest_version.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolve_latest_version_ci_mode_fails(self) -> None:
        """CI mode + resolution failure → SystemExit(1)."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(side_effect=Exception("API unavailable"))
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={"ci": True},
        )

        with pytest.raises(SystemExit) as exc_info:
            await dispatcher._resolve_latest_versions_async(parsed)

        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_resolve_latest_version_interactive_warns(self) -> None:
        """Interactive mode + resolution failure → warning, version stays None."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(side_effect=Exception("API unavailable"))
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch.object(click, "echo") as mock_echo:
            await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version is None
        # Should have output a warning
        echo_calls = [args[0][0] for args in mock_echo.call_args_list]
        warning_text = " ".join(echo_calls)
        assert "Warning" in warning_text

    @pytest.mark.asyncio
    async def test_resolve_latest_version_timeout(self) -> None:
        """Timeout during resolution → graceful handling, version stays None."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(side_effect=TimeoutError("timed out"))
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch.object(click, "echo"):
            await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version is None

    @pytest.mark.asyncio
    async def test_resolve_latest_version_skips_if_no_adapter_capability(self) -> None:
        """Adapter without resolve_latest_version → method returns without error."""
        dispatcher = self._make_dispatcher()
        # Adapter does NOT have resolve_latest_version attribute
        dispatcher.adapter = MagicMock(spec=[])

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        # Should not raise
        await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version is None

    @pytest.mark.asyncio
    async def test_resolve_latest_version_adapter_none(self) -> None:
        """Adapter is None → method returns gracefully without error.

        Coverage gap: ``hasattr(None, "resolve_latest_version")`` returns
        ``False``, so the guard clause exits early without raising.
        """
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = None

        pkg = PackageRef(name="requests", version=None)
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        # Should not raise
        await dispatcher._resolve_latest_versions_async(parsed)

        # Version should remain None since we can't resolve without an adapter
        assert pkg.version is None

    @pytest.mark.asyncio
    async def test_resolve_latest_version_returns_none(self) -> None:
        """Adapter returns None → warning shown, version stays None."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(return_value=None)
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)

        pkg = PackageRef(name="requests", version=None)
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch.object(click, "echo") as mock_echo:
            await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version is None
        # Should have warned the user
        mock_echo.assert_called_once()
        assert "Warning" in mock_echo.call_args[0][0]

    @pytest.mark.asyncio
    async def test_resolve_latest_version_applies_config_timeout(self) -> None:
        """registry_api_timeout from config is used as the wait_for timeout."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(return_value="2.34.2")
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)
        dispatcher.adapter.ecosystem = "pypi"

        mock_config = PKGDConfig()
        mock_config.registry_api_timeout = 20.0

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.load_config", return_value=mock_config), patch.object(click, "echo"):
            await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version == "2.34.2"

    @pytest.mark.asyncio
    async def test_resolve_latest_version_applies_per_ecosystem_timeout(self) -> None:
        """per_ecosystem_registry_timeout override is used when ecosystem matches."""
        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter.resolve_latest_version = AsyncMock(return_value="2.34.2")
        dispatcher.adapter.get_release_date = AsyncMock(return_value=None)
        dispatcher.adapter.ecosystem = "pypi"

        mock_config = PKGDConfig()
        mock_config.registry_api_timeout = 20.0
        mock_config.per_ecosystem_registry_timeout = {"pypi": 5.0}

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.load_config", return_value=mock_config), patch.object(click, "echo"):
            await dispatcher._resolve_latest_versions_async(parsed)

        assert pkg.version == "2.34.2"


class TestCacheVersionTimestampsAsync:
    """Tests for ManagerDispatcher._cache_version_timestamps_async().

    Coverage:
      - test_caches_timestamp_successfully              Timestamp fetched and stored in DB
      - test_skips_when_adapter_lacks_get_release_date  No pipeline capability → skip
      - test_skips_package_with_no_version              Package with version=None → skip
      - test_handles_get_release_date_timeout           TimeoutError → log, skip, no DB write
      - test_handles_get_release_date_none              (None, "") returned → no DB write
      - test_handles_get_release_date_exception         Generic exception → log, skip, no DB write
      - test_heals_source_label_when_publish_time_none  (None, "unresolved") → heal empty label
      - test_does_not_overwrite_valid_source_label      (None, "unresolved") → valid label preserved
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    @pytest.mark.asyncio
    async def test_caches_timestamp_successfully(self, tmp_path: Path) -> None:
        """Timestamp fetched from adapter and stored in DB."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)  # Protocol requirement
        adapter.get_publish_time = AsyncMock(
            return_value=(datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "registry_api"),
        )
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()

        assert results == {
            ("pypi", "requests", "2.0.0"): (datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "registry_api"),
        }

    @pytest.mark.asyncio
    async def test_skips_when_adapter_lacks_get_release_date(self, tmp_path: Path) -> None:
        """Adapter without pipeline capability → method returns without error, no DB write."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock(spec=[])  # Not a PipelineAdapterProtocol instance

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert results == {}

    @pytest.mark.asyncio
    async def test_skips_package_with_no_version(self, tmp_path: Path) -> None:
        """Package with version=None → get_publish_time not called, no DB write."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(return_value=(datetime(2026, 1, 15, tzinfo=UTC), ""))

        pkg = PackageRef(name="requests", version=None, ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        adapter.get_publish_time.assert_not_called()

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert results == {}

    @pytest.mark.asyncio
    async def test_handles_get_release_date_timeout(self, tmp_path: Path) -> None:
        """TimeoutError from get_publish_time → logged, skipped, no DB write."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)  # Protocol requirement
        adapter.get_publish_time = AsyncMock(side_effect=TimeoutError("timed out"))
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            # Should not raise — TimeoutError is caught and logged
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert results == {}

    @pytest.mark.asyncio
    async def test_handles_get_release_date_none(self, tmp_path: Path) -> None:
        """get_publish_time returns (None, "") → no DB write."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(return_value=(None, ""))
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert results == {}

    @pytest.mark.asyncio
    async def test_heals_source_label_when_publish_time_none(self, tmp_path: Path) -> None:
        """When get_publish_time returns (None, "unresolved"), source_label is still updated.

        Regression test for the Defect 1 scenario:
        A pre-Session-39 row has a valid publish_time but empty source_label.
        On re-cache, the API fails and returns (None, "unresolved").
        Before the fix: the "continue" skips the DB update,
        leaving source_label empty → "(source: unknown)".
        After the fix: a targeted UPDATE sets source_label = "unresolved"
        → "(source: user manual)".
        """
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)

        # Seed a pre-Session-39 row: valid publish_time, empty source_label
        conn.execute(
            "INSERT INTO version_timestamps"
            " (ecosystem, package_name, version, publish_time, trust_level, source_label)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("pypi", "requests", "2.0.0", "2026-01-15T12:00:00Z", "verified", ""),
        )
        conn.commit()

        # Verify seed
        pre = conn.execute(
            "SELECT source_label FROM version_timestamps"
            " WHERE ecosystem='pypi' AND package_name='requests' AND version='2.0.0'",
        ).fetchone()
        assert pre is not None, "Seed row should exist"
        assert pre[0] == "", "Seed row should have empty source_label"
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        # API fails → returns (None, "unresolved")
        adapter.get_publish_time = AsyncMock(return_value=(None, "unresolved"))
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        # Verify: source_label healed, publish_time unchanged
        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()

        # Row must still be present
        assert ("pypi", "requests", "2.0.0") in results, "Row should still exist after cache attempt"

        dt, source = results[("pypi", "requests", "2.0.0")]
        assert source == "unresolved", (
            f"Expected source_label='unresolved', got {source!r}. "
            "Defect 1 fix must heal source_label even when publish_time is None."
        )
        assert dt is not None, "Original publish_time must NOT be overwritten with None"
        assert dt == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "Original publish_time must remain unchanged"

    @pytest.mark.asyncio
    async def test_does_not_overwrite_valid_source_label(self, tmp_path: Path) -> None:
        """Valid source_label must NOT be overwritten when publish_time is None.

        Regression test for the Step 2 guard in dispatcher.py:
        The targeted UPDATE should only modify rows with empty/NULL source_label.
        A row with a valid label (e.g., "github_tags") must be preserved
        even when the resolver returns (None, "unresolved").
        """
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)

        # Seed a row with a valid source_label from a previous successful cache
        conn.execute(
            "INSERT INTO version_timestamps"
            " (ecosystem, package_name, version, publish_time, trust_level, source_label)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("pypi", "requests", "2.0.0", "2026-01-15T12:00:00Z", "verified", "github_tags"),
        )
        conn.commit()

        # Verify seed
        pre = conn.execute(
            "SELECT source_label FROM version_timestamps"
            " WHERE ecosystem='pypi' AND package_name='requests' AND version='2.0.0'",
        ).fetchone()
        assert pre is not None, "Seed row should exist"
        assert pre[0] == "github_tags", "Seed row should have valid source_label"
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        # Resolver fails → returns (None, "unresolved")
        adapter.get_publish_time = AsyncMock(return_value=(None, "unresolved"))
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        # Verify: source_label is UNCHANGED because the row already has a valid label
        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()

        assert ("pypi", "requests", "2.0.0") in results, "Row should still exist after cache attempt"

        dt, source = results[("pypi", "requests", "2.0.0")]
        assert source == "github_tags", (
            f"Expected source_label='github_tags' (unchanged), got {source!r}. "
            "Guarded UPDATE must not overwrite valid source_labels."
        )
        assert dt is not None, "Original publish_time must NOT be overwritten with None"
        assert dt == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "Original publish_time must remain unchanged"

    @pytest.mark.asyncio
    async def test_handles_get_release_date_exception(self, tmp_path: Path) -> None:
        """Generic exception from get_publish_time → logged, skipped, no DB write."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(side_effect=Exception("API error"))
        adapter.ecosystem = "pypi"

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            # Should not raise — generic Exception is caught and logged
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert results == {}

    @pytest.mark.asyncio
    async def test_get_publish_time_applies_config_timeout(self, tmp_path: Path) -> None:
        """registry_api_timeout from config is used as the wait_for timeout for get_publish_time."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(
            return_value=(datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "registry"),
        )
        adapter.ecosystem = "pypi"

        mock_config = PKGDConfig()
        mock_config.registry_api_timeout = 20.0

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with (
            patch("pkg_defender.config.load_config", return_value=mock_config),
            patch("pkg_defender.config.get_db_path", return_value=db_path),
        ):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_get_publish_time_applies_per_ecosystem_timeout(self, tmp_path: Path) -> None:
        """per_ecosystem_registry_timeout override is used when ecosystem matches for get_publish_time."""
        from pkg_defender.db.schema import get_connection, get_version_timestamps_batch, init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.close()

        adapter = MagicMock()
        adapter.resolve_latest_version = AsyncMock(return_value=None)
        adapter.get_release_date = AsyncMock(return_value=None)
        adapter.get_publish_time = AsyncMock(
            return_value=(datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC), "registry"),
        )
        adapter.ecosystem = "pypi"

        mock_config = PKGDConfig()
        mock_config.registry_api_timeout = 20.0
        mock_config.per_ecosystem_registry_timeout = {"pypi": 5.0}

        pkg = PackageRef(name="requests", version="2.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["pip", "install", "requests==2.0.0"],
            pkgd_flags={},
        )

        with (
            patch("pkg_defender.config.load_config", return_value=mock_config),
            patch("pkg_defender.config.get_db_path", return_value=db_path),
        ):
            dispatcher = self._make_dispatcher()
            dispatcher.adapter = adapter
            await dispatcher._cache_version_timestamps_async(parsed)

        conn = get_connection(db_path)
        results = get_version_timestamps_batch(conn, "pypi", [("requests", "2.0.0")])
        conn.close()
        assert len(results) == 1


class TestCiModeResolverWarning:
    """Tests for CI-mode-aware resolver degradation warning in ``_run_pre_install_check_async``.

    Coverage:
      - ``test_ci_mode_calls_stderr_write_for_resolver_errors``
        CI mode + errors → ``_stderr_write`` called
      - ``test_interactive_mode_calls_display_resolver_warning``
        Interactive + errors → ``display_resolver_warning`` called
      - ``test_no_errors_no_warning``
        No errors → neither routing function is called
      - ``test_ci_mode_no_errors_no_warning``
        CI mode + no errors → neither function called
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses ``__init__``)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    @pytest.mark.asyncio
    async def test_ci_mode_calls_stderr_write_for_resolver_errors(self) -> None:
        """CI mode + resolver errors → ``_stderr_write`` is called, panel is not."""
        dispatcher = self._make_dispatcher()
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={"ci": True},
        )
        ctx = MagicMock()

        mock_resolver = MagicMock()
        mock_resolver.get_session_errors.return_value = {"rate_limited"}

        with (
            patch("pkg_defender.cli.exec._stderr_write") as mock_stderr,
            patch("pkg_defender.display.display_resolver_warning") as mock_panel,
            patch("pkg_defender.registry._timestamp.get_resolver", return_value=mock_resolver),
            patch.object(dispatcher, "_resolve_latest_versions_async"),
            patch.object(dispatcher, "_cache_version_timestamps_async"),
            patch.object(dispatcher, "_run_pre_install_check"),
        ):
            await dispatcher._run_pre_install_check_async(parsed, ctx)

        mock_stderr.assert_called_once()
        args, _ = mock_stderr.call_args
        assert "PKGD_GITHUB_TOKEN" in args[0] or "ghsa_token" in args[0]
        assert "github.com/settings/tokens" in args[0]
        mock_panel.assert_not_called()

    @pytest.mark.asyncio
    async def test_interactive_mode_calls_display_resolver_warning(self) -> None:
        """Interactive mode + resolver errors → ``_stderr_write`` called with plain text."""
        dispatcher = self._make_dispatcher()
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )
        ctx = MagicMock()

        mock_resolver = MagicMock()
        mock_resolver.get_session_errors.return_value = {"rate_limited"}

        with (
            patch("pkg_defender.cli.exec._stderr_write") as mock_stderr,
            patch("pkg_defender.registry._timestamp.get_resolver", return_value=mock_resolver),
            patch.object(dispatcher, "_resolve_latest_versions_async"),
            patch.object(dispatcher, "_cache_version_timestamps_async"),
            patch.object(dispatcher, "_run_pre_install_check"),
        ):
            await dispatcher._run_pre_install_check_async(parsed, ctx)

        mock_stderr.assert_called()
        all_text = " ".join(args[0][0] for args in mock_stderr.call_args_list)
        assert "PKGD_GITHUB_TOKEN" in all_text or "ghsa_token" in all_text
        assert "github.com/settings/tokens" in all_text

    @pytest.mark.asyncio
    async def test_no_errors_no_warning(self) -> None:
        """No session errors → neither routing function is called."""
        dispatcher = self._make_dispatcher()
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={},
        )
        ctx = MagicMock()

        mock_resolver = MagicMock()
        mock_resolver.get_session_errors.return_value = set()

        with (
            patch("pkg_defender.cli.exec._stderr_write") as mock_stderr,
            patch("pkg_defender.display.display_resolver_warning") as mock_panel,
            patch("pkg_defender.registry._timestamp.get_resolver", return_value=mock_resolver),
            patch.object(dispatcher, "_resolve_latest_versions_async"),
            patch.object(dispatcher, "_cache_version_timestamps_async"),
            patch.object(dispatcher, "_run_pre_install_check"),
        ):
            await dispatcher._run_pre_install_check_async(parsed, ctx)

        mock_stderr.assert_not_called()
        mock_panel.assert_not_called()

    @pytest.mark.asyncio
    async def test_ci_mode_no_errors_no_warning(self) -> None:
        """CI mode + no errors → neither routing function is called."""
        dispatcher = self._make_dispatcher()
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install", "requests"],
            pkgd_flags={"ci": True},
        )
        ctx = MagicMock()

        mock_resolver = MagicMock()
        mock_resolver.get_session_errors.return_value = set()

        with (
            patch("pkg_defender.cli.exec._stderr_write") as mock_stderr,
            patch("pkg_defender.display.display_resolver_warning") as mock_panel,
            patch("pkg_defender.registry._timestamp.get_resolver", return_value=mock_resolver),
            patch.object(dispatcher, "_resolve_latest_versions_async"),
            patch.object(dispatcher, "_cache_version_timestamps_async"),
            patch.object(dispatcher, "_run_pre_install_check"),
        ):
            await dispatcher._run_pre_install_check_async(parsed, ctx)

        mock_stderr.assert_not_called()
        mock_panel.assert_not_called()


class TestCooldownBypassEcosystemFilter:
    """Verify cooldown bypass query respects ecosystem scoping."""

    def test_cooldown_bypass_respects_ecosystem_filter(
        self,
        mock_config: MagicMock,
        runner: None,
        isolated_env: None,
    ) -> None:
        """Verify cooldown bypass query respects ecosystem scoping."""
        import sqlite3

        from pkg_defender.models.command import CommandIntent, PackageRef, ParsedCommand

        mock_conn = MagicMock(spec=sqlite3.Connection)
        mock_conn.execute.return_value.fetchall.return_value = [("requests", "2.28.0")]

        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = True

        pkg = PackageRef(name="requests", version="2.28.0", ecosystem="npm")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            raw_args=["npm", "install", "requests@2.28.0"],
            pkgd_flags={},
        )

        with (
            patch("pkg_defender.config.get_db_path", return_value=mock_db_path),
            patch("pkg_defender.db.schema.get_connection", return_value=mock_conn),
            patch("pkg_defender.audit.cooldown.step_check_cooldown"),
        ):
            disp = ManagerDispatcher.__new__(ManagerDispatcher)
            disp.adapter = MagicMock()
            disp.adapter.ecosystem = "npm"
            disp.manager_name = "npm"

            disp._check_cooldown(
                parsed=parsed,
                ctx=MagicMock(),
                release_dates={"requests": (datetime.now(), "verified")},
            )

            if mock_conn.execute.call_count > 0:
                call_args = mock_conn.execute.call_args[0]
                sql_query = call_args[0]
                sql_params = call_args[1] if len(call_args) > 1 else ()
                assert "ecosystem = ?" in sql_query, f"Cooldown bypass query missing ecosystem filter. SQL: {sql_query}"
                assert "npm" in sql_params, f"Cooldown bypass query missing npm in params. Params: {sql_params}"


class TestProtectionWarning:
    """Tests for ManagerDispatcher._check_protection_warning().

    Coverage:
      - test_secure_level_skips_warning          Secure → no console output
      - test_weakened_level_shows_warning        Weakened → Panel printed (yellow)
      - test_bypass_enabled_level_shows_warning  Bypass_enabled → Panel printed (yellow)
      - test_insecure_level_shows_warning        Insecure → Panel printed (red)
      - test_unknown_level_shows_warning         Unknown → Panel printed (red)
      - test_quiet_mode_suppresses_warning       is_quiet_mode() → suppressed
      - test_json_flag_suppresses_warning        pkgd_flags={"json": True} → suppressed
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self, pkgd_flags: dict[str, str | bool] | None = None) -> ParsedCommand:
        """Create a minimal ParsedCommand for protection warning testing."""
        return ParsedCommand(
            manager="pip",
            manager_subcommand="install",
            intent=CommandIntent.INSTALL,
            packages=[],
            raw_args=["pip", "install"],
            pkgd_flags=pkgd_flags or {},
        )

    # ------------------------------------------------------------------
    # No-warning cases (secure, quiet, JSON)
    # ------------------------------------------------------------------

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_secure_level_skips_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Level 'secure' → no console output."""
        mock_get_status.return_value = {"level": "secure", "issues": []}
        mock_console = MagicMock()

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with patch("pkg_defender.cli.common.console", mock_console):
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_console.print.assert_not_called()

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_quiet_mode_suppresses_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Quiet mode suppresses the warning panel."""
        mock_get_status.return_value = {
            "level": "weakened",
            "issues": ["Cooldown strict mode is disabled"],
        }
        mock_console = MagicMock()

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with (
            patch("pkg_defender.cli.common.console", mock_console),
            patch("pkg_defender.display.is_quiet_mode", return_value=True),
        ):
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_console.print.assert_not_called()

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_json_flag_suppresses_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """JSON output suppresses the warning panel."""
        mock_get_status.return_value = {
            "level": "weakened",
            "issues": ["Cooldown strict mode is disabled"],
        }
        mock_console = MagicMock()

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed(pkgd_flags={"json": True})
        ctx = MagicMock()

        with patch("pkg_defender.cli.common.console", mock_console):
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_console.print.assert_not_called()

    # ------------------------------------------------------------------
    # Warning cases — each protection level prints a Panel
    # ------------------------------------------------------------------

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_weakened_level_shows_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Level 'weakened' → warning text is printed."""
        mock_get_status.return_value = {
            "level": "weakened",
            "issues": ["Cooldown strict mode is disabled"],
        }

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with patch.object(click, "echo") as mock_echo:
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_echo.assert_called()
        call_args = [args[0][0] for args in mock_echo.call_args_list]
        assert any("Protection Status: Weakened" in a for a in call_args)
        assert any("Cooldown strict mode is disabled" in a for a in call_args)
        assert any("Run 'pkgd health' for full details." in a for a in call_args)

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_bypass_enabled_level_shows_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Level 'bypass_enabled' → warning text is printed."""
        mock_get_status.return_value = {
            "level": "bypass_enabled",
            "issues": ["Bypass command is enabled"],
        }

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with patch.object(click, "echo") as mock_echo:
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_echo.assert_called()
        call_args = [args[0][0] for args in mock_echo.call_args_list]
        assert any("Protection Status: Bypass Enabled" in a for a in call_args)
        assert any("Bypass command is enabled" in a for a in call_args)

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_insecure_level_shows_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Level 'insecure' → warning text is printed."""
        mock_get_status.return_value = {
            "level": "insecure",
            "issues": [
                "Threat blocking is disabled",
                "Cooldown checking is disabled",
            ],
        }

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with patch.object(click, "echo") as mock_echo:
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_echo.assert_called()
        call_args = [args[0][0] for args in mock_echo.call_args_list]
        assert any("Protection Status: Insecure" in a for a in call_args)
        assert any("Threat blocking is disabled" in a for a in call_args)
        assert any("Cooldown checking is disabled" in a for a in call_args)

    @patch("pkg_defender.cli.common._get_protection_status")
    def test_unknown_level_shows_warning(
        self,
        mock_get_status: MagicMock,
    ) -> None:
        """Level 'unknown' → warning text is printed."""
        mock_get_status.return_value = {
            "level": "unknown",
            "issues": ["Configuration could not be loaded"],
        }

        dispatcher = self._make_dispatcher()
        config = PKGDConfig()
        parsed = self._make_parsed()
        ctx = MagicMock()

        with patch.object(click, "echo") as mock_echo:
            dispatcher._check_protection_warning(config, parsed, ctx)

        mock_echo.assert_called()
        call_args = [args[0][0] for args in mock_echo.call_args_list]
        assert any("Protection Status: Unknown" in a for a in call_args)
        assert any("Configuration could not be loaded" in a for a in call_args)


class TestOSVEcosystemFiltering:
    """Tests for ecosystem filtering in OSV fetch_from_dump().

    Verifies that ecosystems not in DUMP_ECOSYSTEM_MAP (e.g., "homebrew")
    are filtered out before download, preventing the infinite re-sync loop.
    """

    @pytest.mark.asyncio
    async def test_osv_ecosystem_filtering(self) -> None:
        """Ecosystems not in DUMP_ECOSYSTEM_MAP are filtered before download."""
        from pkg_defender.intel.feeds.osv import fetch_from_dump

        ecosystems = ["pypi", "homebrew", "npm"]

        with patch("pkg_defender.intel.feeds.osv.download_ecosystem_dump") as mock_dl:
            mock_dl.return_value = []  # Empty list — no vulns
            await fetch_from_dump(ecosystems=ecosystems)

        # Only "pypi" and "npm" should have been fetched — "homebrew" filtered
        fetched_ecosystems = [call.args[0] for call in mock_dl.call_args_list]
        assert "homebrew" not in fetched_ecosystems
        assert "pypi" in fetched_ecosystems or "npm" in fetched_ecosystems

    def test_unsupported_ecosystem_no_sync_loop(self) -> None:
        """Unsupported ecosystem produces no failure that would leave last_sync as NULL."""
        from pkg_defender.intel.feeds.osv import DUMP_ECOSYSTEM_MAP

        # "homebrew" is NOT in the map
        assert "homebrew" not in DUMP_ECOSYSTEM_MAP

        # Filtering would exclude it — no download attempt, no failure, no NULL last_sync
        supported = [eco for eco in ["pypi", "homebrew"] if eco in DUMP_ECOSYSTEM_MAP]
        assert supported == ["pypi"]


class TestCacheVersionTimestampsLogging:
    """Regression tests for _cache_version_timestamps_async exception handling.

    Verifies that resolver snapshot failures are logged instead of silently
    swallowed.
    """

    @pytest.mark.asyncio
    async def test_resolver_failure_is_logged(self, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
        """Exception during resolver snapshot produces a debug log entry."""
        from unittest.mock import patch

        from pkg_defender.registry.base import PipelineAdapterProtocol

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"

        # Adapter must pass isinstance(adapter, PipelineAdapterProtocol)
        mock_adapter = MagicMock(spec=PipelineAdapterProtocol)
        dispatcher.adapter = mock_adapter

        # Use a real temporary file so the db_path.exists() check passes.
        db_file = tmp_path / "test.db"
        db_file.touch()

        mock_conn = MagicMock()
        mock_config = MagicMock()
        mock_config.registry_api_timeout = 30
        mock_config.per_ecosystem_registry_timeout = {}

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_file),
            patch("pkg_defender.config.load_config", return_value=mock_config),
            patch("pkg_defender.cli.dispatcher.get_connection", return_value=mock_conn),
            patch(
                "pkg_defender.registry._timestamp.get_resolver",
                side_effect=RuntimeError("resolver unavailable"),
            ),
            caplog.at_level("DEBUG", logger="pkg_defender.cli.dispatcher"),
        ):
            await dispatcher._cache_version_timestamps_async(
                ParsedCommand(manager="pip", manager_subcommand="install", raw_args=[]),
            )

        assert "failed to snapshot session errors" in caplog.text


class TestEnsureDbFreshHomebrewAlert:
    """Tests for the Homebrew Vulnerability Alert in ``_ensure_db_fresh()``.

    Covers the post-sync alert code in dispatcher.py lines 1072-1101:
      - homebrew N>0 → query_threats_by_source called, alert output on stderr
      - homebrew N==0 → no alert, no DB query
      - homebrew records found → detailed per-package output
      - homebrew records empty → alert header NOT shown
      - homebrew with CVSS score → CVSS shown
      - homebrew without CVSS score → no CVSS text
      - homebrew single record → singular "Package" label
      - homebrew multiple records → plural "Packages" label
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_config(self, threshold_hours: int = 8) -> PKGDConfig:
        """Create a config with a specific staleness threshold."""
        config = PKGDConfig()
        config.feeds.staleness_threshold_hours = threshold_hours
        return config

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    @patch("pkg_defender.cli.dispatcher.shutil.which")
    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_homebrew_alert_shown_when_vulnerabilities_found(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
        mock_shutil_which: MagicMock,
    ) -> None:
        """Homebrew N>0 → alert output on stderr with package details."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(
            return_value={"homebrew": 3, "osv": 15, "ghsa": 0},
        )
        mock_feed_aggregator.return_value = mock_aggregator_instance

        mock_shutil_which.return_value = "/usr/local/bin/brew"

        query_results = [
            {
                "package_name": "curl",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "summary": "Buffer overflow in curl",
                "detail_url": "https://osv.dev/curl",
            },
            {
                "package_name": "openssl",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "summary": "RCE in openssl",
                "detail_url": "https://osv.dev/openssl",
            },
            {
                "package_name": "wget",
                "severity": "MEDIUM",
                "cvss_score": None,
                "summary": "Info leak in wget",
                "detail_url": "https://osv.dev/wget",
            },
        ]

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.dispatcher.query_threats_by_source",
                return_value=query_results,
            ) as mock_query,
            patch(
                "pkg_defender.cli.dispatcher.brew_get_installed_version",
                AsyncMock(side_effect=["8.0.1", "3.0.0", "1.2.0"]),
            ),
        ):
            mock_connect.return_value = MagicMock()

            result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True

        # Query should have been called
        mock_query.assert_called_once()
        call_kwargs = mock_query.call_args[1]
        assert call_kwargs["ecosystem"] == "homebrew"
        assert call_kwargs["source"] == "homebrew_osv"

        # Alert header should be on stderr
        echo_calls = [args[0][0] for args in mock_echo.call_args_list if len(args[0]) > 0]
        alert_headers = [c for c in echo_calls if "BREW" in str(c)]
        assert len(alert_headers) >= 1, "Expected BREW alert in output"

        # Should contain 3 Vulnerable Packages (plural since >1)
        plural_marker = [c for c in echo_calls if "Vulnerable Packages" in str(c)]
        assert len(plural_marker) >= 1, "Expected 'Vulnerable Packages' (plural)"

        # Each package should have detail lines
        all_echo = "\n".join(str(c) for c in echo_calls)
        assert "curl" in all_echo
        assert "openssl" in all_echo
        assert "wget" in all_echo

        # CVSS should appear for curl and openssl
        assert "CVSS 7.5" in all_echo
        assert "CVSS 9.8" in all_echo
        # wget has no CVSS — should not show CVSS
        cvss_wget_count = all_echo.count("CVSS")
        assert cvss_wget_count == 2  # Only curl and openssl have CVSS scores

        # Fix message should be present
        assert "brew upgrade curl" in all_echo
        assert "brew upgrade openssl" in all_echo
        assert "brew upgrade wget" in all_echo

    @patch("pkg_defender.cli.dispatcher.shutil.which")
    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_homebrew_alert_not_shown_when_no_vulnerabilities(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
        mock_shutil_which: MagicMock,
    ) -> None:
        """Homebrew N==0 → no alert output."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(
            return_value={"homebrew": 0, "osv": 15},
        )
        mock_feed_aggregator.return_value = mock_aggregator_instance

        mock_shutil_which.return_value = "/usr/local/bin/brew"

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.dispatcher.query_threats_by_source",
            ) as mock_query,
        ):
            mock_connect.return_value = MagicMock()

            result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True

        # query_threats_by_source should NOT have been called (homebrew_count == 0)
        mock_query.assert_not_called()

        # No BREW alert in echo output
        echo_calls = [str(args) for args in mock_echo.call_args_list]
        brew_calls = [c for c in echo_calls if "BREW" in c]
        assert len(brew_calls) == 0, "Expected no BREW alert in output"

    @patch("pkg_defender.cli.dispatcher.shutil.which")
    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_homebrew_alert_no_records_in_db_no_output(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
        mock_shutil_which: MagicMock,
    ) -> None:
        """Homebrew N>0 but no DB records → alert header not shown."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(
            return_value={"homebrew": 2, "osv": 15},
        )
        mock_feed_aggregator.return_value = mock_aggregator_instance

        mock_shutil_which.return_value = "/usr/local/bin/brew"

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.dispatcher.query_threats_by_source",
                return_value=[],
            ) as mock_query,
        ):
            mock_connect.return_value = MagicMock()

            result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True

        # Query was called (homebrew_count > 0), but no BREW output
        mock_query.assert_called_once()

        echo_calls = [str(args) for args in mock_echo.call_args_list]
        brew_calls = [c for c in echo_calls if "BREW" in c]
        assert len(brew_calls) == 0, "Expected no BREW line in output when no records"

    @patch("pkg_defender.cli.dispatcher.shutil.which")
    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_homebrew_alert_single_record_shows_singular(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
        mock_shutil_which: MagicMock,
    ) -> None:
        """Single vulnerable package → uses singular 'Package' label."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(
            return_value={"homebrew": 1, "osv": 0},
        )
        mock_feed_aggregator.return_value = mock_aggregator_instance

        mock_shutil_which.return_value = "/usr/local/bin/brew"

        query_results = [
            {
                "package_name": "curl",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "summary": "Buffer overflow",
                "detail_url": "https://osv.dev/curl",
            },
        ]

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.dispatcher.query_threats_by_source",
                return_value=query_results,
            ),
            patch(
                "pkg_defender.cli.dispatcher.brew_get_installed_version",
                AsyncMock(return_value="8.0.1"),
            ),
        ):
            mock_connect.return_value = MagicMock()

            result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True

        echo_calls = [str(args[0][0]) for args in mock_echo.call_args_list if len(args[0]) > 0]
        brew_lines = [c for c in echo_calls if "BREW" in c]
        assert len(brew_lines) >= 1
        assert "Vulnerable Package" in brew_lines[0]  # singular
        assert "Vulnerable Packages" not in brew_lines[0]  # not plural

    @patch("pkg_defender.cli.dispatcher.shutil.which")
    @patch("pkg_defender.intel.aggregator.FeedAggregator")
    @patch("pkg_defender.config.get_db_path")
    @patch("pkg_defender.db.schema.get_connection")
    @patch("pkg_defender.db.schema.get_feed_state")
    def test_homebrew_alert_other_feeds_dont_trigger(
        self,
        mock_get_feed_state: MagicMock,
        mock_get_connection: MagicMock,
        mock_get_db_path: MagicMock,
        mock_feed_aggregator: MagicMock,
        mock_shutil_which: MagicMock,
    ) -> None:
        """Non-homebrew feeds N>0 do NOT trigger Homebrew alert query."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_get_db_path.return_value = mock_db_path

        old_sync = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        mock_get_feed_state.return_value = {"last_sync": old_sync}

        mock_aggregator_instance = MagicMock()
        mock_aggregator_instance.sync_all = AsyncMock(
            return_value={"osv": 50, "ghsa": 20, "homebrew": 0, "rss": 5},
        )
        mock_feed_aggregator.return_value = mock_aggregator_instance

        mock_shutil_which.return_value = "/usr/local/bin/brew"

        dispatcher = self._make_dispatcher()
        config = self._make_config(threshold_hours=8)

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.dispatcher.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.dispatcher.query_threats_by_source",
            ) as mock_query,
        ):
            mock_connect.return_value = MagicMock()

            result = dispatcher._ensure_db_fresh(config, self._make_ctx())

        assert result is True

        # query_threats_by_source should NOT have been called
        mock_query.assert_not_called()

        # No BREW output
        echo_calls = [str(args) for args in mock_echo.call_args_list]
        brew_calls = [c for c in echo_calls if "BREW" in c]
        assert len(brew_calls) == 0
