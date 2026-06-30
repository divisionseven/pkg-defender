"""Tests for pkgd intel command group: sync, search, report.

Target: 85%+ branch coverage for src/pkg_defender/cli/commands/intel.py

Notes on Click 8.3 CliRunner behaviour:
- ``result.stdout`` / ``result.stderr`` — separate captured streams.
- ``result.output`` — mixed stdout + stderr in write order.
- Rich ``console.print`` writes to stderr but via its own FD (opened at
  import time in ``common.py``), bypassing CliRunner's capture buffer.
  Use ``mock.patch("pkg_defender.cli.commands.{mod}.console.print")``
  to intercept and assert on Rich console output.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_REGISTRY_UNREACHABLE
from pkg_defender.cli.main import cli
from pkg_defender.config.settings import PKGDConfig

# ============================================================================
# Intel Group (help tests)
# ============================================================================


class TestIntelGroup:
    """Tests for the intel group (--help, no subcommand)."""

    def test_intel_help(self, runner: CliRunner) -> None:
        """intel --help shows sync, search, report."""
        result = runner.invoke(cli, ["intel", "--help"])
        assert result.exit_code == 0
        assert "sync" in result.output.lower()
        assert "search" in result.output.lower()
        assert "report" in result.output.lower()

    def test_intel_sync_help(self, runner: CliRunner) -> None:
        """intel sync --help shows usage."""
        result = runner.invoke(cli, ["intel", "sync", "--help"])
        assert result.exit_code == 0
        assert "sync" in result.output.lower()

    def test_intel_search_help(self, runner: CliRunner) -> None:
        """intel search --help shows usage."""
        result = runner.invoke(cli, ["intel", "search", "--help"])
        assert result.exit_code == 0
        assert "search" in result.output.lower()

    def test_intel_report_help(self, runner: CliRunner) -> None:
        """intel report --help shows usage."""
        result = runner.invoke(cli, ["intel", "report", "--help"])
        assert result.exit_code == 0
        assert "report" in result.output.lower()

    def test_intel_no_subcommand_shows_help(self, runner: CliRunner) -> None:
        """intel with no subcommand shows group help."""
        result = runner.invoke(cli, ["intel"])
        assert result.exit_code in (0, 2)
        assert "usage" in result.output.lower() or "commands" in result.output.lower()


# ============================================================================
# TestIntelSync
# ============================================================================


class TestIntelSync:
    """Tests for `pkgd intel sync`."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_aggregator(
        feed_results: dict[str, int] | None = None,
        sync_summary: dict[str, dict[str, Any]] | None = None,
        feed_metadata: dict[str, Any] | None = None,
        failed_feeds: dict[str, str] | None = None,
    ) -> MagicMock:
        """Build a mock FeedAggregator with controlled return values."""
        if feed_results is None:
            feed_results = {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 3, "ossf_malicious": 0}
        if sync_summary is None:
            sync_summary = {
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
                "ghsa": {"status": "success"},
                "rss": {"status": "success"},
                "ossf_malicious": {"status": "success"},
            }
        if feed_metadata is None:
            feed_metadata = {}
        if failed_feeds is None:
            failed_feeds = {}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = feed_metadata
        aggregator.get_failed_feeds.return_value = failed_feeds
        return aggregator

    @staticmethod
    def _mock_db_path(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        """Mock ``get_db_path`` and ``shutil.disk_usage`` for sync tests.

        Returns the mock Path so callers can override ``.exists()`` / ``.stat()``.
        """
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = False
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: mock_db_path,
        )

        mock_usage = MagicMock()
        mock_usage.free = 500 * 1024 * 1024 * 1024
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        return mock_db_path

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_sync_default_output(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Default sync (no flags) shows total via console.print."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ) as _,
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # Verify the "Total" line was printed via console.print
        total_lines = [c for c in mock_print.call_args_list if "Total:" in str(c)]
        assert len(total_lines) == 1, "Expected exactly one 'Total:' console.print call"
        assert "25 threats synced" in str(total_lines[0])

    @patch("shutil.which", side_effect=lambda cmd: "/opt/homebrew/bin/brew" if cmd == "brew" else None)
    def test_sync_json_output(
        self,
        mock_which: MagicMock,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--json flag produces valid JSON on stdout."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data, indent=2) if pretty else json.dumps(data),
        )

        aggregator = self._make_aggregator()

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync", "--json"])

        assert result.exit_code == 0
        # stdout has a blank line from click.echo() then JSON
        stdout = result.stdout.strip()
        data = json.loads(stdout)
        assert data["total_threats_synced"] == 25
        assert len(data["feeds"]) == 5

    def test_sync_output_format_option(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """-o json flag produces valid JSON."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )

        aggregator = self._make_aggregator()
        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync", "-o", "json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        assert data["total_threats_synced"] == 25

    def test_sync_pretty_json(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--pretty --json passes pretty=True to format_json."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        captured: dict[str, Any] = {}

        def _capture_json(data: Any, pretty: bool = False) -> str:
            captured["pretty"] = pretty
            return json.dumps(data, indent=2) if pretty else json.dumps(data)

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            _capture_json,
        )

        aggregator = self._make_aggregator()
        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync", "--json", "--pretty"])

        assert result.exit_code == 0
        assert captured.get("pretty") is True

    def test_sync_quiet_mode(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Quiet mode suppresses console.print output."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: True,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        # In quiet mode, console.print should NOT be called for summary
        total_calls = [c for c in mock_print.call_args_list if "Total:" in str(c)]
        assert len(total_calls) == 0, "Expected no 'Total:' output in quiet mode"

    def test_sync_osv_with_count(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OSV with count >0 shows generic feed summary instead of ecosystem breakdown."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
            feed_metadata={
                "osv": {},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "osv" in all_output
        assert "15 vulnerabilities loaded" in all_output

    def test_sync_osv_no_new_threats(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OSV with count=0 and success status shows 'synced (no new threats)'."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 0, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
            feed_metadata={
                "osv": {},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "database unchanged \u2014 already up to date" in all_output

    def test_sync_osv_with_source_url(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SHOW_SOURCE_URLS=True shows source URL via generic feed handler."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.SHOW_SOURCE_URLS",
            True,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
            feed_metadata={
                "osv": {
                    "source_url": "https://osv.dev",
                },
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "osv" in all_output
        assert "osv.dev" in all_output  # URL should appear via generic handler with SHOW_SOURCE_URLS=True

    def test_sync_osv_no_source_url(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SHOW_SOURCE_URLS=False hides source URLs in generic feed handler."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.SHOW_SOURCE_URLS",
            False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
            feed_metadata={
                "osv": {},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "osv" in all_output
        assert "15 vulnerabilities loaded" in all_output

    def test_sync_feed_with_count_shows_source_url(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feed with count >0 and SHOW_SOURCE_URLS=True shows source_url."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.SHOW_SOURCE_URLS",
            True,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
            feed_metadata={
                "osv": {"source_url": "https://osv.dev"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "osv.dev" in all_output

    def test_sync_feed_error_long_message(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feed error >60 chars shows truncated (first 57 + '...')."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        long_error = "x" * 100
        aggregator = self._make_aggregator(
            feed_results={"osv": 0, "homebrew": 0},
            sync_summary={
                "osv": {"status": "error", "error_message": long_error},
                "homebrew": {"status": "success"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert long_error[:57] in all_output
        assert "..." in all_output

    def test_sync_feed_error_short_message(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feed error <=60 chars shows full message (no truncation)."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        short_error = "Connection refused"
        aggregator = self._make_aggregator(
            feed_results={"osv": 0, "homebrew": 0},
            sync_summary={
                "osv": {"status": "error", "error_message": short_error},
                "homebrew": {"status": "success"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert short_error in all_output
        assert "..." not in all_output

    def test_sync_feed_not_configured(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feed with status 'not_configured' shows dim message."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        # Use a feed name that exists in the default 4-feed list
        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0, "ghsa": 0, "rss": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
                "ghsa": {"status": "not_configured"},
                "rss": {"status": "success"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list).lower()
        assert "ghsa" in all_output
        assert "not configured" in all_output

    def test_sync_no_new_threats(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feed with 0 count and success status shows 'no new threats'."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 0, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list).lower()
        assert "already up to date" in all_output

    def test_sync_rss_warning_shown_in_summary(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """RSS feed with 0 entries and warning shows the warning in sync summary."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "rss": 0},
            sync_summary={
                "osv": {"status": "success"},
                "rss": {"status": "success"},
            },
            feed_metadata={
                "osv": {},
                "rss": {
                    "warning": (
                        "RSS feed https://example.com/feed.xml returned 0 entries "
                        "after filtering. Tip: Adjust RSS filters with: "
                        'pkgd config set feeds.rss_keywords "your, keywords"'
                    ),
                },
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        # Should show the descriptive "no data" message
        assert "no entries matched keywords" in all_output
        # Should also show the RSS warning
        assert "returned 0 entries after filtering" in all_output

        # Verify warnings appear after all feed result lines (deferred display)
        call_strings = [str(call) for call in mock_print.call_args_list]
        warning_indices = [i for i, s in enumerate(call_strings) if "returned 0 entries after filtering" in s]
        result_indices = [i for i, s in enumerate(call_strings) if "no entries matched keywords" in s]
        assert warning_indices, "Warning should be present in output"
        assert result_indices, "Feed result should be present in output"
        assert max(warning_indices) > max(result_indices), "Warning should appear after the last feed result line"

    def test_sync_failed_feeds_stderr(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Failed feeds output styled error on stderr (click.echo with err=True)."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            failed_feeds={"ghsa": "API rate limited"},
        )

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        assert "Feed failures" in result.stderr
        assert "ghsa" in result.stderr
        assert "API rate limited" in result.stderr

    def test_sync_has_issues_tips(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Feeds in error / not_configured state display Helpful Tips."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator(
            feed_results={"osv": 0, "homebrew": 0, "ghsa": 0, "rss": 0},
            sync_summary={
                "osv": {"status": "error", "error_message": "timeout"},
                "homebrew": {"status": "success"},
                "ghsa": {"status": "not_configured"},
                "rss": {"status": "success"},
            },
            failed_feeds={"osv": "timeout"},
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        # Feed failure on stderr (click.echo with err=True)
        assert "Feed failures" in result.stderr

        # Helpful Tips via console.print
        tips_text = str(mock_print.call_args_list)
        assert "Helpful Tips" in tips_text
        assert "pkgd status --feeds" in tips_text
        assert "pkgd health" in tips_text

    def test_sync_db_size_gb(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """DB size >= 1024 MB displays GB formatting."""
        mock_db_path = self._mock_db_path(monkeypatch)
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value = MagicMock(st_size=2 * 1024 * 1024 * 1024)

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "2.0 GB" in all_output

    def test_sync_db_size_mb(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """DB size < 1024 MB displays MB formatting."""
        mock_db_path = self._mock_db_path(monkeypatch)
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value = MagicMock(st_size=500 * 1024 * 1024)

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "500.0 MB" in all_output

    def test_sync_free_space_warning(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Free space < 5 GB shows warning icon."""
        mock_db_path = self._mock_db_path(monkeypatch)
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value = MagicMock(st_size=100 * 1024 * 1024)

        mock_usage = MagicMock()
        mock_usage.free = 2 * 1024 * 1024 * 1024  # 2 GB
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        # Warning icon (unicode ⚠) or "Free space" text in the same call
        assert "Free space" in all_output

    def test_sync_free_space_large(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Free space >= 100 GB shows whole-number GB."""
        mock_db_path = self._mock_db_path(monkeypatch)
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value = MagicMock(st_size=100 * 1024 * 1024)

        mock_usage = MagicMock()
        mock_usage.free = 200 * 1024 * 1024 * 1024  # 200 GB
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "Free space on disk: 200 GB" in all_output

    def test_sync_exception(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FeedAggregator constructor raises → unhandled RuntimeError (exit 1).

        Note: the ``FeedAggregator(...)`` call at line 153 is *before* the
        try/except block that handles ``aggregator.sync_all()`` failures,
        so this exception propagates up to Click as an unhandled error.
        """
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            side_effect=RuntimeError("Network error"),
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 1
        assert isinstance(result.exception, RuntimeError)

    def test_sync_no_db_path_no_size_display(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When db_path does not exist, no DB size line is printed."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "Database size" not in all_output

    def test_sync_sync_all_exception(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``aggregator.sync_all()`` raises → caught by try/except → SystemExit(5)."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        aggregator.sync_all = AsyncMock(side_effect=RuntimeError("API timeout"))

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == EXIT_REGISTRY_UNREACHABLE
        assert "Error: Feed sync failed" in result.output

    def test_sync_timeout_exception(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """sync_all raises TimeoutError → caught by ``except TimeoutError`` → SystemExit(5)."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()
        aggregator.sync_all = AsyncMock(side_effect=TimeoutError("sync timed out"))

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == EXIT_REGISTRY_UNREACHABLE
        assert "timed out" in result.output

    def test_sync_with_disabled_feeds(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Disabling GHSA and RSS exercises the False branches (136->138, 146->148)."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        config = PKGDConfig()
        config.feeds.ghsa_enabled = False
        config.feeds.rss_enabled = False
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: config,
        )

        # Only osv + homebrew in the results (ghsa and rss are disabled)
        aggregator = self._make_aggregator(
            feed_results={"osv": 15, "homebrew": 0},
            sync_summary={
                "osv": {"status": "success"},
                "homebrew": {"status": "success"},
            },
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "osv" in all_output
        assert "ghsa" not in all_output  # Not in feed list when disabled
        assert "rss" not in all_output  # Not in feed list when disabled

    @patch("shutil.which", side_effect=lambda cmd: "/opt/homebrew/bin/brew" if cmd == "brew" else None)
    def test_sync_with_all_feeds_enabled(
        self,
        mock_which: MagicMock,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Enabling all optional feeds exercises the disabled-by-default feed branches."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        # Create a config with ALL feeds enabled so lines 139, 141, 143, 145, 149
        # are exercised (SocketFeed, NpmAdvisoryFeed, MastodonFeed, RedditFeed,
        # XTwitterFeed constructors are all safe — no __init__ side effects).
        config = PKGDConfig()
        config.feeds.socket_enabled = True
        config.feeds.npm_advisory_enabled = True
        config.feeds.mastodon_enabled = True
        config.feeds.reddit_enabled = True
        config.feeds.x_twitter_enabled = True
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: config,
        )

        # Results dict must cover all 9 feeds now
        feed_results = {
            "osv": 15,
            "homebrew": 0,
            "ghsa": 7,
            "rss": 3,
            "socket": 5,
            "npm_advisory": 2,
            "mastodon": 1,
            "reddit": 0,
            "x_twitter": 3,
        }
        sync_summary = {name: {"status": "success"} for name in feed_results}

        aggregator = self._make_aggregator(
            feed_results=feed_results,
            sync_summary=sync_summary,
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        # All 9 feeds should appear (use display names where they differ from keys)
        display_names = {
            "osv": "osv",
            "homebrew": "homebrew",
            "ghsa": "ghsa",
            "rss": "rss",
            "socket": "socket",
            "npm_advisory": "npm",
            "mastodon": "mastodon",
            "reddit": "reddit",
            "x_twitter": "twitter",
        }
        for name, display in display_names.items():
            assert display in all_output, f"Feed {name} (display: {display}) not found in output"

    def test_sync_progress_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``should_show_progress()`` returns True, progress is displayed."""
        from rich.progress import Progress

        self._mock_db_path(monkeypatch)

        # Enable progress display
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: True,
        )

        # Replace feed_sync_progress with a context manager that yields a real Progress
        # so lines 158-168 are exercised (task creation, feed completion callback).
        @contextmanager
        def _mock_feed_sync_progress(total: int) -> Iterator[Progress]:
            progress = Progress()
            progress.add_task("test", total=total)
            with progress:
                yield progress

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.feed_sync_progress",
            _mock_feed_sync_progress,
        )

        aggregator = self._make_aggregator()

        # Make sync_all actually invoke the progress callback so lines 162-168 execute
        async def _sync_all_with_callback(**kwargs: Any) -> dict[str, int]:
            cb = kwargs.get("progress_callback")
            if cb:
                cb("osv", 15)
                cb("homebrew", 0)
                cb("ghsa", 7)
                cb("rss", 3)
            return {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 3}

        aggregator.sync_all = AsyncMock(side_effect=_sync_all_with_callback)
        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            return_value=aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

    def test_sync_callback_without_progress(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Callback fires but progress is None — covers 162->exit False branch.

        When ``should_show_progress`` returns False, ``progress`` is ``None``
        inside ``_on_feed_complete``, so the ``if progress is not None`` at line
        162 takes the False branch (skip body). Previously only the True branch was
        hit.
        """
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        aggregator = self._make_aggregator()

        # Make sync_all invoke the callback even though progress is None
        async def _sync_all_no_progress(**kwargs: Any) -> dict[str, int]:
            cb = kwargs.get("progress_callback")
            if cb:
                cb("osv", 15)
            return {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 3}

        aggregator.sync_all = AsyncMock(side_effect=_sync_all_no_progress)

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print"),
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

    # ------------------------------------------------------------------
    # Sync progress callback tests - Homebrew bold yellow path
    # ------------------------------------------------------------------

    def test_sync_progress_homebrew_vulnerable(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew with N>0 in progress callback uses bold yellow format.

        Exercises the ``feed_name == "homebrew" and record_count > 0`` branch
        of ``_on_feed_complete`` (intel.py line 196), which calls
        ``progress.console.print`` with a bold yellow warning icon.
        """
        from rich.progress import Progress

        self._mock_db_path(monkeypatch)

        # Enable progress display
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: True,
        )

        # Replace feed_sync_progress with a context manager that yields a real Progress
        @contextmanager
        def _mock_feed_sync_progress(total: int) -> Iterator[Progress]:
            progress = Progress()
            progress.add_task("test", total=total)
            with progress:
                yield progress

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.feed_sync_progress",
            _mock_feed_sync_progress,
        )

        # Spy on format_feed_message to verify homebrew N>0 is formatted
        captured_calls: list[tuple[str, int]] = []

        def _spy_format(feed_name: str, record_count: int) -> str:
            captured_calls.append((feed_name, record_count))
            return f"spy-{feed_name}-{record_count}"

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_feed_message",
            _spy_format,
        )

        aggregator = self._make_aggregator()

        # Make sync_all invoke the callback with homebrew N>0
        async def _sync_all_with_callback(**kwargs: Any) -> dict[str, int]:
            cb = kwargs.get("progress_callback")
            if cb:
                cb("homebrew", 3)  # Homebrew with N>0 → bold yellow branch
                cb("osv", 15)  # Normal feed with N>0 → green branch
                cb("ghsa", 0)  # Feed with N==0 → green branch
            return {"homebrew": 3, "osv": 15, "ghsa": 0}

        aggregator.sync_all = AsyncMock(side_effect=_sync_all_with_callback)

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch("shutil.which", side_effect=lambda cmd: "/opt/homebrew/bin/brew" if cmd == "brew" else None),
        ):
            mock_connect.return_value = MagicMock()
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # Verify that format_feed_message was called with homebrew and count=3
        homebrew_calls = [(f, c) for f, c in captured_calls if f == "homebrew"]
        assert len(homebrew_calls) >= 1, (
            f"Expected format_feed_message to be called with 'homebrew', got calls: {captured_calls}"
        )
        assert homebrew_calls[0][1] == 3

        # Verify osv was also formatted
        osv_calls = [(f, c) for f, c in captured_calls if f == "osv"]
        assert len(osv_calls) >= 1

        # Verify ghsa (count=0) was also formatted
        ghsa_calls = [(f, c) for f, c in captured_calls if f == "ghsa"]
        assert len(ghsa_calls) >= 1
        assert ghsa_calls[0][1] == 0

    # ------------------------------------------------------------------
    # Homebrew detection regression tests
    # ------------------------------------------------------------------

    @patch("shutil.which")
    def test_intel_sync_excludes_homebrew_when_brew_not_installed(
        self,
        mock_which: MagicMock,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew feed is excluded when brew is not on PATH."""
        mock_which.return_value = None

        # Mock infrastructure
        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = False
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: mock_db_path,
        )
        mock_usage = MagicMock()
        mock_usage.free = 500 * 1024 * 1024 * 1024
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        # Capture the feeds list before it reaches the aggregator
        captured_feeds: list[Any] = []

        def _capture_aggregator(feeds: list[Any], *args: Any, **kwargs: Any) -> MagicMock:
            captured_feeds.extend(feeds)
            agg = MagicMock()
            agg.sync_all = AsyncMock(return_value={})
            agg.get_sync_summary.return_value = {}
            agg.get_feed_metadata.return_value = {}
            agg.get_failed_feeds.return_value = {}
            return agg

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            side_effect=_capture_aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # feed names do NOT include "homebrew"
        feed_names = [f.name for f in captured_feeds]
        assert "homebrew" not in feed_names, (
            f"Expected 'homebrew' to be excluded from feed list, but got feeds: {feed_names}"
        )

    @patch("shutil.which")
    def test_intel_sync_includes_homebrew_when_brew_installed(
        self,
        mock_which: MagicMock,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew feed is included when brew is on PATH."""
        mock_which.return_value = "/usr/local/bin/brew"

        # Mock infrastructure
        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = False
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: mock_db_path,
        )
        mock_usage = MagicMock()
        mock_usage.free = 500 * 1024 * 1024 * 1024
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        # Capture the feeds list before it reaches the aggregator
        captured_feeds: list[Any] = []

        def _capture_aggregator(feeds: list[Any], *args: Any, **kwargs: Any) -> MagicMock:
            captured_feeds.extend(feeds)
            agg = MagicMock()
            agg.sync_all = AsyncMock(return_value={})
            agg.get_sync_summary.return_value = {}
            agg.get_feed_metadata.return_value = {}
            agg.get_failed_feeds.return_value = {}
            return agg

        with patch(
            "pkg_defender.intel.aggregator.FeedAggregator",
            side_effect=_capture_aggregator,
        ):
            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # feed names DO include "homebrew"
        feed_names = [f.name for f in captured_feeds]
        assert "homebrew" in feed_names, (
            f"Expected 'homebrew' to be included in feed list when brew is installed, but got feeds: {feed_names}"
        )

    def test_sync_exclude_feed_removes_feed(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--exclude-feed ossf_malicious removes OSSF from the sync."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        # Enable OSSF in config so it would be added by default
        config = PKGDConfig()
        config.feeds.ossf_malicious_enabled = True
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: config,
        )

        # Results without ossf_malicious (because it was excluded)
        feed_results = {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 3}
        sync_summary = {name: {"status": "success"} for name in feed_results}

        aggregator = self._make_aggregator(
            feed_results=feed_results,
            sync_summary=sync_summary,
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["intel", "sync", "--exclude-feed", "ossf_malicious"])

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)

        # OSSF should NOT appear in output
        assert "ossf_malicious" not in all_output

        # Other feeds should still appear
        assert "osv" in all_output
        assert "ghsa" in all_output

    def test_sync_exclude_feed_multiple(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Multiple --exclude-feed values exclude multiple feeds."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )

        config = PKGDConfig()
        config.feeds.ossf_malicious_enabled = True
        config.feeds.ghsa_enabled = True
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: config,
        )

        # Results without ossf_malicious and ghsa
        feed_results = {"osv": 15, "homebrew": 0, "rss": 3}
        sync_summary = {name: {"status": "success"} for name in feed_results}

        aggregator = self._make_aggregator(
            feed_results=feed_results,
            sync_summary=sync_summary,
        )

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            result = runner.invoke(
                cli,
                ["intel", "sync", "--exclude-feed", "ossf_malicious", "--exclude-feed", "ghsa"],
            )

        assert result.exit_code == 0
        all_output = str(mock_print.call_args_list)
        assert "ossf_malicious" not in all_output
        assert "ghsa" not in all_output
        assert "osv" in all_output


# ============================================================================
# TestIntelSearch
# ============================================================================


class TestIntelSearch:
    """Tests for `pkgd intel search`."""

    @pytest.fixture
    def mock_config(self) -> PKGDConfig:
        """Default config (search_exclude_severity=["UNKNOWN"])."""
        return PKGDConfig()

    @staticmethod
    def _make_mock_cursor(
        fetchall_result: list[tuple[Any, ...]] | None = None,
    ) -> MagicMock:
        cursor = MagicMock()
        if fetchall_result is not None:
            cursor.fetchall.return_value = fetchall_result
        return cursor

    def _setup_search_mocks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
        rows: list[tuple[Any, ...]] | None = None,
    ) -> MagicMock:
        """Mock DB infrastructure for search and return the mock connection."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value = self._make_mock_cursor(fetchall_result=rows or [])

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: MagicMock(spec=Path),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.init_db",
            lambda _path: mock_conn,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: mock_config,
        )
        return mock_conn

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_search_with_results(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Basic search with results shows threat table."""
        rows = [
            ("1", "npm", "axios", "HIGH", "Vulnerability in axios", "osv", "2026-01-15"),
            ("2", "pip", "requests", "CRITICAL", "Security issue", "ghsa", "2026-01-10"),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios"])

        assert result.exit_code == 0
        assert "axios" in result.output
        assert "requests" in result.output

    def test_search_json_output(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--json flag produces valid JSON array on stdout."""
        rows = [
            ("1", "npm", "axios", "HIGH", "Vulnerability", "osv", "2026-01-15"),
        ]
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        assert isinstance(data, list)
        assert data[0]["package_name"] == "axios"
        assert data[0]["severity"] == "HIGH"

    def test_search_no_results(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """No results shows 'No threats found'."""
        self._setup_search_mocks(monkeypatch, mock_config, rows=[])

        result = runner.invoke(cli, ["intel", "search", "nonexistent"])

        assert result.exit_code == 0
        assert "No threats found" in result.output

    def test_search_invalid_exclude_severity(
        self,
        runner: CliRunner,
    ) -> None:
        """Invalid --exclude-severity → BadParameter (exit 2)."""
        result = runner.invoke(cli, ["intel", "search", "axios", "--exclude-severity", "INVALID"])
        assert result.exit_code == 2
        assert "Invalid severity" in result.output

    def test_search_exclude_severity_valid(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Valid --exclude-severity filters results."""
        rows = [
            ("1", "npm", "axios", "HIGH", "Vuln", "osv", "2026-01-15"),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios", "--exclude-severity", "LOW,UNKNOWN"])
        assert result.exit_code == 0
        assert "axios" in result.output

    def test_search_exclude_severity_empty(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Empty --exclude-severity '' falls back to config default (UNKNOWN)."""
        rows = [
            ("1", "npm", "axios", "UNKNOWN", "Vuln", "osv", "2026-01-15"),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios", "--exclude-severity", ""])
        assert result.exit_code == 0

    def test_search_with_manager_filter(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--manager uses ecosystem_filter SQL branch."""
        rows = [
            ("1", "npm", "axios", "HIGH", "Vuln", "osv", "2026-01-15"),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios", "--manager", "npm"])
        assert result.exit_code == 0
        assert "axios" in result.output

    def test_search_with_manager_no_results(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--manager filter with no results."""
        self._setup_search_mocks(monkeypatch, mock_config, rows=[])

        result = runner.invoke(cli, ["intel", "search", "axios", "--manager", "pip"])
        assert result.exit_code == 0
        assert "No threats found" in result.output

    def test_search_missing_query(
        self,
        runner: CliRunner,
    ) -> None:
        """Search without query → exit 2 (Missing argument)."""
        result = runner.invoke(cli, ["intel", "search"])
        assert result.exit_code == 2
        assert "Missing argument" in result.output

    def test_search_pretty_json(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--pretty --json passes pretty=True."""
        captured: dict[str, Any] = {}

        def _capture_json(data: Any, pretty: bool = False) -> str:
            captured["pretty"] = pretty
            return json.dumps(data, indent=2) if pretty else json.dumps(data)

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            _capture_json,
        )
        self._setup_search_mocks(
            monkeypatch,
            mock_config,
            rows=[("1", "npm", "axios", "HIGH", "Vuln", "osv", "2026-01-15")],
        )

        result = runner.invoke(cli, ["intel", "search", "axios", "--json", "--pretty"])
        assert result.exit_code == 0
        assert captured.get("pretty") is True

    def test_search_package_name_none(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Row with None package_name displays em-dash in table."""
        rows = [
            ("1", "npm", None, "HIGH", "Vuln", "osv", "2026-01-15"),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "test"])
        assert result.exit_code == 0
        assert "\u2014" in result.output  # em-dash

    def test_search_first_seen_none(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Row with None first_seen displays em-dash in table."""
        rows = [
            ("1", "npm", "axios", "HIGH", "Vuln", "osv", None),
        ]
        self._setup_search_mocks(monkeypatch, mock_config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "test"])
        assert result.exit_code == 0
        assert "\u2014" in result.output  # em-dash

    def test_search_json_with_no_severity_filter(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Search with --exclude-severity that excludes nothing produces valid JSON."""
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )

        config = PKGDConfig()
        config.output.search_exclude_severity = []
        rows = [
            ("1", "npm", "axios", "HIGH", "Vuln", "osv", "2026-01-15"),
        ]
        self._setup_search_mocks(monkeypatch, config, rows=rows)

        result = runner.invoke(cli, ["intel", "search", "axios", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        assert data[0]["package_name"] == "axios"


# ============================================================================
# TestIntelReport
# ============================================================================


class TestIntelReport:
    """Tests for `pkgd intel report`."""

    @pytest.fixture
    def mock_config(self) -> PKGDConfig:
        """Default config (intel_exclude_severity=["UNKNOWN"])."""
        return PKGDConfig()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_mock_cursor(
        fetchall_result: list[tuple[Any, ...]] | None = None,
        fetchone_result: tuple[Any, ...] | None = None,
    ) -> MagicMock:
        cursor = MagicMock()
        if fetchall_result is not None:
            cursor.fetchall.return_value = fetchall_result
        if fetchone_result is not None:
            cursor.fetchone.return_value = fetchone_result
        return cursor

    def _setup_report_mocks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
        *,
        total_count: int = 100,
        severity_rows: list[tuple[Any, ...]] | None = None,
        source_rows: list[tuple[Any, ...]] | None = None,
        ecosystem_rows: list[tuple[Any, ...]] | None = None,
        top_pkg_rows: list[tuple[Any, ...]] | None = None,
        threat_rows: list[tuple[Any, ...]] | None = None,
        ecosystem_query_expected: bool = True,
        stale_check_expected: bool = True,
    ) -> MagicMock:
        """Set up DB mocks for the report's 5-6 execute calls.

        Execute calls (in order):
          1. stale check: get_feed_state (from _check_and_warn_staleness)
          2. COUNT(*)
          3. severity GROUP BY
          4. source GROUP BY
          5. ecosystem GROUP BY (severity columns) — **skipped** when
             ``ecosystem_query_expected=False`` (all severities excluded).
          6. top_packages GROUP BY
          7. recent threats (last 7 days)

        Args:
            ecosystem_query_expected: When False, the 4th execute call
                is omitted from the side_effect list.
            stale_check_expected: When False, the stale-check cursor
                (position 0 in the side_effect list) is omitted.
                Use False for JSON-output tests where
                ``_check_and_warn_staleness`` is skipped.
        """
        if severity_rows is None:
            severity_rows = [
                ("CRITICAL", 50),
                ("HIGH", 30),
                ("MEDIUM", 15),
                ("LOW", 5),
            ]
        if source_rows is None:
            source_rows = [
                ("osv", 60),
                ("ghsa", 40),
            ]
        if ecosystem_rows is None:
            ecosystem_rows = [
                ("npm", 10, 5, 3, 2, 20),
            ]
        if top_pkg_rows is None:
            top_pkg_rows = [
                ("axios", "npm", 5, "CRITICAL"),
            ]
        if threat_rows is None:
            threat_rows = [
                ("axios", "CRITICAL", "osv", "2026-01-01T00:00:00", '["1.0.0"]', "[]"),
            ]

        cursors = []
        if stale_check_expected:
            cursors.append(self._make_mock_cursor())  # stale check: get_feed_state
        cursors.extend(
            [
                self._make_mock_cursor(fetchone_result=(total_count,)),
                self._make_mock_cursor(fetchall_result=severity_rows),
                self._make_mock_cursor(fetchall_result=source_rows),
            ]
        )
        if ecosystem_query_expected:
            cursors.append(self._make_mock_cursor(fetchall_result=ecosystem_rows))

        cursors.append(self._make_mock_cursor(fetchall_result=top_pkg_rows))
        cursors.append(self._make_mock_cursor(fetchall_result=threat_rows))

        mock_conn = MagicMock()
        mock_conn.execute.side_effect = cursors

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: MagicMock(spec=Path),
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.init_db",
            lambda _path: mock_conn,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel._get_config_from_context",
            lambda _ctx: mock_config,
        )

        return mock_conn

    @staticmethod
    def _recent_iso(hours_ago: float = 2) -> str:
        """ISO timestamp *hours_ago* before now (for threat age calculation)."""
        dt = datetime.now(UTC) - timedelta(hours=hours_ago)
        return dt.isoformat()

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_report_default(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Default report shows all sections."""
        self._setup_report_mocks(monkeypatch, mock_config)

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "THREAT INTELLIGENCE REPORT" in result.output
        assert "Recent Threats" in result.output
        assert "Threat Overview" in result.output
        assert "Threat Landscape" in result.output

    def test_report_json(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--json produces valid JSON with report sections."""
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )
        self._setup_report_mocks(monkeypatch, mock_config, stale_check_expected=False)

        result = runner.invoke(cli, ["intel", "report", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        assert "recent_threats" in data
        assert "threat_overview" in data
        assert "threat_landscape" in data
        assert data["threat_overview"]["severity"]["critical"] == 50
        assert data["threat_overview"]["severity"]["high"] == 30
        assert data["threat_overview"]["severity"]["medium"] == 15
        assert data["threat_overview"]["severity"]["low"] == 5
        # Ecosystem severity keys are also lowercased
        assert data["threat_landscape"]["ecosystem"]["npm"]["critical"] == 10
        assert data["threat_landscape"]["ecosystem"]["npm"]["high"] == 5
        assert data["threat_landscape"]["ecosystem"]["npm"]["medium"] == 3
        assert data["threat_landscape"]["ecosystem"]["npm"]["low"] == 2
        assert data["threat_landscape"]["ecosystem"]["npm"]["total"] == 20

    def test_report_json_severity_keys_lowercased_with_unknown(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: all five severity keys (incl. UNKNOWN) are lowercased in JSON.

        Root cause: src/pkg_defender/cli/commands/intel.py:710 —
        severity overview keys were not lowercased before the fix.
        This test FAILS before the fix and PASSES after.
        """
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )
        # Override config to include UNKNOWN in results
        config = PKGDConfig()
        config.output.intel_exclude_severity = []

        self._setup_report_mocks(
            monkeypatch,
            config,
            severity_rows=[
                ("CRITICAL", 50),
                ("HIGH", 30),
                ("MEDIUM", 15),
                ("LOW", 5),
                ("UNKNOWN", 2),
            ],
            ecosystem_rows=[
                ("npm", 10, 5, 3, 2, 1, 21),
            ],
            stale_check_expected=False,
        )

        result = runner.invoke(cli, ["intel", "report", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())

        # All five severity keys must be lowercased
        assert data["threat_overview"]["severity"]["critical"] == 50
        assert data["threat_overview"]["severity"]["high"] == 30
        assert data["threat_overview"]["severity"]["medium"] == 15
        assert data["threat_overview"]["severity"]["low"] == 5
        assert data["threat_overview"]["severity"]["unknown"] == 2
        # Ensure uppercase keys do NOT exist
        assert "CRITICAL" not in data["threat_overview"]["severity"]
        assert "UNKNOWN" not in data["threat_overview"]["severity"]

        # Ecosystem severity keys must also be lowercased
        assert data["threat_landscape"]["ecosystem"]["npm"]["critical"] == 10
        assert data["threat_landscape"]["ecosystem"]["npm"]["unknown"] == 1
        assert "CRITICAL" not in data["threat_landscape"]["ecosystem"]["npm"]

    def test_report_json_with_affected_versions(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """JSON report parses affected_versions/affected_ranges from JSON strings."""
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                (
                    "axios",
                    "CRITICAL",
                    "osv",
                    "2026-01-01T00:00:00",
                    '["1.0.0", "1.1.0"]',
                    '[{"type": "SEMVER", "range": "<2.0.0"}]',
                ),
            ],
            stale_check_expected=False,
        )

        result = runner.invoke(cli, ["intel", "report", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        threat = data["recent_threats"][0]
        assert threat["affected_versions"] == ["1.0.0", "1.1.0"]
        assert threat["affected_ranges"] == [{"type": "SEMVER", "range": "<2.0.0"}]

    def test_report_json_affected_versions_none(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """None affected_versions/ranges → empty lists in JSON."""
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            lambda data, pretty=False: json.dumps(data),
        )
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", "2026-01-01T00:00:00", None, None),
            ],
            stale_check_expected=False,
        )

        result = runner.invoke(cli, ["intel", "report", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout.strip())
        threat = data["recent_threats"][0]
        assert threat["affected_versions"] == []
        assert threat["affected_ranges"] == []

    def test_report_exclude_severity(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--exclude-severity excludes severities from output."""
        self._setup_report_mocks(monkeypatch, mock_config)

        result = runner.invoke(cli, ["intel", "report", "--exclude-severity", "LOW,UNKNOWN"])
        assert result.exit_code == 0

    def test_report_exclude_severity_invalid(
        self,
        runner: CliRunner,
    ) -> None:
        """Invalid --exclude-severity → BadParameter (exit 2)."""
        result = runner.invoke(cli, ["intel", "report", "--exclude-severity", "INVALID"])
        assert result.exit_code == 2
        assert "Invalid severity" in result.output

    def test_report_exclude_severity_empty(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Empty --exclude-severity '' falls back to config default."""
        self._setup_report_mocks(monkeypatch, mock_config)

        result = runner.invoke(cli, ["intel", "report", "--exclude-severity", ""])
        assert result.exit_code == 0

    def test_report_excluded_severity_display(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Excluded severities appear in a dim info line."""
        config = PKGDConfig()
        config.output.intel_exclude_severity = ["LOW"]
        self._setup_report_mocks(monkeypatch, config)

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "Excluding Severity" in result.output
        assert "LOW" in result.output

    def test_report_no_recent_threats(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """No threats in last 7 days shows dim message."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "No threats in the last 7 days" in result.output

    def test_report_no_threat_records(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """No severity/source rows shows 'No threat records found'."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            severity_rows=[],
            source_rows=[],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "No threat records found" in result.output

    def test_report_only_severity_table(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Only severity data (no source data) prints severity table standalone."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            severity_rows=[("CRITICAL", 50)],
            source_rows=[],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "CRITICAL" in result.output

    def test_report_threat_age_days(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat age > 24h displays 'Xd ago'."""
        five_days_iso = self._recent_iso(hours_ago=5 * 24)
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", five_days_iso, "[]", "[]"),
            ],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "5d ago" in result.output

    def test_report_threat_age_hours(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat age < 24h > 1h displays 'Xh ago'."""
        three_hours_iso = self._recent_iso(hours_ago=3)
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", three_hours_iso, "[]", "[]"),
            ],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "3h ago" in result.output

    def test_report_threat_age_less_than_one_hour(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat age < 1h displays '<1h ago'."""
        half_hour_iso = self._recent_iso(hours_ago=0.5)
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", half_hour_iso, "[]", "[]"),
            ],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "<1h ago" in result.output

    def test_report_threat_age_parse_error(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Unparseable first_seen displays '?' for age."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", "not-a-date", "[]", "[]"),
            ],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "?" in result.output

    def test_report_threat_age_naive_datetime(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Naive datetime (no tzinfo) treated as UTC."""
        naive_iso = (datetime.now(UTC) - timedelta(hours=2)).replace(tzinfo=None).isoformat()
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            threat_rows=[
                ("axios", "CRITICAL", "osv", naive_iso, "[]", "[]"),
            ],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "h ago" in result.output or "d ago" in result.output

    def test_report_ecosystem_filter(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--manager adds ecosystem filter and title suffix."""
        self._setup_report_mocks(monkeypatch, mock_config)

        result = runner.invoke(cli, ["intel", "report", "--manager", "npm"])

        assert result.exit_code == 0
        assert "Ecosystem: npm" in result.output

    def test_report_partial_data_only_eco_table(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat Landscape: only ecosystem_rows → just eco_table."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            ecosystem_rows=[("npm", 10, 5, 3, 2, 20)],
            top_pkg_rows=[],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "Top Targeted Ecosystems" in result.output

    def test_report_partial_data_only_pkg_table(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat Landscape: only top_pkg_rows → just pkg_table."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            ecosystem_rows=[],
            top_pkg_rows=[("axios", "npm", 5, "CRITICAL")],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "Top Targeted Packages" in result.output

    def test_report_partial_data_no_landscape(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """Threat Landscape: no data → dim message."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            ecosystem_rows=[],
            top_pkg_rows=[],
        )

        result = runner.invoke(cli, ["intel", "report"])

        assert result.exit_code == 0
        assert "No ecosystem or package data available" in result.output

    def test_report_exclude_severity_all(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """All severities excluded → no ecosystem columns to query."""
        self._setup_report_mocks(
            monkeypatch,
            mock_config,
            ecosystem_rows=[],
            top_pkg_rows=[],
            ecosystem_query_expected=False,
        )

        result = runner.invoke(
            cli,
            [
                "intel",
                "report",
                "--exclude-severity",
                "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
            ],
        )

        assert result.exit_code == 0
        # When all severities excluded, no ecosystem or package data
        assert "No ecosystem or package data available" in result.output

    def test_report_pretty_json(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        mock_config: PKGDConfig,
    ) -> None:
        """--pretty --json passes pretty=True."""
        captured: dict[str, Any] = {}

        def _capture_json(data: Any, pretty: bool = False) -> str:
            captured["pretty"] = pretty
            return json.dumps(data, indent=2) if pretty else json.dumps(data)

        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.format_json",
            _capture_json,
        )
        self._setup_report_mocks(monkeypatch, mock_config, stale_check_expected=False)

        result = runner.invoke(cli, ["intel", "report", "--json", "--pretty"])
        assert result.exit_code == 0
        assert captured.get("pretty") is True


# ============================================================================
# TestIntelSyncHomebrewAlert
# ============================================================================


class TestIntelSyncHomebrewAlert:
    """Tests for the Homebrew Vulnerability Alert after intel sync.

    Covers the post-sync code in intel.py lines 259-295:
      - homebrew N>0  → query_threats_by_source called, alert panel shown
      - homebrew N==0 → no alert, no DB query
      - homebrew records found → Panel rendered with package details
      - homebrew records empty → Panel NOT rendered
      - Other feeds N>0  → no Homebrew alert triggered
      - homebrew status "failed" with count N>0 → alert still shows
        (the alert is gated on results count, not feed status)
    """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mock_db_path(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        """Mock ``get_db_path`` and ``shutil.disk_usage`` for sync tests."""
        mock_db_path = MagicMock(spec=Path)
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value = MagicMock(st_size=100 * 1024 * 1024)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.get_db_path",
            lambda: mock_db_path,
        )
        mock_usage = MagicMock()
        mock_usage.free = 500 * 1024 * 1024 * 1024
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.shutil.disk_usage",
            lambda _path: mock_usage,
        )
        return mock_db_path

    def _run_sync(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        feed_results: dict[str, int] | None = None,
        sync_summary: dict[str, dict[str, Any]] | None = None,
        query_results: list[dict[str, Any]] | None = None,
    ) -> None:
        """Run intel sync with mocked infra and Homebrew alert path."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        if feed_results is None:
            feed_results = {"osv": 15, "homebrew": 0}
        if sync_summary is None:
            sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        # Mock sqlite3.connect and query_threats_by_source
        mock_db_path = MagicMock()
        mock_db_path.configure_mock(**{"__str__": MagicMock(return_value="/tmp/test.db")})

        mock_query = MagicMock(return_value=query_results) if query_results is not None else MagicMock(return_value=[])

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch(
                "pkg_defender.cli.commands.intel.brew_get_installed_version",
                AsyncMock(return_value="8.0.1"),
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            mock_connect.return_value = MagicMock()

            # We need to patch get_db_path before the alert section uses it
            monkeypatch.setattr(
                "pkg_defender.cli.commands.intel.get_db_path",
                lambda: mock_db_path,
            )

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0
        self._mock_print = mock_print

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_homebrew_with_vulnerabilities_triggers_alert(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew with N>0 queries threats and shows alert panel."""
        query_results = [
            {
                "package_name": "curl",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "summary": "Buffer overflow",
                "detail_url": "https://osv.dev/curl",
            },
        ]

        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 15, "homebrew": 3, "ghsa": 7, "rss": 0, "ossf_malicious": 0}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        mock_query = MagicMock(return_value=query_results)

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch(
                "pkg_defender.cli.commands.intel.brew_get_installed_version",
                AsyncMock(return_value="8.0.1"),
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # query_threats_by_source should have been called with homebrew params
        mock_query.assert_called_once()
        call_args = mock_query.call_args
        assert call_args[1]["ecosystem"] == "homebrew"
        assert call_args[1]["source"] == "homebrew_osv"

        # Alert Panel should have been rendered (console.print called with Panel)
        from rich.panel import Panel

        panel_calls = [c for c in mock_print.call_args_list if len(c[0]) > 0 and isinstance(c[0][0], Panel)]
        assert len(panel_calls) >= 1, (
            f"Expected at least one Panel rendered, got {len(panel_calls)} print calls: "
            f"{[(str(c[0][0])[:80] if len(c[0]) > 0 else '') for c in mock_print.call_args_list]}"
        )

    def test_homebrew_no_vulnerabilities_no_alert(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew with N==0 does not query threats or show alert."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 0, "ossf_malicious": 0}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        mock_query = MagicMock()

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch("pkg_defender.cli.commands.intel.console.print"),
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # query_threats_by_source should NOT have been called
        mock_query.assert_not_called()

    def test_homebrew_no_records_in_db_no_alert(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew with N>0 but no records in DB does not show alert."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 15, "homebrew": 1, "ghsa": 7, "rss": 0, "ossf_malicious": 0}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        mock_query = MagicMock(return_value=[])  # Empty records

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch("pkg_defender.cli.commands.intel.brew_get_installed_version", AsyncMock(return_value="8.0.1")),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # query was called (since homebrew_count > 0)
        mock_query.assert_called_once()

        # No Panel should be rendered when no records returned
        from rich.panel import Panel

        panel_calls = [c for c in mock_print.call_args_list if len(c[0]) > 0 and isinstance(c[0][0], Panel)]
        assert len(panel_calls) == 0, f"Expected no Panel when records empty, got {len(panel_calls)}"

    def test_other_feed_with_count_does_not_trigger_homebrew_alert(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-homebrew feed with N>0 does NOT trigger Homebrew alert query."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 15, "homebrew": 0, "ghsa": 7, "rss": 0, "ossf_malicious": 5}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        mock_query = MagicMock()

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch("pkg_defender.cli.commands.intel.console.print"),
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # query_threats_by_source should NOT have been called
        mock_query.assert_not_called()

    def test_homebrew_with_cvss_score_shows_cvss(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Homebrew alert includes CVSS score when present in record."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 0, "homebrew": 2}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        query_results = [
            {
                "package_name": "curl",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "summary": "Buffer overflow",
                "detail_url": "https://osv.dev/curl",
            },
            {
                "package_name": "openssl",
                "severity": "CRITICAL",
                "cvss_score": None,
                "summary": "RCE in openssl",
                "detail_url": "https://osv.dev/openssl",
            },
        ]
        mock_query = MagicMock(return_value=query_results)

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch(
                "pkg_defender.cli.commands.intel.brew_get_installed_version",
                AsyncMock(return_value="8.0.1"),
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # Verify the Panel was rendered with the right subtitle
        from rich.panel import Panel

        panel_calls = [c for c in mock_print.call_args_list if len(c[0]) > 0 and isinstance(c[0][0], Panel)]
        assert len(panel_calls) >= 1, "Expected at least one Panel rendered"

        panel = panel_calls[0][0][0]
        assert panel.subtitle is not None
        assert "2 Vulnerable Packages" in panel.subtitle, (
            f"Expected '2 Vulnerable Packages' in subtitle, got: {panel.subtitle}"
        )

        # Verify brew_get_installed_version was called for both packages

    def test_homebrew_single_vulnerable_package_singular_label(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Single vulnerable package uses singular label 'Package'."""
        self._mock_db_path(monkeypatch)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.should_show_progress",
            lambda: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.intel.is_quiet_mode",
            lambda: False,
        )

        feed_results = {"osv": 0, "homebrew": 1}
        sync_summary = {k: {"status": "success"} for k in feed_results}

        aggregator = MagicMock()
        aggregator.sync_all = AsyncMock(return_value=feed_results)
        aggregator.get_sync_summary.return_value = sync_summary
        aggregator.get_feed_metadata.return_value = {}
        aggregator.get_failed_feeds.return_value = {}

        query_results = [
            {
                "package_name": "curl",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "summary": "Buffer overflow",
                "detail_url": "https://osv.dev/curl",
            },
        ]
        mock_query = MagicMock(return_value=query_results)

        with (
            patch(
                "pkg_defender.intel.aggregator.FeedAggregator",
                return_value=aggregator,
            ),
            patch("pkg_defender.cli.commands.intel.sqlite3.connect") as mock_connect,
            patch(
                "pkg_defender.cli.commands.intel.query_threats_by_source",
                mock_query,
            ),
            patch(
                "pkg_defender.cli.commands.intel.brew_get_installed_version",
                AsyncMock(return_value="8.0.1"),
            ),
            patch("pkg_defender.cli.commands.intel.console.print") as mock_print,
        ):
            mock_connect.return_value = MagicMock()

            result = runner.invoke(cli, ["intel", "sync"])

        assert result.exit_code == 0

        # Verify the Panel subtitle uses singular "Package"
        from rich.panel import Panel

        panel_calls = [c for c in mock_print.call_args_list if len(c[0]) > 0 and isinstance(c[0][0], Panel)]
        assert len(panel_calls) >= 1, "Expected at least one Panel rendered"

        panel = panel_calls[0][0][0]
        assert panel.subtitle is not None
        assert panel.subtitle == "1 Vulnerable Package Found", (
            f"Expected singular '1 Vulnerable Package Found', got: {panel.subtitle}"
        )
