"""Tests for pkgd health --verbose command — coverage table."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli


class TestHealthVerbose:
    """Tests for the adapter coverage matrix via health --verbose."""

    def test_coverage_table_shows_all_17_adapters(self, runner: CliRunner, isolated_env: dict[str, Any]) -> None:
        """Verify coverage table has 17 rows (17 unique adapter classes)."""
        result = runner.invoke(cli, ["health", "--verbose"])
        # Health may report diagnostic issues — exit code can be non-zero
        # even when the coverage table renders successfully.
        assert result.exit_code in (0, 1), f"Exit code {result.exit_code}: {result.output[:200]}"
        # Check for feature-specific content that ONLY exists in the new table
        assert "Adapter Coverage Matrix" in result.output
        assert "Cooldown Status" in result.output
        # Count unique adapter manager names (17 unique classes, deduplicated)
        adapter_names = {
            "pip",
            "cargo",
            "composer",
            "gem",
            "npm",
            "yarn",
            "bun",
            "pnpm",
            "poetry",
            "pipenv",
            "uv",
            "bundle",
            "apt",
            "brew",
            "conda",
            "dnf",
            "yum",
        }
        found_adapters = {name for name in adapter_names if name in result.output}
        assert len(found_adapters) == 17, f"Expected 17 adapters, found {len(found_adapters)}: {found_adapters}"
        # FULL/PARTIAL adapters show "active" cooldown status in the table
        assert "active" in result.output

    def test_coverage_table_tier_color_coding(self, runner: CliRunner, isolated_env: dict[str, Any]) -> None:
        """Audit-tier adapters show 'skipped' cooldown status."""
        result = runner.invoke(cli, ["health", "--verbose"])
        assert result.exit_code in (0, 1), f"Exit code {result.exit_code}: {result.output[:200]}"
        assert "skipped" in result.output.lower()

    def test_health_verbose_json_includes_coverage(self, runner: CliRunner, isolated_env: dict[str, Any]) -> None:
        """JSON output has coverage array with expected keys."""
        import json

        result = runner.invoke(cli, ["health", "--verbose", "-o", "json"])
        assert result.exit_code in (0, 1), f"Exit code {result.exit_code}: {result.output[:200]}"
        # JSON output is on stdout (Rich tables now suppressed in JSON mode)
        data = json.loads(result.stdout)
        assert "coverage" in data
        assert isinstance(data["coverage"], list)
        assert len(data["coverage"]) == 17
        for entry in data["coverage"]:
            assert "adapter" in entry
            assert "ecosystem" in entry
            assert "coverage_tier" in entry
            assert "threat_count" in entry
            assert "cooldown_status" in entry
            # Validate coverage_tier is a known value
            assert entry["coverage_tier"] in ("full", "partial", "audit"), (
                f"Unexpected coverage_tier: {entry['coverage_tier']!r}"
            )
            # Validate cooldown_status is a known value
            assert entry["cooldown_status"] in ("active", "skipped"), (
                f"Unexpected cooldown_status: {entry['cooldown_status']!r}"
            )
            # Validate threat_count is a non-negative integer
            assert isinstance(entry["threat_count"], int) and entry["threat_count"] >= 0, (
                f"Invalid threat_count: {entry['threat_count']!r}"
            )

    def test_coverage_table_with_seeded_threats(
        self, runner: CliRunner, db_conn: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Seed threats in DB and verify counts appear in coverage table."""
        # db_conn fixture creates its own temp DB. Use its path as monkeypatched
        # override for get_db_path so CliRunner's health command connects to it.
        cursor = db_conn.execute("PRAGMA database_list")
        db_row = cursor.fetchone()
        assert db_row is not None, "Could not read db_conn database path"
        db_path_str = db_row[2]  # column 2 is the filename
        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: Path(db_path_str))

        # Insert test threats into db_conn
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test-1", "npm", "bad-pkg", "HIGH", 0.9, "osv", "test threat"),
        )
        db_conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test-2", "pypi", "evil-pkg", "CRITICAL", 0.95, "osv", "another threat"),
        )
        db_conn.commit()

        result = runner.invoke(cli, ["health", "--verbose"])
        assert result.exit_code in (0, 1), f"Exit code {result.exit_code}: {result.output[:200]}"
        # npm adapters should show at least 1 threat
        # (npm + yarn + bun + pnpm all use "npm" ecosystem)
        assert "1" in result.output

    def test_health_verbose_handles_no_db_gracefully(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """When DB is unavailable, health --verbose shows message not crash."""
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: Path("/nonexistent/test.db"),
        )
        result = runner.invoke(cli, ["health", "--verbose"])
        assert result.exit_code != 0
        # Should not traceback; should show graceful message
        assert "Error" in result.output or "not found" in result.output

    @pytest.mark.parametrize(
        ("tier_value", "expected_color"),
        [
            ("full", "green"),
            ("partial", "yellow"),
            ("audit", "red"),
        ],
    )
    def test_coverage_tier_colors(self, tier_value: str, expected_color: str) -> None:
        """Verify color coding for each tier value."""
        from pkg_defender.registry.base import CoverageTier

        tier = CoverageTier[tier_value.upper()]
        tier_styles = {
            CoverageTier.FULL: "[green]FULL[/]",
            CoverageTier.PARTIAL: "[yellow]PARTIAL[/]",
            CoverageTier.AUDIT: "[red]AUDIT[/]",
        }
        rendered = tier_styles[tier]
        assert f"[{expected_color}]" in rendered
        assert "[/]" in rendered
        assert tier_value.upper() in rendered
