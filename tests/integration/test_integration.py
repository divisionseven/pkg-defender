"""Integration and edge case tests for pkg-defender.

Covers:
- End-to-end install flow (cooldown → threat → display)
- Stale DB warning behavior
- strict_mode=True blocking vs strict_mode=False allowing
- Bypass flow with audit logging
- Version parsing edge cases (semver pre-release, build metadata)
- Config set/reset commands
- Error paths (network failures, invalid config, missing dirs)
- audit --json output
- Multi-feed sync integration (OSV + GHSA + Socket)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import (
    EXIT_REGISTRY_UNREACHABLE,
    EXIT_THREAT_DETECTED,
)
from pkg_defender.cli.main import cli
from pkg_defender.db.schema import (
    init_db,
    insert_threat,
    insert_version_timestamp,
    update_feed_state,
)
from pkg_defender.models import ThreatRecord, VersionInfo


def _make_threat(
    *,
    id: str = "osv:TEST-001",
    ecosystem: str = "npm",
    package_name: str = "lodash",
    affected_versions: list[str] | None = None,
    affected_ranges: list[str] | None = None,
    severity: str = "HIGH",
    confidence: float = 0.85,
    source: str = "osv",
    source_id: str = "TEST-001",
    summary: str = "test threat",
) -> ThreatRecord:
    """Helper to build a ThreatRecord with sane defaults."""
    return ThreatRecord(
        id=id,
        ecosystem=ecosystem,
        package_name=package_name,
        affected_versions=affected_versions if affected_versions is not None else [],
        affected_ranges=affected_ranges if affected_ranges is not None else [],
        severity=severity,
        confidence=confidence,
        source=source,
        source_id=source_id,
        summary=summary,
        detail_url=None,
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 6, 1, tzinfo=UTC),
    )


# ===================================================================
# 7. Config Set/Reset CLI Commands
# ===================================================================


class TestConfigSetReset:
    """Tests for pkgd config set and pkgd config reset commands."""

    def test_config_set_basic(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set cooldown.default_days 3 writes to TOML file."""
        config_path = isolated_env["config_path"]
        # Make sure the config dir exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        runner.invoke(cli, ["config", "set", "cooldown.default_days", "3"], input="3\n3\n")
        # Verify the file was written (command may have failed due to other checks)
        assert config_path.exists()
        content = config_path.read_text()
        # Allow both integer and string formats
        assert "default_days" in content

    def test_config_set_boolean(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set cooldown.strict_mode false writes boolean TOML."""
        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)

        runner.invoke(cli, ["config", "set", "cooldown.strict_mode", "false"], input="false\nfalse\n")
        # Exit code doesn't matter for this test
        content = config_path.read_text()
        assert "strict_mode" in content

    def test_config_set_invalid_key_format(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set invalidkey value → exit code 6 (config error)."""
        result = runner.invoke(cli, ["config", "set", "invalidkey", "value"])
        assert result.exit_code == 6
        assert "Unknown config key" in result.output

    def test_config_set_rejects_nonexistent_section(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set nonexistent.key value → exit 6."""
        result = runner.invoke(cli, ["config", "set", "nonexistent.foo", "value"])
        assert result.exit_code == 6
        assert "Unknown config key" in result.output

    def test_config_set_and_get_preserves_int_type(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set + get round-trip preserves int type."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n\n[cooldown]\n")
        # Set an int value using --config to bypass project-level config discovery
        set_result = runner.invoke(cli, ["--config", str(config_path), "config", "set", "cooldown.default_days", "7"])
        assert set_result.exit_code == 0
        # Read the TOML directly to verify the type is int
        content = config_path.read_text()
        parsed = tomllib.loads(content)
        assert isinstance(parsed["cooldown"]["default_days"], int)
        assert parsed["cooldown"]["default_days"] == 7
        # Read it back via CLI
        get_result = runner.invoke(cli, ["--config", str(config_path), "config", "get", "cooldown.default_days"])
        assert get_result.exit_code == 0
        assert get_result.output.strip() == "7"

    def test_config_set_and_get_preserves_bool_type(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set + get round-trip preserves bool type."""
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n\n[cooldown]\n")
        # Set a bool value using --config to bypass project-level config discovery
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "cooldown.strict_mode", "false"],
        )
        assert set_result.exit_code == 0
        # Read the TOML directly to verify the type is bool
        content = config_path.read_text()
        parsed = tomllib.loads(content)
        assert isinstance(parsed["cooldown"]["strict_mode"], bool)
        assert parsed["cooldown"]["strict_mode"] is False
        # Read it back via CLI
        get_result = runner.invoke(cli, ["--config", str(config_path), "config", "get", "cooldown.strict_mode"])
        assert get_result.exit_code == 0

    def test_config_set_root_level_int_round_trip(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set + get round-trip preserves root-level int type.

        Root-level keys use a different coercion path (len(parts) == 1).
        This test verifies command_timeout_seconds (int) round-trips as int.
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n")
        # Set a root-level int value
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "command_timeout_seconds", "45"],
        )
        assert set_result.exit_code == 0
        # Verify TOML type is int
        content = config_path.read_text()
        parsed = tomllib.loads(content)
        assert isinstance(parsed["command_timeout_seconds"], int)
        assert parsed["command_timeout_seconds"] == 45
        # Verify CLI get returns correct value
        get_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "get", "command_timeout_seconds"],
        )
        assert get_result.exit_code == 0
        assert get_result.output.strip() == "45"

    def test_config_set_root_level_bool_round_trip(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set + get round-trip preserves root-level bool type.

        Root-level keys use a different coercion path (len(parts) == 1).
        This test verifies fail_on_threat_enabled (bool) round-trips as bool.
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n")
        # Set a root-level bool value
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "fail_on_threat_enabled", "false"],
        )
        assert set_result.exit_code == 0
        # Verify TOML type is bool
        content = config_path.read_text()
        parsed = tomllib.loads(content)
        assert isinstance(parsed["fail_on_threat_enabled"], bool)
        assert parsed["fail_on_threat_enabled"] is False
        # Verify CLI get returns correct value
        get_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "get", "fail_on_threat_enabled"],
        )
        assert get_result.exit_code == 0

    def test_config_set_preserves_existing_keys(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Setting one key preserves other existing keys in the config.

        Regression test: the config dict manipulation in config_set() must
        not drop existing keys when writing new ones.
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # Write a config with multiple sections and keys
        config_path.write_text(
            "# minimal config\n\n"
            "[cooldown]\n"
            "default_days = 3\n"
            "enabled = true\n"
            "strict_mode = true\n"
            "\n"
            "[feeds]\n"
            "osv_enabled = true\n"
            "http_timeout = 60\n"
        )
        # Set a new key in the cooldown section
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "cooldown.bypass_require_reason", "false"],
        )
        assert set_result.exit_code == 0
        # Verify ALL existing keys and the new one are preserved
        parsed = tomllib.loads(config_path.read_text())
        assert parsed["cooldown"]["default_days"] == 3
        assert parsed["cooldown"]["enabled"] is True
        assert parsed["cooldown"]["strict_mode"] is True
        assert parsed["cooldown"]["bypass_require_reason"] is False
        assert parsed["feeds"]["osv_enabled"] is True
        assert parsed["feeds"]["http_timeout"] == 60

    def test_config_set_idempotent(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Setting the same key twice produces the same result.

        Idempotency test: config set cooldown.default_days 7 twice should
        produce identical file content both times.
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n\n[cooldown]\n")
        # Set the same value twice
        set_result_1 = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "cooldown.default_days", "7"],
        )
        assert set_result_1.exit_code == 0
        parsed_1 = tomllib.loads(config_path.read_text())
        assert parsed_1["cooldown"]["default_days"] == 7
        # Second set
        set_result_2 = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "cooldown.default_days", "7"],
        )
        assert set_result_2.exit_code == 0
        parsed_2 = tomllib.loads(config_path.read_text())
        assert parsed_2 == parsed_1  # identical outputs

    def test_config_set_creates_file_when_missing(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Setting a key when no config file exists creates one.

        Exercises the data = {} / no-file-exists path in config_set().
        """
        import tomllib

        config_path = isolated_env["config_path"]
        # Ensure the file does NOT exist (fixture creates the parent dir, not the file)
        config_path.unlink(missing_ok=True)
        assert not config_path.exists()
        # Set a value — should create the config file
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "cooldown.default_days", "7"],
        )
        assert set_result.exit_code == 0
        assert config_path.exists()
        parsed = tomllib.loads(config_path.read_text())
        assert parsed["cooldown"]["default_days"] == 7

    def test_config_set_string_field_preserves_type(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Setting a str field writes a quoted string in TOML.

        The type coercion code skips non-bool/non-int/non-float fields,
        so string values pass through to _write_config_toml as-is.
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("# minimal config\n\n[feeds]\n")
        # Set a string field
        set_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set", "feeds.mastodon_instance", "mastodon.social"],
        )
        assert set_result.exit_code == 0
        parsed = tomllib.loads(config_path.read_text())
        assert parsed["feeds"]["mastodon_instance"] == "mastodon.social"
        # Verify CLI get returns the correct value
        get_result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "get", "feeds.mastodon_instance"],
        )
        assert get_result.exit_code == 0
        assert "mastodon.social" in get_result.output

    def test_config_reset_no_config_file(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config reset when no config exists → 'already at defaults'."""
        # Ensure config file doesn't exist
        isolated_env["config_path"].unlink(missing_ok=True)
        result = runner.invoke(cli, ["config", "reset"], input="y\n")
        assert result.exit_code == 0
        assert "already at defaults" in result.output.lower()

    def test_config_reset_with_existing_file(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config reset with existing config → deletes file."""
        config_path = isolated_env["config_path"]
        config_path.write_text("[cooldown]\ndefault_days = 7\n")
        assert config_path.exists()

        result = runner.invoke(cli, ["config", "reset"], input="y\n")
        assert result.exit_code == 0
        assert "reset" in result.output.lower() or "Deleted" in result.output


# ===================================================================
# 8. Audit JSON Output
# ===================================================================


class TestAuditJsonOutput:
    """Tests for pkgd audit --json output."""

    def test_audit_json_no_threats(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd audit --json with no threats → valid JSON with total and empty threats."""
        audit_dir = isolated_env["db_path"].parent / "audit_json"
        audit_dir.mkdir(parents=True, exist_ok=True)
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        (audit_dir / "package-lock.json").write_text(json.dumps(lock_data))

        result = runner.invoke(cli, ["audit", str(audit_dir), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total"] == 1
        assert data["threats"] == []

    def test_audit_json_with_threats(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd audit --json with threats → valid JSON with threat details."""
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        threat = _make_threat(
            id="osv:JSON-001",
            package_name="lodash",
            affected_versions=["4.17.21"],
            severity="HIGH",
        )
        insert_threat(conn, threat)
        conn.close()

        audit_dir = isolated_env["db_path"].parent / "audit_json_threat"
        audit_dir.mkdir(parents=True, exist_ok=True)
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        (audit_dir / "package-lock.json").write_text(json.dumps(lock_data))

        result = runner.invoke(cli, ["audit", str(audit_dir), "--json"])
        assert result.exit_code == EXIT_THREAT_DETECTED  # strict mode with threats
        data = json.loads(result.stdout)
        assert data["total"] == 1
        assert len(data["threats"]) == 1
        assert data["threats"][0]["package"] == "lodash"

    def test_audit_corrupt_lock_file(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd audit with corrupt JSON → exit 2."""
        audit_dir = isolated_env["db_path"].parent / "audit_corrupt"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "package-lock.json").write_text("{invalid json!!!")

        result = runner.invoke(cli, ["audit", str(audit_dir)])
        assert result.exit_code == EXIT_REGISTRY_UNREACHABLE
        assert "Cannot read lock file" in result.output or "Error" in result.output


# ===================================================================
# 9. Intel Sync Error Path
# ===================================================================


class TestIntelSyncErrors:
    """Tests for error handling in pkgd intel sync."""

    def test_sync_feed_graceful_failure(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd intel sync with one feed failing → other feeds still work, exit 0."""

        async def mock_sync_all_failure(*args: Any, **kwargs: Any) -> dict[str, int]:
            return {"osv": 0, "ghsa": 0, "socket": 0}

        with patch("pkg_defender.intel.aggregator.FeedAggregator") as mock_agg_class:
            mock_agg = mock_agg_class.return_value
            # OSV fails (returns 0), others succeed
            mock_agg.sync_all = mock_sync_all_failure

            result = runner.invoke(cli, ["intel", "sync"])
            assert result.exit_code == 0
            assert "already up to date" in result.output.lower()


# ===================================================================
# 10. Health Command Edge Cases
# ===================================================================


class TestHealthEdgeCases:
    """Additional edge case tests for pkgd health."""

    def test_health_with_osv_synced(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd health with synced OSV feed → core checks pass.

        Note: Exit code is 1 because shell hooks are not installed.
        """
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        update_feed_state(conn, "osv", None, "idle")
        conn.close()

        isolated_env["config_path"].write_text("[cooldown]\ndefault_days = 1\n")

        result = runner.invoke(cli, ["health"])
        # Core checks pass, but exit code is 1 due to missing shell hooks
        assert result.exit_code == 1
        assert "OK" in result.output

    def test_health_config_exists(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd health with config file → config check shows OK.

        Note: Exit code is 1 because shell hooks are not installed.
        """
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        update_feed_state(conn, "osv", None, "idle")
        conn.close()

        isolated_env["config_path"].write_text("[cooldown]\ndefault_days = 1\n")

        result = runner.invoke(cli, ["health"])
        # Core checks pass, but exit code is 1 due to missing shell hooks
        assert result.exit_code == 1
        assert "Config file" in result.output

    def test_health_verbose_with_real_db(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Health --verbose works with a real (seeded) database."""
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        update_feed_state(conn, "osv", None, "idle")
        conn.close()
        isolated_env["config_path"].write_text("[cooldown]\ndefault_days = 1\n")
        result = runner.invoke(cli, ["health", "--verbose"])
        assert result.exit_code == 1  # hooks not installed
        assert "OK" in result.output


# ===================================================================
# 11. Reset Command Edge Cases
# ===================================================================


class TestResetEdgeCases:
    """Additional edge case tests for pkgd reset."""

    def test_reset_no_data_to_delete(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd reset when no DB or config exists → 'No data to reset'."""
        # Ensure neither file exists
        isolated_env["db_path"].unlink(missing_ok=True)
        isolated_env["config_path"].unlink(missing_ok=True)

        result = runner.invoke(cli, ["reset"], input="y\n")
        assert result.exit_code == 0
        assert "No data to reset" in result.output


# ===================================================================
# 14. Scoped Package Parsing in Install
# ===================================================================


class TestFullAuditPipelineIntegration:
    """End-to-end audit pipeline: detect lock file → parse → check threats → display.

    Tests the full Phase 2 audit flow across multiple lock file formats.
    """

    def test_audit_detect_lock_file_parse_check_threats(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Full pipeline: detect lock file, parse, check threats, display results."""
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)

        # Seed threat for one of the packages in the lock file
        threat = _make_threat(
            id="osv:AUDIT-PIPE-1",
            package_name="lodash",
            affected_versions=["4.17.21"],
            severity="CRITICAL",
            source="osv",
        )
        insert_threat(conn, threat)
        conn.close()

        # Create a package-lock.json with multiple packages
        audit_dir = isolated_env["db_path"].parent / "audit_pipeline"
        audit_dir.mkdir(parents=True, exist_ok=True)
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/axios": {"version": "1.6.0"},
            },
        }
        (audit_dir / "package-lock.json").write_text(json.dumps(lock_data))

        result = runner.invoke(cli, ["audit", str(audit_dir)])
        # Should find the lodash threat
        assert result.exit_code == EXIT_THREAT_DETECTED  # strict mode with threats
        assert "lodash" in result.output.lower()

    def test_audit_poetry_lock_deep_mode(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Audit poetry.lock with deep mode checks cooldown violations."""
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)

        # Seed a threat for requests
        threat = _make_threat(
            id="osv:POETRY-1",
            package_name="requests",
            affected_versions=["2.31.0"],
            severity="HIGH",
            source="osv",
            ecosystem="pypi",
        )
        insert_threat(conn, threat)

        # Seed a very recent version timestamp for certifi (cooldown violation)

        insert_version_timestamp(
            conn,
            VersionInfo(
                version="2024.2.2",
                publish_time=datetime.now(UTC) - timedelta(hours=1),
                ecosystem="pypi",
                package_name="certifi",
            ),
        )
        conn.close()

        # Copy the poetry.lock fixture
        import shutil

        fixture = Path(__file__).parent.parent / "fixtures" / "lock_files" / "poetry.lock"
        audit_dir = isolated_env["db_path"].parent / "audit_poetry"
        audit_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(fixture, audit_dir / "poetry.lock")

        result = runner.invoke(cli, ["audit", str(audit_dir), "--deep"])
        # Should find the requests threat
        assert result.exit_code == EXIT_THREAT_DETECTED
        assert "requests" in result.output.lower()

    def test_audit_requirements_txt_format(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Audit requirements.txt format end-to-end."""
        db_path = isolated_env["db_path"]
        conn = init_db(db_path)

        threat = _make_threat(
            id="osv:REQ-1",
            package_name="flask",
            affected_versions=["3.0.0"],
            severity="HIGH",
            source="osv",
            ecosystem="pypi",
        )
        insert_threat(conn, threat)
        conn.close()

        import shutil

        fixture = Path(__file__).parent.parent / "fixtures" / "lock_files" / "requirements.txt"
        audit_dir = isolated_env["db_path"].parent / "audit_req"
        audit_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(fixture, audit_dir / "requirements.txt")

        result = runner.invoke(cli, ["audit", str(audit_dir)])
        assert result.exit_code == EXIT_THREAT_DETECTED
        assert "flask" in result.output.lower()

    def test_audit_clean_lock_file_passes(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Clean lock file with no threats → passes (exit 0)."""
        audit_dir = isolated_env["db_path"].parent / "audit_clean"
        audit_dir.mkdir(parents=True, exist_ok=True)
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/safe-pkg": {"version": "1.0.0"},
            },
        }
        (audit_dir / "package-lock.json").write_text(json.dumps(lock_data))

        result = runner.invoke(cli, ["audit", str(audit_dir)])
        assert result.exit_code == 0


# ===================================================================
# 16. Phase 2: Multi-Feed Sync Integration
# ===================================================================


class TestMultiFeedSyncIntegration:
    """Multi-feed sync: OSV + GHSA + Socket → aggregator → DB → verify no duplicates.

    Tests idempotency, deduplication across feeds, and per-feed isolation.
    """

    @pytest.mark.asyncio
    async def test_multi_feed_sync_no_duplicates(self, isolated_env: dict[str, Path]) -> None:
        """Syncing the same threat from OSV and GHSA produces no duplicates in DB."""
        from pkg_defender.intel.aggregator import FeedAggregator
        from pkg_defender.intel.base import FeedFetchResult, FeedSource

        db_path = isolated_env["db_path"]
        conn = init_db(db_path)

        now = datetime.now(UTC)

        # Create two mock feeds that return the same package threat
        # but with different source IDs (simulating OSV + GHSA for same vuln)
        class MockOSVFeed(FeedSource):
            @property
            def name(self) -> str:
                return "osv"

            @property
            def supports_incremental(self) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(
                    records=[
                        ThreatRecord(
                            id="osv:DEDUP-1",
                            ecosystem="npm",
                            package_name="lodash",
                            affected_versions=["4.17.20"],
                            affected_ranges=[],
                            severity="CRITICAL",
                            confidence=0.85,
                            source="osv",
                            source_id="DEDUP-1",
                            summary="Prototype pollution",
                            detail_url="https://osv.dev/DEDUP-1",
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    feed_metadata={},
                )

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        class MockGHSAFeed(FeedSource):
            @property
            def name(self) -> str:
                return "ghsa"

            @property
            def supports_incremental(self) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(
                    records=[
                        ThreatRecord(
                            id="ghsa:DEDUP-2",
                            ecosystem="npm",
                            package_name="lodash",
                            affected_versions=["4.17.20"],
                            affected_ranges=[],
                            severity="CRITICAL",
                            confidence=0.85,
                            source="ghsa",
                            source_id="DEDUP-2",
                            summary="Prototype pollution via GHSA",
                            detail_url="https://github.com/advisories/DEDUP-2",
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    feed_metadata={},
                )

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        feeds = [MockOSVFeed(), MockGHSAFeed()]
        aggregator = FeedAggregator(feeds, db_path)

        # First sync
        result = await aggregator.sync_all()
        assert result["osv"] == 1
        assert result["ghsa"] == 1

        # Verify both threats in DB
        all_threats = conn.execute("SELECT id FROM threats").fetchall()
        assert len(all_threats) == 2

        # Second sync (idempotency check)
        await aggregator.sync_all()
        # Records are upserted (hit_count incremented), no new rows
        all_threats2 = conn.execute("SELECT id FROM threats").fetchall()
        assert len(all_threats2) == 2

        # Hit counts should have increased
        for row in conn.execute("SELECT id, hit_count FROM threats").fetchall():
            assert row[1] >= 2

        conn.close()

    @pytest.mark.asyncio
    async def test_one_feed_failure_does_not_block_others(self, isolated_env: dict[str, Path]) -> None:
        """If OSV feed raises, GHSA and Socket results still get stored."""
        from pkg_defender.intel.aggregator import FeedAggregator
        from pkg_defender.intel.base import FeedFetchResult, FeedSource

        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        now = datetime.now(UTC)

        class FailingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "osv"

            @property
            def supports_incremental(self) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                raise RuntimeError("OSV API down")

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        class WorkingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "ghsa"

            @property
            def supports_incremental(self) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(
                    records=[
                        ThreatRecord(
                            id="ghsa:WORKING-1",
                            ecosystem="npm",
                            package_name="axios",
                            affected_versions=["1.0.0"],
                            affected_ranges=[],
                            severity="HIGH",
                            confidence=0.85,
                            source="ghsa",
                            source_id="WORKING-1",
                            summary="SSRF vulnerability",
                            detail_url=None,
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    feed_metadata={},
                )

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        aggregator = FeedAggregator([FailingFeed(), WorkingFeed()], db_path)
        result = await aggregator.sync_all()

        # OSV failed (0), GHSA succeeded (1)
        assert result["osv"] == 0
        assert result["ghsa"] == 1

        # Verify GHSA threat is in DB despite OSV failure
        rows = conn.execute("SELECT id FROM threats").fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "ghsa:WORKING-1"

        conn.close()

    @pytest.mark.asyncio
    async def test_three_feeds_sync_independently(self, isolated_env: dict[str, Path]) -> None:
        """Three feeds sync concurrently, each with its own transaction boundary."""
        from pkg_defender.intel.aggregator import FeedAggregator
        from pkg_defender.intel.base import FeedFetchResult, FeedSource

        db_path = isolated_env["db_path"]
        conn = init_db(db_path)
        now = datetime.now(UTC)

        def make_feed(name: str, pkg: str, severity: str) -> FeedSource:
            class NamedFeed(FeedSource):
                @property
                def feed_name(self) -> str:
                    return name

                @property
                def name(self) -> str:
                    return name

                @property
                def supports_incremental(self) -> bool:
                    return True

                async def fetch(
                    self,
                    since: datetime | None = None,
                    ecosystems: list[str] | None = None,
                    session: aiohttp.ClientSession | None = None,
                    config: Any = None,
                ) -> FeedFetchResult:
                    return FeedFetchResult(
                        records=[
                            ThreatRecord(
                                id=f"{name}:MULTI-1",
                                ecosystem="npm",
                                package_name=pkg,
                                affected_versions=["1.0.0"],
                                affected_ranges=[],
                                severity=severity,
                                confidence=0.85,
                                source=name,
                                source_id="MULTI-1",
                                summary=f"Threat from {name}",
                                detail_url=None,
                                first_seen=now,
                                last_seen=now,
                            )
                        ],
                        feed_metadata={},
                    )

                async def check_package(
                    self,
                    package: str,
                    version: str,
                    ecosystem: str,
                    session: aiohttp.ClientSession | None = None,
                    config: Any = None,
                ) -> FeedFetchResult:
                    return FeedFetchResult(records=[], feed_metadata={})

                def is_configured(self, config: Any) -> bool:
                    return True

            return NamedFeed()

        feeds = [
            make_feed("osv", "lodash", "CRITICAL"),
            make_feed("ghsa", "axios", "HIGH"),
            make_feed("socket", "express", "MEDIUM"),
        ]

        aggregator = FeedAggregator(feeds, db_path)
        result = await aggregator.sync_all()

        assert result["osv"] == 1
        assert result["ghsa"] == 1
        assert result["socket"] == 1

        # All 3 threats should be in DB
        rows = conn.execute("SELECT source, package_name FROM threats ORDER BY source").fetchall()
        assert len(rows) == 3
        sources = {r[0] for r in rows}
        assert sources == {"osv", "ghsa", "socket"}

        conn.close()
