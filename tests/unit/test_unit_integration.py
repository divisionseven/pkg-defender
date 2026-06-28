"""Unit and edge case tests for pkg-defender.

Covers:
- OSV severity mapping edge cases
- Display edge cases (long names, many threats, unicode)
- TOML writing fallback edge cases
- Version checking edge cases
"""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rich.console import Console

from pkg_defender.cli.common import _generate_config_template, _write_config_toml
from pkg_defender.core.checker import _parse_version
from pkg_defender.display import (
    display_allowed,
    display_both_block,
    display_cooldown_block,
    display_stale_db_warning,
    display_threat_block,
    humanize_timedelta,
)
from pkg_defender.models import CooldownResult, ScoredThreat, ThreatRecord
from pkg_defender.version import _version_matches


def _console_capture() -> Console:
    """Create a recording Console for output capture."""
    return Console(record=True, no_color=True, width=80)


# ===================================================================
# 1. End-to-End Install Flow Integration
# ===================================================================


class TestOSVIntegration:
    """Integration tests for OSV feed processing."""

    def test_cvss_just_below_7_0_is_medium(self) -> None:
        """CVSS score 6.99 → MEDIUM."""
        from pkg_defender.intel.feeds.osv import _cvss_to_severity

        assert _cvss_to_severity(6.99) == "MEDIUM"

    def test_cvss_just_below_4_0_is_low(self) -> None:
        """CVSS score 3.99 → LOW."""
        from pkg_defender.intel.feeds.osv import _cvss_to_severity

        assert _cvss_to_severity(3.99) == "LOW"

    def test_cvss_negative_returns_unknown(self) -> None:
        """Negative CVSS score → UNKNOWN."""
        from pkg_defender.intel.feeds.osv import _cvss_to_severity

        assert _cvss_to_severity(-1.0) == "UNKNOWN"

    def test_extract_cvss_non_numeric_string(self) -> None:
        """Non-numeric, non-CVSS string → None."""
        from pkg_defender.intel.feeds._osv_parser import _extract_cvss_score

        assert _extract_cvss_score("not-a-score") is None

    def test_extract_cvss_boundary_0(self) -> None:
        """CVSS score '0.0' → 0.0 (valid boundary)."""
        from pkg_defender.intel.feeds._osv_parser import _extract_cvss_score

        assert _extract_cvss_score("0.0") == 0.0

    def test_extract_cvss_boundary_10(self) -> None:
        """CVSS score '10.0' → 10.0 (valid boundary)."""
        from pkg_defender.intel.feeds._osv_parser import _extract_cvss_score

        assert _extract_cvss_score("10.0") == 10.0

    def test_map_severity_database_specific_invalid(self) -> None:
        """database_specific.severity with invalid value → UNKNOWN."""
        from pkg_defender.intel.feeds.osv import _map_severity

        vuln = {"database_specific": {"severity": "INVALID"}}
        assert _map_severity(vuln) == "UNKNOWN"

    def test_map_severity_database_specific_not_string(self) -> None:
        """database_specific.severity that is not a string → UNKNOWN."""
        from pkg_defender.intel.feeds.osv import _map_severity

        vuln = {"database_specific": {"severity": 42}}
        assert _map_severity(vuln) == "UNKNOWN"

    def test_parse_vuln_with_duplicate_versions(self) -> None:
        """Duplicate versions in affected list are deduplicated."""
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        vuln = {
            "id": "TEST-DUP",
            "affected": [
                {
                    "package": {"name": "pkg", "ecosystem": "npm"},
                    "versions": ["1.0.0", "1.0.0", "2.0.0"],
                }
            ],
        }
        record = _parse_osv_vuln(vuln, ecosystem="pkg")
        assert record.affected_versions.count("1.0.0") == 1
        assert "2.0.0" in record.affected_versions

    def test_parse_vuln_with_last_affected_range(self) -> None:
        """Range with last_affected creates '<=' bound."""
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        vuln = {
            "id": "TEST-LA",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"last_affected": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }
        record = _parse_osv_vuln(vuln, ecosystem="pkg")
        assert any(">=1.0.0" in r for r in record.affected_ranges)
        assert any("<=2.0.0" in r for r in record.affected_ranges)
        # NEW: Verify no bracket prefix
        for r in record.affected_ranges:
            assert not r.startswith("[")


# ===================================================================
# 6. Display Edge Cases
# ===================================================================


class TestDisplayEdgeCases:
    """Edge case tests for display functions."""

    def test_cooldown_block_with_long_package_name(self) -> None:
        """Long package names render without error."""
        con = _console_capture()
        result = CooldownResult(
            allowed=False,
            age=timedelta(hours=2),
            remaining=timedelta(hours=22),
            reason="too_new",
        )
        long_name = "@very-long-scope/very-long-package-name-for-testing"
        display_cooldown_block(long_name, "1.0.0", result, console=con)
        output = con.export_text()
        assert long_name in output

    def test_threat_block_with_many_threats(self) -> None:
        """Many threats render without error."""
        con = _console_capture()
        threats = []
        for i in range(20):
            record = ThreatRecord(
                id=f"osv:THREAT-{i}",
                ecosystem="npm",
                package_name="vuln-pkg",
                affected_versions=["1.0.0"],
                affected_ranges=[],
                severity="HIGH",
                confidence=0.8,
                source="osv",
                source_id=f"THREAT-{i}",
                summary=f"Vulnerability #{i} with details",
                detail_url=f"https://osv.dev/vulnerability/THREAT-{i}",
                first_seen=datetime(2024, 1, 1, tzinfo=UTC),
                last_seen=datetime(2024, 6, 1, tzinfo=UTC),
            )
            threats.append(
                ScoredThreat(
                    record=record,
                    final_score=0.8,
                    display_severity="HIGH",
                    version_match_type="exact",
                )
            )
        display_threat_block("vuln-pkg", "1.0.0", threats, console=con)
        output = con.export_text()
        assert "vuln-pkg@1.0.0" in output

    def test_threat_block_with_unicode_summary(self) -> None:
        """Unicode characters in summary render correctly."""
        con = _console_capture()
        record = ThreatRecord(
            id="osv:UNICODE-1",
            ecosystem="npm",
            package_name="unicode-pkg",
            affected_versions=["1.0.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="osv",
            source_id="UNICODE-1",
            summary="XSS vulnerability — 日本語テスト — émojis 🚨",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, tzinfo=UTC),
        )
        threats = [
            ScoredThreat(
                record=record,
                final_score=0.9,
                display_severity="HIGH",
                version_match_type="exact",
            )
        ]
        display_threat_block("unicode-pkg", "1.0.0", threats, console=con)
        output = con.export_text()
        assert "unicode-pkg@1.0.0" in output

    def test_both_block_with_no_threat_detail_url(self) -> None:
        """Both block handles threats with no detail_url."""
        con = _console_capture()
        cooldown = CooldownResult(
            allowed=False,
            age=timedelta(hours=1),
            remaining=timedelta(hours=23),
        )
        record = ThreatRecord(
            id="osv:NOURL-1",
            ecosystem="npm",
            package_name="pkg",
            affected_versions=["1.0.0"],
            affected_ranges=[],
            severity="MEDIUM",
            confidence=0.7,
            source="osv",
            source_id="NOURL-1",
            summary="No URL threat",
            detail_url=None,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 6, 1, tzinfo=UTC),
        )
        threats = [
            ScoredThreat(
                record=record,
                final_score=0.7,
                display_severity="MEDIUM",
                version_match_type="range",
            )
        ]
        display_both_block("pkg", "1.0.0", cooldown, threats, console=con)
        output = con.export_text()
        assert "No URL threat" in output

    def test_allowed_with_very_long_version(self) -> None:
        """Very long version strings render correctly."""
        con = _console_capture()
        display_allowed("pkg", "1.2.3-alpha.1+build.20260401.abcdef", console=con, force_display=True)
        output = con.export_text()
        assert "1.2.3-alpha.1+build.20260401.abcdef" in output

    def test_humanize_timedelta_exactly_one_unit(self) -> None:
        """Singular units (1 day, 1 hour, 1 minute) have no trailing 's'."""
        assert humanize_timedelta(timedelta(days=1)) == "1 day"
        assert humanize_timedelta(timedelta(hours=1)) == "1 hour"
        assert humanize_timedelta(timedelta(minutes=1)) == "1 minute"
        assert humanize_timedelta(timedelta(seconds=1)) == "1 second"

    def test_humanize_timedelta_large_values(self) -> None:
        """Large timedelta values are formatted correctly."""
        assert humanize_timedelta(timedelta(days=365)) == "365 days"

    def test_stale_db_warning_with_recent_sync(self) -> None:
        """Stale DB warning with a sync from 1 hour ago shows '1 hour ago'."""
        con = _console_capture()
        last_sync = datetime.now(tz=UTC) - timedelta(hours=1)
        display_stale_db_warning(last_sync, console=con)
        output = con.export_text()
        assert "stale" in output.lower()
        assert "hour" in output.lower()


# ===================================================================
# 12. _write_toml_fallback Edge Cases
# ===================================================================


class TestGenerateConfigTemplateContent:
    """Tests for template content correctness."""

    def test_root_fields_match_defaults(self) -> None:
        """Root-level field values match PKGDConfig defaults."""
        from tomlkit import dumps

        content = dumps(_generate_config_template())
        parsed = tomllib.loads(content)
        from pkg_defender.config.settings import PKGDConfig

        defaults = PKGDConfig()
        assert parsed["command_timeout_seconds"] == defaults.command_timeout_seconds
        assert parsed["fail_on_threat_enabled"] == defaults.fail_on_threat_enabled
        assert parsed["fail_on_warn_enabled"] == defaults.fail_on_warn_enabled

    def test_cooldown_fields_match_defaults(self) -> None:
        """Cooldown section field values match PKGDConfig defaults."""
        from tomlkit import dumps

        content = dumps(_generate_config_template())
        parsed = tomllib.loads(content)
        from pkg_defender.config.settings import PKGDConfig

        defaults = PKGDConfig()
        cooldown = parsed["cooldown"]
        assert cooldown["default_days"] == defaults.cooldown.default_days
        assert cooldown["enabled"] == defaults.cooldown.enabled
        assert cooldown["strict_mode"] == defaults.cooldown.strict_mode
        assert cooldown["bypass_require_reason"] == defaults.cooldown.bypass_require_reason
        assert cooldown["bypass_log_retention_days"] == defaults.cooldown.bypass_log_retention_days

    def test_database_path_omitted(self) -> None:
        """database.path=None is NOT in the TOML output."""
        from tomlkit import dumps

        content = dumps(_generate_config_template())
        parsed = tomllib.loads(content)
        assert "path" not in parsed.get("database", {})

    def test_template_creates_parent_directories(self, tmp_path: Path) -> None:
        """Writing template to nested path creates parent directories."""
        from tomlkit import dumps

        path = tmp_path / "subdir" / "nested" / "test.toml"
        _write_config_toml(path, dumps(_generate_config_template()))
        assert path.exists()

    def test_special_keys_roundtrip_via_tomlkit(self, tmp_path: Path) -> None:
        """Keys with special characters are handled by tomlkit."""
        from tomlkit import dumps
        from tomlkit import table as tomlkit_table

        doc = _generate_config_template()
        # Add overrides with package names containing special chars
        cooldown = doc.get("cooldown")
        if cooldown:
            overrides = tomlkit_table()
            overrides["@babel/core"] = 14
            overrides["react"] = 7
            overrides["lodash"] = 3
            overrides["some-package"] = 5
            cooldown["overrides"] = overrides
        content = dumps(doc)
        _write_config_toml(tmp_path / "test.toml", content)

        with open(tmp_path / "test.toml", "rb") as f:
            result = tomllib.load(f)
        assert result["cooldown"]["overrides"]["@babel/core"] == 14
        assert result["cooldown"]["overrides"]["react"] == 7


# ===================================================================
# 13. Checker Edge Cases
# ===================================================================


class TestCheckerEdgeCases:
    """Additional edge case tests for the pre-install checker."""

    def test_empty_affected_versions_and_ranges(self) -> None:
        """Both lists empty → no match (None)."""
        result = _version_matches("1.0.0", [], [])
        assert result is None

    def test_exact_match_case_sensitive(self) -> None:
        """Exact match is case-sensitive."""
        result = _version_matches("1.0.0", ["1.0.0"], [])
        assert result == "exact"

    def test_version_with_many_dots(self) -> None:
        """Versions with many components compare correctly."""
        assert _parse_version("2024.01.15.1") == (2024, 1, 15, 1)

    def test_compare_same_version_different_prerelease(self) -> None:
        """Alpha pre-release is less than beta per PEP 440."""
        from pkg_defender.version import _compare_versions

        assert _compare_versions("1.0.0-alpha", "1.0.0-beta") == -1

    def test_compare_different_lengths(self) -> None:
        """Versions of different lengths compare correctly."""
        from pkg_defender.version import _compare_versions

        assert _compare_versions("1.0", "1.0.1") == -1
        assert _compare_versions("1.0.1", "1.0") == 1
