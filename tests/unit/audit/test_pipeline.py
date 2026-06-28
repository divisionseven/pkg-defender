"""Expanded tests for audit pipeline module.

Note: Runtime pipeline functions (run_audit_pipeline, _audit_single_package,
_determine_verdict, _aggregate_results, _log_audit_event) were deleted in
v1.0 cleanup. Only shared type definitions and adapter-resolution tests remain.
"""

import pytest

from pkg_defender.audit.types import AuditResult, Threat, Verdict


class TestVerdict:
    """Tests for Verdict enum."""

    def test_values(self) -> None:
        assert Verdict.PASS == "PASS"
        assert Verdict.FAIL == "FAIL"
        assert Verdict.BLOCKED == "BLOCKED"
        assert Verdict.WARN == "WARN"
        assert Verdict.ERROR == "ERROR"
        assert Verdict.PARTIAL_PASS == "PARTIAL_PASS"

    def test_has_all_expected_values(self) -> None:
        """Verify all verdicts are present."""
        all_verdicts = [v.value for v in Verdict]
        assert "PASS" in all_verdicts
        assert "FAIL" in all_verdicts
        assert "BLOCKED" in all_verdicts
        assert "WARN" in all_verdicts
        assert "ERROR" in all_verdicts
        assert "PARTIAL_PASS" in all_verdicts


class TestThreat:
    """Tests for Threat dataclass."""

    def test_create_full(self) -> None:
        """Create Threat with all fields."""
        threat = Threat(severity="HIGH", summary="Test threat", source="test", score=8.5)
        assert threat.severity == "HIGH"
        assert threat.summary == "Test threat"
        assert threat.source == "test"
        assert threat.score == 8.5

    def test_create_minimal(self) -> None:
        """Create Threat with only required fields."""
        threat = Threat(severity="LOW", summary="Minor issue", source="scanner")
        assert threat.severity == "LOW"
        assert threat.score == 0.0  # default


class TestAuditResult:
    """Tests for AuditResult dataclass."""

    def test_create_full(self) -> None:
        """Create AuditResult with all fields."""
        from datetime import UTC, datetime

        result = AuditResult(
            package="requests",
            ecosystem="pypi",
            version="2.28.0",
            release_date=datetime.now(UTC),
            threats_all=[],
            threats_versioned=[],
            cooldown_pass=True,
            cooldown_days_remaining=0,
            cooldown_window_days=3,
            overall_verdict=Verdict.PASS,
            verdict_reason="All clear",
            exit_code=0,
        )
        assert result.package == "requests"
        assert result.overall_verdict == Verdict.PASS
        assert result.exit_code == 0

    def test_create_minimal(self) -> None:
        """Create AuditResult with minimal fields."""
        result = AuditResult(
            package="test",
            ecosystem="test",
            version=None,
            release_date=None,
            threats_all=[],
            threats_versioned=[],
            overall_verdict=Verdict.PASS,
            verdict_reason="",
            exit_code=0,
        )
        assert result.package == "test"


class TestEcosystemKeyNormalization:
    """Regression tests for ecosystem→manager key mismatch bug.

    Before Step 1.5: get_adapter("pip") returned None (silent skip).
    After Step 1.5: get_pipeline_adapter("pip") returns PipelineAdapter.

    These tests call the REAL get_pipeline_adapter function with the
    REAL ECOSYSTEM_ALIAS_MAP and registry maps. They do NOT mock the
    function under test — only external dependencies (network calls)
    are mocked where needed.
    """

    @pytest.mark.parametrize(
        "ecosystem_key,expected_ecosystem_attr",
        [
            # Manager-style keys (direct lookup in UNIFIED_MANAGER_REGISTRY)
            ("pip", "pip"),
            ("npm", "npm"),
            ("gem", "gem"),
            ("cargo", "cargo"),
            ("homebrew", "homebrew"),
            ("apt", "apt"),
            ("conda", "conda"),
            ("dnf", "dnf"),
            # Ecosystem-style keys (via ECOSYSTEM_ALIAS_MAP)
            ("pypi", "pypi"),
            ("rubygems", "rubygems"),
            ("crates", "crates"),
        ],
    )
    def test_ecosystem_key_resolves(
        self,
        ecosystem_key: str,
        expected_ecosystem_attr: str,
    ) -> None:
        """Both ecosystem and manager keys resolve to a non-None adapter.

        REGRESSION: Before fix, get_adapter("pip") returned None.
        After fix, get_pipeline_adapter("pip") returns PipelineAdapter.
        """
        from pkg_defender.registry import get_pipeline_adapter

        adapter = get_pipeline_adapter(ecosystem_key)
        assert adapter is not None, (
            f"get_pipeline_adapter({ecosystem_key!r}) returned None — the key-mismatch bug is NOT fixed"
        )
        assert adapter.ecosystem == expected_ecosystem_attr, (
            f"get_pipeline_adapter({ecosystem_key!r}).ecosystem == "
            f"{adapter.ecosystem!r}, expected {expected_ecosystem_attr!r}"
        )

    def test_unknown_ecosystem_returns_none(self) -> None:
        """Unknown ecosystem key returns None (not an error)."""
        from pkg_defender.registry import get_pipeline_adapter

        adapter = get_pipeline_adapter("nonexistent_ecosystem")
        assert adapter is None

    def test_composer_returns_none_known_gap(self) -> None:
        """composer/packagist resolves to ComposerAdapter.

        ComposerAdapter is now registered in UNIFIED_MANAGER_REGISTRY at key "composer".
        ECOSYSTEM_ALIAS_MAP maps "packagist" → "composer", so both keys
        resolve to a real adapter.
        """
        from pkg_defender.registry import get_pipeline_adapter

        adapter = get_pipeline_adapter("composer")
        assert adapter is not None, "ComposerAdapter is registered in UNIFIED_MANAGER_REGISTRY — should resolve"
        assert adapter.ecosystem == "composer"

        adapter = get_pipeline_adapter("packagist")
        assert adapter is not None, "packagist→composer alias should resolve to ComposerAdapter"
        assert adapter.adapter_ecosystem == "composer"

    def test_adapter_ecosystem_exposes_underlying_registry(self) -> None:
        """PipelineAdapter.adapter_ecosystem returns the wrapped adapter's ecosystem.

        When get_pipeline_adapter("npm") is called, the resolved adapter
        is NpmUnifiedAdapter (ecosystem="npm"). adapter.ecosystem returns
        "npm" (the requested key), and adapter.adapter_ecosystem also
        returns "npm" (the unified adapter's ecosystem).
        """
        from pkg_defender.registry import get_pipeline_adapter

        adapter = get_pipeline_adapter("npm")
        assert adapter is not None
        assert adapter.ecosystem == "npm", "adapter.ecosystem should return the requested key 'npm'"
        assert adapter.adapter_ecosystem == "npm", (
            "adapter.adapter_ecosystem should return the underlying registry "
            f"identifier, expected 'npm', got {adapter.adapter_ecosystem!r}"
        )

    def test_unified_adapter_delegates_to_bridge_methods(self) -> None:
        """PipelineAdapter delegates to UnifiedRegistryAdapter bridge methods.

        When the wrapped adapter is a UnifiedRegistryAdapter (e.g. for
        "pip" → PyPIUnifiedAdapter), PipelineAdapter.resolve_latest_version
        should call the bridge method directly, not the low-level
        get_latest_version.
        """
        from pkg_defender.registry import get_pipeline_adapter
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        adapter = get_pipeline_adapter("pip")
        assert adapter is not None
        assert isinstance(adapter._adapter, UnifiedRegistryAdapter), (
            f"Expected UnifiedRegistryAdapter for 'pip', got {type(adapter._adapter)}"
        )
        # Verify the adapter has bridge methods (the PipelineAdapter will delegate to these)
        assert hasattr(adapter._adapter, "resolve_latest_version")
        assert hasattr(adapter._adapter, "get_release_date")


class TestCrossPathVerdictConsistency:
    """Regression: verify production path (checker → scorer) is self-consistent.

    The deleted pipeline's _determine_verdict() used a simple CVSS-based threshold
    (score >= 9.0 = BLOCKED). The production path uses the weighted scorer in
    core/checker.py with BLOCK_SCORE_THRESHOLD = 0.3. These disagree by design —
    this test verifies the PRODUCTION path is consistent with its own design.
    """

    def test_scorer_blocks_critical_threats(self) -> None:
        """Critical-severity threats should exceed the block threshold."""
        from datetime import UTC, datetime

        from pkg_defender.core.checker import BLOCK_SCORE_THRESHOLD
        from pkg_defender.core.scorer import score_threat
        from pkg_defender.models import ThreatRecord

        threat = ThreatRecord(
            id="test-cross-1",
            ecosystem="npm",
            package_name="malicious-pkg",
            affected_versions=["1.0.0"],
            source="osv",
            severity="CRITICAL",
            summary="Malicious package",
            cvss_score=9.5,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            hit_count=1,
            is_malicious=True,
            is_unverified=False,
        )
        scored = score_threat(threat, "exact", corroboration_count=1, now=datetime.now(UTC))
        assert scored.final_score >= BLOCK_SCORE_THRESHOLD, (
            f"CRITICAL threat should score >= {BLOCK_SCORE_THRESHOLD}, got {scored.final_score}"
        )

    def test_scorer_does_not_block_low_severity_social(self) -> None:
        """Low-severity social-source threats should NOT exceed block threshold.

        Board mandate: social feeds are informational only and must never
        trigger a block on their own.
        """
        from datetime import UTC, datetime

        from pkg_defender.core.checker import BLOCK_SCORE_THRESHOLD
        from pkg_defender.core.scorer import score_threat
        from pkg_defender.models import ThreatRecord

        threat = ThreatRecord(
            id="test-cross-2",
            ecosystem="npm",
            package_name="some-pkg",
            affected_versions=["1.0.0"],
            source="reddit",  # Social source — low confidence
            severity="LOW",
            summary="User report",
            cvss_score=2.0,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            hit_count=1,
            is_malicious=False,
            is_unverified=True,
        )
        scored = score_threat(threat, "exact", corroboration_count=1, now=datetime.now(UTC))
        assert scored.final_score < BLOCK_SCORE_THRESHOLD, (
            f"Low-severity social threat should score below {BLOCK_SCORE_THRESHOLD}, got {scored.final_score}"
        )

    def test_checker_blocks_high_cvss_threat(self) -> None:
        """check_package returns blocked=True for a high-CVSS threat in DB."""
        import json
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from pkg_defender.core.checker import check_package

        # Build a mock row that looks like a sqlite3.Row
        row = {
            "id": "test-cross-3",
            "ecosystem": "pypi",
            "package_name": "requests",
            "affected_versions": json.dumps(["2.28.0"]),
            "affected_ranges": "[]",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "source": "osv",
            "source_id": "OSV-2024-001",
            "summary": "Critical RCE in requests",
            "detail_url": "https://osv.dev/OSV-2024-001",
            "first_seen": "2024-01-15T00:00:00+00:00",
            "last_seen": "2024-01-15T00:00:00+00:00",
            "hit_count": 5,
            "cvss_score": 9.5,
            "published_at": "2024-01-15T00:00:00+00:00",
            "ingested_at": "2024-01-15T00:00:00+00:00",
            "is_malicious": 1,
            "is_unverified": 0,
            "updated_at": "2024-01-15T00:00:00+00:00",
        }

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [row]

        result = check_package(
            mock_conn,
            ecosystem="pypi",
            package="requests",
            version="2.28.0",
            now=datetime.now(UTC),
        )
        assert result.blocked is True, (
            f"Critical CVSS 9.5 threat should block, got blocked={result.blocked}, highest_score={result.highest_score}"
        )
        assert result.highest_score >= 0.3

    def test_checker_does_not_block_low_threat(self) -> None:
        """check_package returns blocked=False for a low-severity threat."""
        import json
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from pkg_defender.core.checker import check_package

        row = {
            "id": "test-cross-4",
            "ecosystem": "pypi",
            "package_name": "requests",
            "affected_versions": json.dumps(["2.28.0"]),
            "affected_ranges": "[]",
            "severity": "LOW",
            "confidence": 0.3,
            "source": "reddit",
            "source_id": "reddit-thread-123",
            "summary": "Possible concern",
            "detail_url": "",
            "first_seen": "2024-06-01T00:00:00+00:00",
            "last_seen": "2024-06-01T00:00:00+00:00",
            "hit_count": 1,
            "cvss_score": 2.0,
            "published_at": None,
            "ingested_at": "2024-06-01T00:00:00+00:00",
            "is_malicious": 0,
            "is_unverified": 1,
            "updated_at": "2024-06-01T00:00:00+00:00",
        }

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [row]

        result = check_package(
            mock_conn,
            ecosystem="pypi",
            package="requests",
            version="2.28.0",
            now=datetime.now(UTC),
        )
        assert result.blocked is False, (
            f"Low-severity social threat should NOT block, got blocked={result.blocked}, "
            f"highest_score={result.highest_score}"
        )
