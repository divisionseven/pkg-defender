"""Tests for the threat scorer module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pkg_defender.core.scorer import (
    CORROBORATION_MULTIPLIER,
    RECENCY_DECAY_PER_WEEK,
    RECENCY_FLOOR,
    SOURCE_CONFIDENCE,
    get_display_severity,
    get_source_confidence,
    score_threat,
    score_threats,
)
from pkg_defender.models import ThreatRecord

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 4, 1, tzinfo=UTC)


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
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> ThreatRecord:
    """Build a ThreatRecord with sane defaults."""
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
        first_seen=first_seen or NOW - timedelta(days=30),
        last_seen=last_seen or NOW - timedelta(days=1),
    )


# ---------------------------------------------------------------------------
# get_source_confidence
# ---------------------------------------------------------------------------


class TestGetSourceConfidence:
    """Tests for get_source_confidence."""

    def test_known_sources(self) -> None:
        """Every defined source returns its weight."""
        for source, expected in SOURCE_CONFIDENCE.items():
            assert get_source_confidence(source) == pytest.approx(expected)

    def test_social_sources_are_lower(self) -> None:
        """Social sources score below structured feeds."""
        assert get_source_confidence("mastodon") < get_source_confidence("osv")
        assert get_source_confidence("reddit") < get_source_confidence("osv")
        assert get_source_confidence("x_twitter") < get_source_confidence("osv")

    def test_unknown_source_defaults_to_half(self) -> None:
        assert get_source_confidence("unknown_feed") == pytest.approx(0.5)

    def test_empty_string_defaults(self) -> None:
        assert get_source_confidence("") == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# get_display_severity
# ---------------------------------------------------------------------------


class TestGetDisplaySeverity:
    """Tests for get_display_severity thresholds."""

    def test_critical_threshold(self) -> None:
        assert get_display_severity(0.9) == "CRITICAL"
        assert get_display_severity(1.0) == "CRITICAL"
        assert get_display_severity(0.95) == "CRITICAL"

    def test_high_threshold(self) -> None:
        assert get_display_severity(0.7) == "HIGH"
        assert get_display_severity(0.89) == "HIGH"
        assert get_display_severity(0.85) == "HIGH"

    def test_medium_threshold(self) -> None:
        assert get_display_severity(0.4) == "MEDIUM"
        assert get_display_severity(0.69) == "MEDIUM"
        assert get_display_severity(0.5) == "MEDIUM"

    def test_low_threshold(self) -> None:
        assert get_display_severity(0.01) == "LOW"
        assert get_display_severity(0.39) == "LOW"

    def test_zero_is_unknown(self) -> None:
        assert get_display_severity(0.0) == "UNKNOWN"

    def test_negative_is_unknown(self) -> None:
        assert get_display_severity(-0.1) == "UNKNOWN"

    def test_boundary_values(self) -> None:
        """Exact boundary points."""
        assert get_display_severity(0.8999) == "HIGH"
        assert get_display_severity(0.4001) == "MEDIUM"
        assert get_display_severity(0.001) == "LOW"


# ---------------------------------------------------------------------------
# score_threat — severity base scoring
# ---------------------------------------------------------------------------


class TestScoreThreatSeverity:
    """Tests for severity-based base scoring."""

    @pytest.mark.parametrize(
        "severity, expected_severity_score",
        [
            ("CRITICAL", 1.0),
            ("HIGH", 0.8),
            ("MEDIUM", 0.5),
            ("LOW", 0.3),
            ("UNKNOWN", 0.1),
        ],
    )
    def test_severity_base_scores(self, severity: str, expected_severity_score: float) -> None:
        """Each severity maps to the correct base score."""
        threat = _make_threat(severity=severity, source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        # base = severity * source_confidence(0.9), no decay for recent
        expected = expected_severity_score * 0.9
        assert scored.final_score == pytest.approx(expected, abs=1e-6)

    def test_critical_full_confidence_osv(self) -> None:
        """CRITICAL (1.0) * osv (0.9) = 0.9."""
        threat = _make_threat(severity="CRITICAL", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.final_score == pytest.approx(0.9, abs=1e-6)

    def test_unknown_severity_scores_low(self) -> None:
        """UNKNOWN (0.1) * any source produces low score."""
        threat = _make_threat(severity="UNKNOWN", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.final_score < 0.1


# ---------------------------------------------------------------------------
# score_threat — source confidence weighting
# ---------------------------------------------------------------------------


class TestScoreThreatSourceConfidence:
    """Tests for source confidence weighting in scoring."""

    def test_osv_vs_social(self) -> None:
        """OSV should score higher than social feeds for same severity."""
        threat_osv = _make_threat(severity="HIGH", source="osv")
        threat_mastodon = _make_threat(severity="HIGH", source="mastodon")

        scored_osv = score_threat(threat_osv, "exact", now=NOW)
        scored_mastodon = score_threat(threat_mastodon, "exact", now=NOW)

        assert scored_osv.final_score > scored_mastodon.final_score

    def test_socket_highest_confidence(self) -> None:
        """Socket (0.95) should score above all others for same severity."""
        threat_socket = _make_threat(severity="HIGH", source="socket")
        threat_osv = _make_threat(severity="HIGH", source="osv")
        threat_ghsa = _make_threat(severity="HIGH", source="ghsa")

        scored_socket = score_threat(threat_socket, "exact", now=NOW)
        scored_osv = score_threat(threat_osv, "exact", now=NOW)
        scored_ghsa = score_threat(threat_ghsa, "exact", now=NOW)

        assert scored_socket.final_score > scored_osv.final_score
        assert scored_socket.final_score > scored_ghsa.final_score

    def test_formula(self) -> None:
        """Verify exact formula: base = severity * source_conf * corrob * decay."""
        threat = _make_threat(severity="HIGH", source="osv")
        scored = score_threat(threat, "exact", corroboration_count=1, now=NOW)

        expected_base = 0.8 * 0.9  # HIGH * osv
        # no decay since threat is only ~30 days old
        weeks_old = 30 / 7.0
        decay = max(RECENCY_FLOOR, 1.0 - weeks_old * RECENCY_DECAY_PER_WEEK)
        expected = round(min(expected_base * 1.0 * decay, 1.0), 10)

        assert scored.final_score == pytest.approx(expected, abs=1e-6)


# ---------------------------------------------------------------------------
# score_threat — corroboration multiplier
# ---------------------------------------------------------------------------


class TestScoreThreatCorroboration:
    """Tests for multi-source corroboration multiplier."""

    def test_single_source_no_boost(self) -> None:
        """1 source -> multiplier 1.0 (no boost)."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", corroboration_count=1, now=NOW)
        base = 0.8 * 0.9  # severity * source
        assert scored.final_score == pytest.approx(base, abs=1e-6)

    def test_two_sources_boost(self) -> None:
        """2 sources -> multiplier 1.15 (15% boost)."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored_single = score_threat(threat, "exact", corroboration_count=1, now=NOW)
        scored_double = score_threat(threat, "exact", corroboration_count=2, now=NOW)
        assert scored_double.final_score == pytest.approx(scored_single.final_score * 1.15, abs=1e-6)

    def test_three_sources_boost(self) -> None:
        """3 sources -> multiplier 1.25 (25% boost)."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", corroboration_count=3, now=NOW)
        base = 0.8 * 0.9 * 1.25
        assert scored.final_score == pytest.approx(base, abs=1e-6)

    def test_four_sources_cap(self) -> None:
        """4 sources -> multiplier 1.3 (capped)."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", corroboration_count=4, now=NOW)
        base = 0.8 * 0.9 * 1.3
        assert scored.final_score == pytest.approx(base, abs=1e-6)

    def test_returns_same_score_when_corroboration_count_exceeds_maximum(self) -> None:
        """5+ sources still capped at 1.3 (corroboration_count=4 key)."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored_4 = score_threat(threat, "exact", corroboration_count=4, now=NOW)
        scored_5 = score_threat(threat, "exact", corroboration_count=5, now=NOW)
        assert scored_5.final_score == pytest.approx(scored_4.final_score, abs=1e-6)

    def test_all_corroboration_multipliers(self) -> None:
        """Verify all defined multipliers match the dict."""
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        for count, mult in CORROBORATION_MULTIPLIER.items():
            scored = score_threat(threat, "exact", corroboration_count=count, now=NOW)
            base = 0.8 * 0.9 * mult
            assert scored.final_score == pytest.approx(base, abs=1e-6)


# ---------------------------------------------------------------------------
# score_threat — recency decay
# ---------------------------------------------------------------------------


class TestScoreThreatRecency:
    """Tests for recency decay."""

    def test_brand_new_threat_no_decay(self) -> None:
        """Threat seen today: weeks_old ~ 0, decay ~ 1.0."""
        threat = _make_threat(first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9  # HIGH * osv
        assert scored.final_score == pytest.approx(base, abs=1e-4)

    def test_one_week_old(self) -> None:
        """1 week old: 5% decay."""
        threat = _make_threat(first_seen=NOW - timedelta(weeks=1))
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9
        expected = base * (1.0 - 1 * 0.05)
        assert scored.final_score == pytest.approx(expected, abs=1e-4)

    def test_four_weeks_old(self) -> None:
        """4 weeks old: 20% decay."""
        threat = _make_threat(first_seen=NOW - timedelta(weeks=4))
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9
        expected = base * (1.0 - 4 * 0.05)
        assert scored.final_score == pytest.approx(expected, abs=1e-4)

    def test_recency_floor(self) -> None:
        """Very old threat: never goes below 50% of original."""
        threat = _make_threat(first_seen=NOW - timedelta(weeks=100))
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9
        expected = base * RECENCY_FLOOR
        assert scored.final_score == pytest.approx(expected, abs=1e-4)

    def test_floor_applied_at_exact_boundary(self) -> None:
        """Exactly at the floor boundary: 1 - 10 * 0.05 = 0.5."""
        threat = _make_threat(first_seen=NOW - timedelta(weeks=10))
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9
        # 1 - 10 * 0.05 = 0.5, which equals RECENCY_FLOOR
        expected = base * RECENCY_FLOOR
        assert scored.final_score == pytest.approx(expected, abs=1e-4)

    def test_past_floor_stays_at_floor(self) -> None:
        """20 weeks: 1 - 20 * 0.05 = 0.0, clamped to RECENCY_FLOOR."""
        threat = _make_threat(first_seen=NOW - timedelta(weeks=20))
        scored = score_threat(threat, "exact", now=NOW)
        base = 0.8 * 0.9
        expected = base * RECENCY_FLOOR
        assert scored.final_score == pytest.approx(expected, abs=1e-4)

    def test_naive_datetime_handled(self) -> None:
        """first_seen without timezone is treated as UTC."""
        naive = datetime(2026, 3, 1)
        threat = _make_threat(first_seen=naive)
        # Should not raise — naive datetime is converted internally
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.final_score > 0


# ---------------------------------------------------------------------------
# score_threat — score cap at 1.0
# ---------------------------------------------------------------------------


class TestScoreThreatCap:
    """Tests for score capping at 1.0."""

    def test_score_capped_at_one(self) -> None:
        """Even with corroboration, score never exceeds 1.0."""
        threat = _make_threat(severity="CRITICAL", source="socket", first_seen=NOW)
        # socket (0.95) * CRITICAL (1.0) * 4-source corrob (1.3) = 1.235 -> capped 1.0
        scored = score_threat(threat, "exact", corroboration_count=4, now=NOW)
        assert scored.final_score == pytest.approx(1.0)

    def test_score_exactly_one(self) -> None:
        """A score that works out to exactly 1.0 stays at 1.0."""
        # osv (0.9) * CRITICAL (1.0) * no decay, no corrob = 0.9 < 1.0
        # But osv (0.9) * CRITICAL (1.0) * corrob 4 (1.3) = 1.17 -> 1.0
        threat = _make_threat(severity="CRITICAL", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", corroboration_count=4, now=NOW)
        assert scored.final_score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# score_threat — version_match_type passthrough
# ---------------------------------------------------------------------------


class TestScoreThreatVersionMatch:
    """Tests for version_match_type passthrough."""

    def test_exact(self) -> None:
        threat = _make_threat()
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.version_match_type == "exact"

    def test_range(self) -> None:
        threat = _make_threat()
        scored = score_threat(threat, "range", now=NOW)
        assert scored.version_match_type == "range"

    def test_package_wide(self) -> None:
        threat = _make_threat()
        scored = score_threat(threat, "package_wide", now=NOW)
        assert scored.version_match_type == "package_wide"


# ---------------------------------------------------------------------------
# score_threat — display_severity derived from score
# ---------------------------------------------------------------------------


class TestScoreThreatDisplaySeverity:
    """Tests that display_severity is derived from final_score."""

    def test_critical_score_gets_critical_display(self) -> None:
        # CRITICAL * socket * 4-source -> 1.0 (capped)
        threat = _make_threat(severity="CRITICAL", source="socket", first_seen=NOW)
        scored = score_threat(threat, "exact", corroboration_count=4, now=NOW)
        assert scored.display_severity == "CRITICAL"

    def test_high_score_gets_high_display(self) -> None:
        # HIGH (0.8) * osv (0.9) = 0.72 -> HIGH
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.display_severity == "HIGH"

    def test_medium_score_gets_medium_display(self) -> None:
        # MEDIUM (0.5) * osv (0.9) = 0.45 -> MEDIUM
        threat = _make_threat(severity="MEDIUM", source="osv", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.display_severity == "MEDIUM"

    def test_low_score_gets_low_display(self) -> None:
        # LOW (0.3) * rss (0.5) = 0.15 -> LOW
        threat = _make_threat(severity="LOW", source="rss", first_seen=NOW)
        scored = score_threat(threat, "exact", now=NOW)
        assert scored.display_severity == "LOW"


# ---------------------------------------------------------------------------
# score_threats — batch scoring with corroboration
# ---------------------------------------------------------------------------


class TestScoreThreats:
    """Tests for score_threats (batch scoring)."""

    def test_empty_list(self) -> None:
        assert score_threats([], "exact", now=NOW) == []

    def test_single_threat(self) -> None:
        threat = _make_threat(severity="HIGH", source="osv", first_seen=NOW)
        results = score_threats([threat], "exact", now=NOW)
        assert len(results) == 1
        assert results[0].final_score == pytest.approx(0.72, abs=1e-6)

    def test_same_package_different_sources_corroboration(self) -> None:
        """Two sources confirming the same (ecosystem, package) threat."""
        t1 = _make_threat(id="osv:1", source="osv", severity="HIGH", first_seen=NOW)
        t2 = _make_threat(id="ghsa:1", source="ghsa", severity="HIGH", first_seen=NOW)
        results = score_threats([t1, t2], "exact", now=NOW)

        # Each should get corroboration_count=2
        for r in results:
            base = 0.8 * SOURCE_CONFIDENCE[r.record.source]
            expected = base * 1.15  # 2-source multiplier
            assert r.final_score == pytest.approx(expected, abs=1e-4)

    def test_different_packages_no_corroboration(self) -> None:
        """Different packages don't corroborate each other."""
        t1 = _make_threat(id="osv:1", package_name="lodash", source="osv", first_seen=NOW)
        t2 = _make_threat(id="osv:2", package_name="axios", source="osv", first_seen=NOW)
        results = score_threats([t1, t2], "exact", now=NOW)

        # Each is alone in its group, so corroboration = 1
        for r in results:
            base = 0.8 * 0.9  # HIGH * osv
            assert r.final_score == pytest.approx(base, abs=1e-4)

    def test_three_sources_three_way_corroboration(self) -> None:
        """Three sources for same package -> corroboration_count=3."""
        t1 = _make_threat(id="osv:1", source="osv", first_seen=NOW)
        t2 = _make_threat(id="ghsa:1", source="ghsa", first_seen=NOW)
        t3 = _make_threat(id="rss:1", source="rss", first_seen=NOW)
        results = score_threats([t1, t2, t3], "exact", now=NOW)

        for r in results:
            base = 0.8 * SOURCE_CONFIDENCE[r.record.source]
            expected = base * 1.25  # 3-source multiplier
            assert r.final_score == pytest.approx(expected, abs=1e-4)

    def test_sorted_by_score_descending(self) -> None:
        """Results are sorted by final_score descending."""
        t_low = _make_threat(id="1", severity="LOW", source="mastodon", first_seen=NOW)
        t_high = _make_threat(id="2", severity="CRITICAL", source="socket", first_seen=NOW)
        t_med = _make_threat(id="3", severity="MEDIUM", source="osv", first_seen=NOW)
        results = score_threats([t_low, t_high, t_med], "exact", now=NOW)

        scores = [r.final_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_version_match_type_propagated(self) -> None:
        """All results carry the version_match_type passed to score_threats."""
        t1 = _make_threat(id="1", source="osv", first_seen=NOW)
        t2 = _make_threat(id="2", source="ghsa", first_seen=NOW)
        results = score_threats([t1, t2], "range", now=NOW)
        for r in results:
            assert r.version_match_type == "range"

    def test_mixed_ecosystem_corroboration(self) -> None:
        """Same package, different ecosystems -> no cross-corroboration."""
        t1 = _make_threat(id="1", ecosystem="npm", source="osv", first_seen=NOW)
        t2 = _make_threat(id="2", ecosystem="pypi", source="osv", first_seen=NOW)
        results = score_threats([t1, t2], "exact", now=NOW)
        # Different ecosystem+package keys, so corroboration = 1 each
        for r in results:
            assert r.final_score == pytest.approx(0.72, abs=1e-4)

    def test_four_plus_sources_capped(self) -> None:
        """Four sources for same package -> corroboration_count=4 (cap)."""
        t1 = _make_threat(id="1", source="osv", first_seen=NOW)
        t2 = _make_threat(id="2", source="ghsa", first_seen=NOW)
        t3 = _make_threat(id="3", source="socket", first_seen=NOW)
        t4 = _make_threat(id="4", source="rss", first_seen=NOW)
        results = score_threats([t1, t2, t3, t4], "exact", now=NOW)
        # Each gets corroboration_count=4, capped
        for r in results:
            base = 0.8 * SOURCE_CONFIDENCE[r.record.source]
            expected = base * 1.3
            assert r.final_score == pytest.approx(expected, abs=1e-4)


# ---------------------------------------------------------------------------
# Integration: checker uses scorer
# ---------------------------------------------------------------------------


class TestCheckerUsesScorer:
    """Verify that checker.py imports and uses score_threat from scorer."""

    def test_checker_imports_scorer(self) -> None:
        """check_package should use the scorer module, not inline logic."""

        # Verify that score_threats is imported from scorer, not defined locally
        import pkg_defender.core.checker as checker_mod

        assert hasattr(checker_mod, "score_threats")
        assert not hasattr(checker_mod, "_score_threat")
        assert not hasattr(checker_mod, "SEVERITY_SCORES")

    def test_checker_score_matches_scorer(self) -> None:
        """check_package scores should match direct scorer calls."""

        from pkg_defender.core.checker import check_package
        from pkg_defender.db.schema import init_db, insert_threat

        db_path = Path("/tmp/test_scorer_integration.db")
        if db_path.exists():
            db_path.unlink()
        conn = init_db(db_path)

        # Use current time truncated to seconds so both check_package (which
        # calls datetime.now() internally) and our direct scorer call agree.
        now = datetime.now(UTC).replace(microsecond=0)
        threat = _make_threat(
            id="osv:INTEG-1",
            affected_versions=["2.0.0"],
            severity="CRITICAL",
            source="osv",
            first_seen=now - timedelta(days=7),
        )
        insert_threat(conn, threat)

        result = check_package(conn, "npm", "lodash", "2.0.0")
        assert result.blocked is True
        assert len(result.threats) == 1

        # Direct scorer call should produce the same score
        direct_scored = score_threat(threat, "exact", now=now)
        assert result.threats[0].final_score == pytest.approx(direct_scored.final_score, abs=0.01)

        conn.close()
        db_path.unlink()
