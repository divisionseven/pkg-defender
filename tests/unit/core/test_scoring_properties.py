"""Property-based tests for threat scoring invariants.

Uses hypothesis for randomized/fuzzing-style testing of numeric
invariants in the scoring model.
"""

from datetime import UTC, datetime
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from pkg_defender.core.scorer import get_display_severity, score_threat
from pkg_defender.models.models import ThreatRecord

settings.register_profile("ci", max_examples=100)
settings.load_profile("ci")

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SOCIAL_SOURCES = {"mastodon", "reddit", "x_twitter"}

_SOURCE_STRATEGY = st.sampled_from(
    [
        "osv",
        "ghsa",
        "socket",
        "npm_advisory",
        "ossf_malicious",
        "homebrew_osv",
        "rss",
        "mastodon",
        "reddit",
        "x_twitter",
    ]
)

_SEVERITY_STRATEGY = st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])

_ECOSYSTEM_STRATEGY = st.sampled_from(["npm", "pypi", "cargo", "gem", "go"])
# Shared base for ThreatRecord builds — provides only the fields that
# score_threat actually reads (severity, source, first_seen) plus the
# required positional fields (id, ecosystem).
_THREAT_BUILD_KWARGS: dict[str, Any] = {
    "id": st.text(min_size=1, max_size=64),
    "ecosystem": _ECOSYSTEM_STRATEGY,
    "severity": _SEVERITY_STRATEGY,
    "source": _SOURCE_STRATEGY,
    "first_seen": st.datetimes(),
}


# ---------------------------------------------------------------------------
# get_display_severity  — property-based tests
# ---------------------------------------------------------------------------
class TestGetDisplaySeverityProperties:
    """Property-based tests for get_display_severity invariants."""

    @given(st.floats(min_value=0.0, max_value=1.0))
    def test_output_is_always_valid_severity(self, score: float) -> None:
        """Output is always one of the valid severity labels."""
        assert get_display_severity(score) in VALID_SEVERITIES

    @given(
        st.floats(min_value=0.0, max_value=1.0),
        st.floats(min_value=0.0, max_value=1.0),
    )
    def test_display_severity_is_monotonic(self, s1: float, s2: float) -> None:
        """Higher scores never produce a lower severity label (monotonic)."""
        if s2 >= s1:
            sev1 = SEVERITY_ORDER[get_display_severity(s1)]
            sev2 = SEVERITY_ORDER[get_display_severity(s2)]
            assert sev2 >= sev1, f"s1={s1} -> {get_display_severity(s1)}, s2={s2} -> {get_display_severity(s2)}"


# ---------------------------------------------------------------------------
# score_threat — property-based tests
# ---------------------------------------------------------------------------
class TestScoreThreatProperties:
    """Property-based tests for score_threat invariants."""

    @given(
        st.builds(ThreatRecord, **_THREAT_BUILD_KWARGS),
        st.integers(min_value=0, max_value=10),
    )
    def test_score_always_between_zero_and_one(
        self,
        threat: ThreatRecord,
        corroboration_count: int,
    ) -> None:
        """Final score is always in [0.0, 1.0] regardless of inputs."""
        now = datetime.now(UTC)
        result = score_threat(threat, "exact", max(corroboration_count, 1), now)
        assert 0.0 <= result.final_score <= 1.0, (
            f"Score {result.final_score} out of range [0, 1] "
            f"(severity={threat.severity}, source={threat.source}, "
            f"corrob={corroboration_count})"
        )

    @given(
        st.builds(ThreatRecord, **_THREAT_BUILD_KWARGS),
        st.integers(min_value=0, max_value=10),
    )
    def test_display_severity_matches_get_display_severity(
        self,
        threat: ThreatRecord,
        corroboration_count: int,
    ) -> None:
        """display_severity on ScoredThreat matches get_display_severity(final_score)."""
        now = datetime.now(UTC)
        result = score_threat(threat, "exact", max(corroboration_count, 1), now)
        expected = get_display_severity(result.final_score)
        assert result.display_severity == expected, (
            f"display_severity={result.display_severity} != "
            f"get_display_severity({result.final_score})={expected} "
            f"(severity={threat.severity}, source={threat.source})"
        )

    @given(
        st.builds(
            ThreatRecord,
            **{
                **_THREAT_BUILD_KWARGS,
                "severity": st.just("CRITICAL"),
                "source": st.sampled_from(["mastodon", "reddit", "x_twitter"]),
            },
        ),
        st.integers(min_value=0, max_value=10),
    )
    def test_social_critical_never_exceeds_medium(
        self,
        threat: ThreatRecord,
        corroboration_count: int,
    ) -> None:
        """Social sources with CRITICAL severity never exceed MEDIUM display."""
        now = datetime.now(UTC)
        result = score_threat(threat, "exact", max(corroboration_count, 1), now)
        severity_order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert severity_order[result.display_severity] <= severity_order["MEDIUM"], (
            f"Social source {threat.source} with CRITICAL severity "
            f"produced display_severity={result.display_severity} "
            f"(score={result.final_score})"
        )

    @given(
        st.builds(ThreatRecord, **_THREAT_BUILD_KWARGS),
        st.integers(min_value=1, max_value=9),
    )
    def test_higher_corroboration_never_lowers_score(
        self,
        threat: ThreatRecord,
        c_low: int,
    ) -> None:
        """Higher corroboration_count never produces a lower score (monotonic)."""
        c_high = c_low + 1
        now = datetime.now(UTC)
        score_low = score_threat(threat, "exact", c_low, now).final_score
        score_high = score_threat(threat, "exact", c_high, now).final_score
        assert score_high >= score_low, (
            f"corrob={c_high} gave score={score_high} < "
            f"corrob={c_low} gave score={score_low} "
            f"(severity={threat.severity}, source={threat.source})"
        )
