# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Threat scorer — confidence weights, severity multipliers, recency decay."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pkg_defender.models import ScoredThreat, ThreatRecord


# Source confidence weights

SOURCE_CONFIDENCE: dict[str, float] = {
    "osv": 0.9,  # Structured, version-precise, curated
    "ghsa": 0.85,  # High quality but bulk/advisory-level
    "socket": 0.95,  # Real-time, most accurate for active attacks
    "npm_advisory": 0.8,
    "ossf_malicious": 1.0,  # Authoritative malicious package list
    "homebrew_osv": 0.9,  # Homebrew OSV — same upstream OSV database as osv
    "rss": 0.5,  # Unstructured text, keyword matching
    "mastodon": 0.4,  # Social, noisy, high false positive
    "reddit": 0.45,  # Social but moderated communities
    "x_twitter": 0.5,  # BYOK, varies by trusted account
}


SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.3,
    "UNKNOWN": 0.1,
}


# Number of independent sources confirming the same threat
CORROBORATION_MULTIPLIER: dict[int, float] = {
    1: 1.0,  # Single source — no boost
    2: 1.15,  # Two sources — 15% boost
    3: 1.25,  # Three sources — 25% boost
    4: 1.3,  # Four+ sources — 30% boost (cap)
}

# Recency decay: threats lose 5% score per week, minimum 50% of original
RECENCY_DECAY_PER_WEEK: float = 0.05
RECENCY_FLOOR: float = 0.5


def get_source_confidence(source: str) -> float:
    """Return the confidence weight for a threat source.

    Unknown sources default to 0.5.

    Args:
        source: The source identifier (e.g. ``"osv"``, ``"mastodon"``).

    Returns:
        Confidence weight between 0.0 and 1.0.
    """
    return SOURCE_CONFIDENCE.get(source, 0.5)


def get_display_severity(score: float) -> str:
    """Map a numeric score to a human-readable severity label.

    Args:
        score: Final numeric score (0.0 – 1.0).

    Returns:
        One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``,
        or ``"UNKNOWN"``.
    """
    if score >= 0.9:
        return "CRITICAL"
    if score >= 0.7:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def score_threat(
    threat: ThreatRecord,
    version_match_type: str,
    corroboration_count: int = 1,
    now: datetime | None = None,
) -> ScoredThreat:
    """Score a single threat record.

    The final score combines:
    - Severity base score
    - Source confidence weight
    - Multi-source corroboration multiplier
    - Recency decay (older threats score slightly lower)

    The result is clamped to 1.0 maximum.

    Args:
        threat: The matched ThreatRecord.
        version_match_type: How the version matched (``"exact"``, ``"range"``,
            or ``"package_wide"``).
        corroboration_count: Number of independent sources confirming the same
            threat (minimum 1, capped at 4).
        now: Reference datetime for recency calculation. Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        A ScoredThreat with computed final_score and display_severity.
    """
    from pkg_defender.models import ScoredThreat

    if now is None:
        now = datetime.now(UTC)

    # Base: severity * source confidence
    severity_score = SEVERITY_SCORES.get(threat.severity, 0.1)
    source_conf = get_source_confidence(threat.source)

    # Social feed sources are informational-only — cap their effective
    # confidence to ensure they can never produce a blocking score
    # (BLOCK_SCORE_THRESHOLD = 0.3 in checker.py).
    social_feeds = {"mastodon", "reddit", "x_twitter"}
    if threat.source in social_feeds:
        source_conf = min(source_conf, 0.2)

    base_score = severity_score * source_conf

    # Corroboration multiplier
    corr_key = min(corroboration_count, 4)
    corrob_mult = CORROBORATION_MULTIPLIER[corr_key]
    base_score *= corrob_mult

    # Recency decay
    first_seen = threat.first_seen
    # Ensure both datetimes are timezone-aware for comparison
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=UTC)
    weeks_old = max((now - first_seen).days / 7.0, 0.0)
    decay = max(RECENCY_FLOOR, 1.0 - weeks_old * RECENCY_DECAY_PER_WEEK)
    final_score = base_score * decay

    final_score = round(min(final_score, 1.0), 10)

    return ScoredThreat(
        record=threat,
        final_score=final_score,
        display_severity=get_display_severity(final_score),
        version_match_type=version_match_type,
    )


def score_threats(
    threats: list[ThreatRecord],
    version_match_type: str,
    now: datetime | None = None,
) -> list[ScoredThreat]:
    """Score a list of threats with multi-source corroboration.

    Threats are grouped by (ecosystem, package) to determine how many
    independent sources confirm each threat group. Each individual threat
    is then scored with the corroboration count for its group.

    Args:
        threats: List of matched ThreatRecords.
        version_match_type: How the version matched (``"exact"``, ``"range"``,
            or ``"package_wide"``).
        now: Reference datetime for recency calculation. Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        List of ScoredThreat objects sorted by final_score descending.
    """
    if not threats:
        return []

    # Group by (ecosystem, package_name) and count unique sources
    groups: dict[tuple[str, str | None], set[str]] = defaultdict(set)
    for t in threats:
        key = (t.ecosystem, t.package_name)
        groups[key].add(t.source)

    # Score each threat with its group's corroboration count
    scored: list[ScoredThreat] = []
    for t in threats:
        key = (t.ecosystem, t.package_name)
        corroboration_count = len(groups[key])
        scored.append(score_threat(t, version_match_type, corroboration_count, now))

    # Sort by final_score descending
    scored.sort(key=lambda s: s.final_score, reverse=True)
    return scored
