# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Pre-install checker — queries threat DB and scoring system."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from typing import overload

from pkg_defender.core.scorer import score_threats
from pkg_defender.models import CheckResult, ThreatRecord
from pkg_defender.version import (
    _version_matches,
)
from pkg_defender.version import (
    parse_version as _parse_version,  # noqa: F401 — re-exported for tests
)

__all__: list[str] = [
    "_parse_version",
    "_safe_fromisoformat",
    "BLOCK_SCORE_THRESHOLD",
    "check_package",
    "check_packages_batch",
]

BLOCK_SCORE_THRESHOLD: float = 0.3


def check_package(
    conn: sqlite3.Connection,
    ecosystem: str,
    package: str,
    version: str,
    now: datetime | None = None,
) -> CheckResult:
    """Query the local threat DB and return a scored CheckResult.

    Note: This function performs both general (package-wide) and version-specific
    threat checks in a single SQL query. The SQL fetches all threats for the
    ecosystem+package, then _version_matches() filters by version. This is
    an intentional optimization — see SPEC_AUDIT_PIPELINE.md Gap 8 Resolution.

    Pure local SQLite lookup — no network I/O.

    Args:
        conn: Open SQLite connection (created by the CLI layer).
        ecosystem: Ecosystem identifier (e.g. ``"npm"``).
        package: Package name.
        version: Exact version string to check.
        now: Reference datetime for recency calculation. Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        A CheckResult with ``blocked=True`` when any matching threat scores >=
    ``BLOCK_SCORE_THRESHOLD``. Social sources (score <= 0.225 max) never
    trigger a block.
    """

    rows1 = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE ecosystem = ? AND package_name = ?",
        (ecosystem, package),
    ).fetchall()
    rows2 = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE ecosystem = ? AND package_name = 'unknown'",
        (ecosystem,),
    ).fetchall()
    rows = rows1 + rows2

    threat_records: list[ThreatRecord] = []
    match_type: str | None = None

    for row in rows:
        try:
            affected_versions: list[str] = (
                json.loads(row["affected_versions"])
                if row["affected_versions"] and isinstance(row["affected_versions"], str)
                else []
            )
            affected_ranges: list[str] = (
                json.loads(row["affected_ranges"])
                if row["affected_ranges"] and isinstance(row["affected_ranges"], str)
                else []
            )
        except (json.JSONDecodeError, TypeError) as e:
            # Log malformed record, skip it
            logger = logging.getLogger(__name__)
            threat_id = row["id"]
            logger.warning(f"Malformed JSON in threat {threat_id}: {e}. Skipping.")
            continue
        match_type = _version_matches(version, affected_versions, affected_ranges)
        if match_type is None:
            continue

        threat = _row_to_threat(row)
        if threat is None:
            continue
        threat_records.append(threat)

    # Score ALL threats with multi-source corroboration
    # match_type is guaranteed non-None here since all threats passed the
    # None check in the loop above. The assert narrows the type for mypy.
    if threat_records:
        assert match_type is not None
        scored_threats = score_threats(threat_records, match_type, now=now)
    else:
        scored_threats = []

    blocked = any(st.final_score >= BLOCK_SCORE_THRESHOLD for st in scored_threats)
    highest_score = max((st.final_score for st in scored_threats), default=0.0)
    highest_severity = "UNKNOWN"
    if scored_threats:
        best = max(scored_threats, key=lambda st: st.final_score)
        highest_severity = best.display_severity

    return CheckResult(
        blocked=blocked,
        threats=scored_threats,
        highest_score=highest_score,
        highest_severity=highest_severity,
    )


def get_ecosystem_null_threats(
    conn: sqlite3.Connection,
    ecosystem: str,
) -> list[ThreatRecord]:
    """Fetch ecosystem-wide threats (package_name = 'unknown') as raw ThreatRecords.

    These threats apply to ALL packages in the ecosystem.
    The SQL query is executed once and the results cached per-ecosystem by the
    caller, eliminating the N+1 pattern where the same query runs per-package.

    Args:
        conn: Open SQLite connection.
        ecosystem: Ecosystem identifier (e.g., "pypi", "npm").

    Returns:
        List of ThreatRecord objects where package_name = 'unknown'.
    """
    rows = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE ecosystem = ? AND package_name = 'unknown'",
        (ecosystem,),
    ).fetchall()
    results: list[ThreatRecord] = []
    for r in rows:
        threat = _row_to_threat(r)
        if threat is not None:
            results.append(threat)
    return results


def check_packages_batch(
    conn: sqlite3.Connection,
    packages: list[tuple[str, str, str]],
    now: datetime | None = None,
) -> dict[tuple[str, str, str], CheckResult]:
    """Batch threat check for multiple packages.

    Executes 2 SQL queries per distinct ecosystem (one for named-package
    threats, one for ecosystem-wide threats where package_name='unknown'),
    then scores per-package in Python.

    Replaces N calls to check_package() (2N SQL queries) with 2E queries
    (E = number of distinct ecosystems).

    Args:
        conn: Open SQLite connection.
        packages: List of (ecosystem, package, version) tuples.
        now: Reference datetime for recency calculation.

    Returns:
        Dict mapping (ecosystem, package, version) -> CheckResult.
    """
    if not packages:
        return {}

    # Group packages by ecosystem for batch querying
    ecosystem_packages: dict[str, list[tuple[str, str]]] = {}
    for eco, pkg, ver in packages:
        ecosystem_packages.setdefault(eco, []).append((pkg, ver))

    # Fetch all threats per ecosystem (2 queries per ecosystem)
    ecosystem_named_threats: dict[str, dict[str, list[sqlite3.Row]]] = {}
    ecosystem_null_threats: dict[str, list[ThreatRecord]] = {}

    for eco in ecosystem_packages:
        # Query 1: Named-package threats for all packages in this ecosystem
        pkg_names = list({pkg for pkg, _ in ecosystem_packages[eco]})
        if pkg_names:
            placeholders = ",".join(["?"] * len(pkg_names))
            rows = conn.execute(
                f"SELECT id, ecosystem, package_name, affected_versions, "
                f"affected_ranges, severity, confidence, source, source_id, "
                f"summary, detail_url, first_seen, last_seen, hit_count, "
                f"cvss_score, published_at, ingested_at, is_malicious, "
                f"is_unverified, updated_at "
                f"FROM threats WHERE ecosystem = ? "
                f"AND package_name IN ({placeholders})",
                [eco] + pkg_names,
            ).fetchall()
        else:
            rows = []

        # Group named-package rows by package_name
        named_by_pkg: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            pkg_name = row["package_name"]
            named_by_pkg.setdefault(pkg_name, []).append(row)
        ecosystem_named_threats[eco] = named_by_pkg

        # Query 2: Ecosystem-wide threats where package_name='unknown' (once per ecosystem)
        ecosystem_null_threats[eco] = get_ecosystem_null_threats(conn, eco)

    # Score per-package using the same pipeline as check_package()
    results: dict[tuple[str, str, str], CheckResult] = {}
    for eco, pkg_list in ecosystem_packages.items():
        named_rows = ecosystem_named_threats.get(eco, {})
        null_threats = ecosystem_null_threats.get(eco, [])

        for pkg_name, version in pkg_list:
            # Combine named-package rows + ecosystem-wide threats
            pkg_rows = named_rows.get(pkg_name, [])
            threat_records: list[ThreatRecord] = []

            # Collect named-package threats
            last_match_type: str | None = None
            for row in pkg_rows:
                try:
                    affected_versions: list[str] = (
                        json.loads(row["affected_versions"])
                        if row["affected_versions"] and isinstance(row["affected_versions"], str)
                        else []
                    )
                    affected_ranges: list[str] = (
                        json.loads(row["affected_ranges"])
                        if row["affected_ranges"] and isinstance(row["affected_ranges"], str)
                        else []
                    )
                except (json.JSONDecodeError, TypeError) as e:
                    logger = logging.getLogger(__name__)
                    logger.warning("Malformed JSON in threat %s: %s. Skipping.", row["id"], e)
                    continue
                match_type = _version_matches(version, affected_versions, affected_ranges)
                if match_type is None:
                    continue
                threat = _row_to_threat(row)
                if threat is None:
                    continue
                threat_records.append(threat)
                last_match_type = match_type

            # Collect ecosystem-wide threats (package_name='unknown')
            for threat in null_threats:
                match_type = _version_matches(version, threat.affected_versions, threat.affected_ranges)
                if match_type is None:
                    continue
                threat_records.append(threat)
                last_match_type = match_type

            # Score ALL threats with multi-source corroboration
            # last_match_type is guaranteed non-None here since all threats passed
            # the None check before being appended, and the variable is only
            # updated alongside threat_records.append().
            if threat_records:
                assert last_match_type is not None
                scored_threats = score_threats(threat_records, last_match_type, now=now)
            else:
                scored_threats = []

            blocked = any(st.final_score >= BLOCK_SCORE_THRESHOLD for st in scored_threats)
            highest_score = max((st.final_score for st in scored_threats), default=0.0)
            highest_severity = "UNKNOWN"
            if scored_threats:
                best = max(scored_threats, key=lambda st: st.final_score)
                highest_severity = best.display_severity

            results[(eco, pkg_name, version)] = CheckResult(
                blocked=blocked,
                threats=scored_threats,
                highest_score=highest_score,
                highest_severity=highest_severity,
            )

    return results


@overload
def _safe_fromisoformat(value: str | None, default: datetime) -> datetime: ...


@overload
def _safe_fromisoformat(value: str | None, default: None) -> datetime | None: ...


def _safe_fromisoformat(value: str | None, default: datetime | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, returning *default* on failure."""
    if value is None:
        return default
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        logger = logging.getLogger(__name__)
        logger.warning("Malformed ISO timestamp: %s. Using default.", value)
        return default


def _row_to_threat(row: sqlite3.Row) -> ThreatRecord | None:
    """Convert a raw DB row into a ThreatRecord.

    Returns None if the row contains malformed JSON.
    Uses column-name access for resilience against future schema changes.
    """
    try:
        affected_versions = (
            json.loads(row["affected_versions"])
            if row["affected_versions"] and isinstance(row["affected_versions"], str)
            else []
        )
        affected_ranges = (
            json.loads(row["affected_ranges"])
            if row["affected_ranges"] and isinstance(row["affected_ranges"], str)
            else []
        )
    except (json.JSONDecodeError, TypeError) as e:
        logger = logging.getLogger(__name__)
        logger.warning(f"Malformed JSON in row: {e}")
        return None

    return ThreatRecord(
        id=row["id"],
        ecosystem=row["ecosystem"],
        package_name=row["package_name"],
        affected_versions=affected_versions,
        affected_ranges=affected_ranges,
        severity=row["severity"] or "UNKNOWN",
        confidence=row["confidence"] if row["confidence"] is not None else 0.5,
        source=row["source"] or "",
        source_id=row["source_id"],
        summary=row["summary"] or "",
        detail_url=row["detail_url"],
        first_seen=_safe_fromisoformat(row["first_seen"], datetime.now(UTC)),
        last_seen=_safe_fromisoformat(row["last_seen"], datetime.now(UTC)),
        hit_count=row["hit_count"] if row["hit_count"] is not None else 1,
        cvss_score=row["cvss_score"],
        published_at=_safe_fromisoformat(row["published_at"], None),
        ingested_at=_safe_fromisoformat(row["ingested_at"], datetime.now(UTC)),
        is_malicious=bool(row["is_malicious"]),
        is_unverified=bool(row["is_unverified"]),
    )
