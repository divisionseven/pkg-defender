"""Shared OSV vulnerability parsing utilities.

Provides the canonical ``_parse_osv_vuln`` function used by both the OSV feed
and the Homebrew feed, along with the CVSS/severity extraction helpers that
feed into it.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from pkg_defender.models import ThreatRecord


def cvss_to_severity(score: float | None) -> str:
    """Map a CVSS base score to a severity string.

    Args:
        score: CVSS base score (0.0–10.0) or None.

    Returns:
        Severity string.
    """
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _extract_cvss_score(cvss_string: str) -> float | None:
    """Extract the base score from a CVSS vector string.

    Handles both ``CVSS:3.1/AV:N/...`` format (where score may be embedded)
    and plain numeric strings.

    Args:
        cvss_string: A CVSS vector string or numeric score string.

    Returns:
        The numeric base score, or None if unparseable.
    """
    if not cvss_string:
        return None

    # Plain numeric string
    try:
        score = float(cvss_string)
        if 0.0 <= score <= 10.0:
            return score
    except ValueError:
        pass

    # CVSS vector — base score is not always in the vector string itself;
    # some APIs embed it as "CVSS:3.1/AV:N/.../score:9.8" but OSV typically
    # uses the full vector.  We cannot compute the score from the vector alone
    # without a CVSS calculator, so return None.
    return None


def _extract_severity_and_cvss(vuln: dict[str, Any]) -> float | None:
    """Extract severity (as CVSS score) from an OSV vulnerability dict.

    Checks ``severity[].score`` (CVSS vector string) first, then
    ``database_specific.severity``.  CVSS base score mapping:
        >= 9.0 → CRITICAL, >= 7.0 → HIGH, >= 4.0 → MEDIUM, > 0 → LOW

    Args:
        vuln: Raw OSV vulnerability object.

    Returns:
        CVSS base score (0.0-10.0), or None if no severity info available.
    """
    # Try severity[].score (CVSS vector string — extract base score)
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        cvss_score = _extract_cvss_score(score_str)
        if cvss_score is not None:
            return cvss_score

    # Try database_specific.severity (plain text like "CRITICAL", "HIGH", etc.)
    db_specific = vuln.get("database_specific", {})
    db_severity = db_specific.get("severity", "")
    if isinstance(db_severity, str) and db_severity.upper() in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ):
        severity_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 1.0,
        }
        return severity_map.get(db_severity.upper())

    return None


def _parse_osv_vuln(
    vuln: dict[str, Any],
    *,
    ecosystem: str,
    package: str | None = None,
    id_prefix: str = "osv:",
    source: str = "osv",
    include_eco_in_id: bool = True,
) -> ThreatRecord:
    """Parse a single OSV vulnerability dict into a ThreatRecord.

    Args:
        vuln: Raw OSV vulnerability object.
        ecosystem: Internal ecosystem identifier (e.g. ``"npm"``,
            ``"homebrew"``).  Used as ``record.ecosystem`` and, when
            *include_eco_in_id* is True, appended to the record ID.
        package: Package name.  When ``None``, inferred from the first
            ``affected[].package.name`` entry.
        id_prefix: Prefix for ``record.id``.  Default ``"osv:"`` produces
            IDs like ``"osv:GHSA-xxxx:npm"``.  Homebrew feed uses
            ``"homebrew_osv:"``.
        source: Value for ``record.source``.  Default ``"osv"``.
        include_eco_in_id: Whether to append ``:{ecosystem}`` to
            ``record.id``.  ``True`` for OSV format
            (``"osv:GHSA-xxxx:npm"``), ``False`` for homebrew format
            (``"homebrew_osv:GHSA-xxxx"``).

    Returns:
        A populated ThreatRecord.
    """
    osv_id: str = vuln.get("id", "UNKNOWN")
    now = datetime.now(UTC)

    # --- ID construction ---
    record_id = f"{id_prefix}{osv_id}:{ecosystem}" if include_eco_in_id else f"{id_prefix}{osv_id}"

    # --- affected_versions & affected_ranges ---
    affected_versions: list[str] = []
    affected_ranges: list[str] = []
    for affected_entry in vuln.get("affected", []):
        # Explicit version list
        for ver in affected_entry.get("versions", []):
            if ver not in affected_versions:
                affected_versions.append(ver)
        # Ranges (SEMVER, ECOSYSTEM, GIT)
        for rng in affected_entry.get("ranges", []):
            if rng.get("type") == "GIT":  # Skip GIT ranges — commit hashes are not comparable versions
                continue
            events = rng.get("events", [])
            parts: list[str] = []
            for event in events:
                if "introduced" in event:
                    parts.append(f">={event['introduced']}")
                if "last_affected" in event:
                    parts.append(f"<={event['last_affected']}")
                if "fixed" in event:
                    parts.append(f"<{event['fixed']}")
            if parts:
                range_str = ", ".join(parts)
                if range_str not in affected_ranges:
                    affected_ranges.append(range_str)

    # --- severity and cvss_score ---
    cvss_score = _extract_severity_and_cvss(vuln)
    severity = cvss_to_severity(cvss_score) if cvss_score else "UNKNOWN"

    # --- summary ---
    summary = vuln.get("summary", "")
    if not summary:
        details = vuln.get("details", "")
        summary = details[:200] if details else ""

    # --- timestamps ---
    first_seen = now
    for field_name in ("published", "modified"):
        raw_ts = vuln.get(field_name)
        if raw_ts:
            try:
                first_seen = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                break
            except (ValueError, TypeError):
                pass

    last_seen = now
    raw_modified = vuln.get("modified")
    if raw_modified:
        with contextlib.suppress(ValueError, TypeError):
            last_seen = datetime.fromisoformat(raw_modified.replace("Z", "+00:00"))

    # --- If a specific package was requested, try to extract it from affected ---
    if package is None:
        for affected_entry in vuln.get("affected", []):
            pkg_info = affected_entry.get("package", {})
            if pkg_info.get("name"):
                package = pkg_info["name"]
                break

    return ThreatRecord(
        id=record_id,
        ecosystem=ecosystem,
        package_name=package or "unknown",
        affected_versions=affected_versions,
        affected_ranges=affected_ranges,
        severity=severity,
        confidence=0.9,
        source=source,
        source_id=osv_id,
        summary=summary,
        detail_url=f"https://osv.dev/vulnerability/{osv_id}",
        first_seen=first_seen,
        last_seen=last_seen,
        hit_count=1,
        cvss_score=cvss_score,
        published_at=first_seen,
        ingested_at=now,
        is_malicious=False,
        is_unverified=False,
    )
