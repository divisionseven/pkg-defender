"""Version comparison utilities — single source of truth.

All version comparison in pkg-defender flows through this module.
Uses ``packaging.version.parse`` for PEP 440 compliance, with a
numeric-tuple fallback for non-PEP-440 version strings.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


def parse_version(version: str) -> tuple[int, ...]:
    """Parse a version string into a comparable numeric tuple.

    Strips ``v``/``V`` prefixes, then attempts PEP 440 parsing via
    ``packaging.version.parse``. On ``InvalidVersion``, falls back to
    extracting numeric components from the version string.

    Args:
        version: Version string (e.g. ``"1.2.3"``, ``"v2.0.0"``,
            ``"1.2.3-beta.1"``).

    Returns:
        Tuple of integer version components for comparison.
    """
    cleaned = version.lstrip("vV")

    try:
        from packaging.version import parse as packaging_parse

        pv = packaging_parse(cleaned)
        # packaging.version.Version stores release as tuple — use it directly.
        # Pre-release and post-release info are accessible but for our
        # comparison use case, the Version object's rich comparison is better.
        # So we return the release tuple for fallback use only.
        return pv.release if hasattr(pv, "release") else (0,)
    except Exception:
        # Non-PEP-440 version — fall back to numeric extraction
        return _numeric_tuple(cleaned)


def _numeric_tuple(version: str) -> tuple[int, ...]:
    """Extract numeric components from a version string.

    Splits on ``.``, ``-``, and ``+`` separators, extracting leading
    digits from each segment. Non-numeric segments become ``0``.

    Args:
        version: Cleaned version string (no ``v`` prefix).

    Returns:
        Tuple of integer components.
    """
    parts: list[int] = []
    for segment in re.split(r"[.+-]", version):
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings using PEP 440 ordering.

    Uses ``packaging.version.parse`` for correct comparison. Falls back
    to numeric-tuple comparison for non-PEP-440 strings.

    Args:
        v1: First version string.
        v2: Second version string.

    Returns:
        ``-1`` if *v1* < *v2*, ``0`` if equal, ``1`` if *v1* > *v2*.
    """
    cleaned_v1 = v1.lstrip("vV")
    cleaned_v2 = v2.lstrip("vV")

    try:
        from packaging.version import parse as packaging_parse

        pv1 = packaging_parse(cleaned_v1)
        pv2 = packaging_parse(cleaned_v2)

        if pv1 < pv2:
            return -1
        if pv1 > pv2:
            return 1
        return 0
    except Exception:
        # Non-PEP-440 — fall back to numeric tuple comparison
        t1 = _numeric_tuple(cleaned_v1)
        t2 = _numeric_tuple(cleaned_v2)

        # Pad to equal length
        max_len = max(len(t1), len(t2))
        t1 = t1 + (0,) * (max_len - len(t1))
        t2 = t2 + (0,) * (max_len - len(t2))

        for a, b in zip(t1, t2, strict=True):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0


# Operator prefix strings, longest first to avoid ">=" being consumed by ">"
_OPERATORS: list[str] = [">=", "<=", "!=", "==", ">", "<"]


def _check_single_condition(pkg_version: str, condition: str) -> bool:
    """Evaluate a single version condition against the package version.

    A condition is an operator followed by a version string (e.g. ``">=1.0.0"``).
    If no operator is present, the condition defaults to exact match (``==``).

    Args:
        pkg_version: The installed package version string.
        condition: A single condition string (e.g. ``">=1.0.0"``, ``"1.5.0"``).

    Returns:
        True if the condition is satisfied, False otherwise.
    """
    condition = condition.strip()
    if not condition:
        return True

    # Try each operator prefix (longest first to avoid partial matches)
    for op in _OPERATORS:
        if condition.startswith(op):
            bound_version = condition[len(op) :].strip()
            cmp = _compare_versions(pkg_version, bound_version)
            if op == ">=":
                return cmp >= 0
            if op == "<=":
                return cmp <= 0
            if op == ">":
                return cmp > 0
            if op == "<":
                return cmp < 0
            if op == "==":
                return cmp == 0
            if op == "!=":
                return cmp != 0

    # No operator prefix — treat as exact match (==)
    return _compare_versions(pkg_version, condition) == 0


def _check_range(pkg_version: str, range_spec: str) -> bool:
    """Check whether *pkg_version* satisfies a (possibly compound) range spec.

    Compound ranges are comma-separated: ``">=1.0.0,<2.0.0"``.
    ALL conditions must pass (AND logic). If any condition fails, returns False.

    Args:
        pkg_version: The installed package version string.
        range_spec: A range specifier (e.g. ``">=1.0.0"`` or ``">=1.0.0,<2.0.0"``).

    Returns:
        True if *pkg_version* satisfies every condition in the range spec.
    """
    conditions = range_spec.split(",")
    return all(_check_single_condition(pkg_version, cond) for cond in conditions)


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Delegates to :func:`pkg_defender.version.compare_versions`.

    Args:
        v1: First version string.
        v2: Second version string.

    Returns:
        ``-1`` if *v1* < *v2*, ``0`` if equal, ``1`` if *v1* > *v2*.
    """
    return compare_versions(v1, v2)


def _version_matches(
    version: str,
    affected_versions: list[str],
    affected_ranges: list[str],
) -> str | None:
    """Check if a version matches affected_versions or affected_ranges.

    Supported range operators: ``>=``, ``<=``, ``>``, ``<``, ``==``, ``!=``.
    Compound ranges use comma-separated conditions (AND logic): ``>=1.0.0,<2.0.0``.
    A bare version string with no operator defaults to exact match (``==``).

    Args:
        version: The package version to check.
        affected_versions: List of exact versions affected.
        affected_ranges: List of version ranges (e.g. ``">=1.0.0"``, ``">=1.0.0,<2.0.0"``).

    Returns:
        "exact" for exact match, "range" for range match, or None if not matched.
    """
    if not affected_versions and not affected_ranges:
        return None
    if version in affected_versions:
        return "exact"
    # Range matching — supports all operators and compound (comma-separated) ranges
    for rng in affected_ranges:
        if _check_range(version, rng):
            return "range"
    return None
