"""Tests for _version_matches — single operators, compound ranges, bare versions.

All tests exercise ``pkg_defender.version._version_matches``, the single
consolidated source of truth for version matching.
"""

from __future__ import annotations

import pytest

from pkg_defender.version import _version_matches as version_matches

# ---------------------------------------------------------------------------
# Parametrized test cases — all 17 required scenarios
# ---------------------------------------------------------------------------

# Each tuple: (pkg_version, affected_versions, affected_ranges, expected_result)
# expected_result: "exact", "range", or None
_VERSION_MATCH_CASES: list[tuple[str, list[str], list[str], str | None]] = [
    # 1. >=1.0.0 with 1.5.0 → True
    ("1.5.0", [], [">=1.0.0"], "range"),
    # 2. >=1.0.0 with 0.9.0 → False
    ("0.9.0", [], [">=1.0.0"], None),
    # 3. <2.0.0 with 1.5.0 → True
    ("1.5.0", [], ["<2.0.0"], "range"),
    # 4. <2.0.0 with 2.1.0 → False
    ("2.1.0", [], ["<2.0.0"], None),
    # 5. <=2.0.0 with 2.0.0 → True
    ("2.0.0", [], ["<=2.0.0"], "range"),
    # 6. <=2.0.0 with 2.1.0 → False
    ("2.1.0", [], ["<=2.0.0"], None),
    # 7. >1.0.0 with 1.1.0 → True
    ("1.1.0", [], [">1.0.0"], "range"),
    # 8. >1.0.0 with 1.0.0 → False
    ("1.0.0", [], [">1.0.0"], None),
    # 9. ==1.5.0 with 1.5.0 → True
    ("1.5.0", [], ["==1.5.0"], "range"),
    # 10. ==1.5.0 with 1.6.0 → False
    ("1.6.0", [], ["==1.5.0"], None),
    # 11. !=1.5.0 with 1.6.0 → True
    ("1.6.0", [], ["!=1.5.0"], "range"),
    # 12. !=1.5.0 with 1.5.0 → False
    ("1.5.0", [], ["!=1.5.0"], None),
    # 13. >=1.0.0,<2.0.0 with 1.5.0 → True (compound AND)
    ("1.5.0", [], [">=1.0.0,<2.0.0"], "range"),
    # 14. >=1.0.0,<2.0.0 with 2.5.0 → False (upper bound fails)
    ("2.5.0", [], [">=1.0.0,<2.0.0"], None),
    # 15. >=1.0.0,<2.0.0 with 0.5.0 → False (lower bound fails)
    ("0.5.0", [], [">=1.0.0,<2.0.0"], None),
    # 16. 1.5.0 (bare version, no operator) with 1.5.0 → True (exact match)
    ("1.5.0", [], ["1.5.0"], "range"),
    # 17. 1.5.0 (bare version) with 1.6.0 → False
    ("1.6.0", [], ["1.5.0"], None),
]


# ---------------------------------------------------------------------------
# Tests for checker._version_matches
# ---------------------------------------------------------------------------


class TestVersionMatches:
    """Tests for pkg_defender.version._version_matches."""

    @pytest.mark.parametrize(
        "pkg_version, affected_versions, affected_ranges, expected",
        _VERSION_MATCH_CASES,
        ids=[f"case_{i + 1}" for i in range(len(_VERSION_MATCH_CASES))],
    )
    def test_version_match(
        self,
        pkg_version: str,
        affected_versions: list[str],
        affected_ranges: list[str],
        expected: str | None,
    ) -> None:
        """Parametrized test covering all 17 required scenarios."""
        result = version_matches(pkg_version, affected_versions, affected_ranges)
        assert result == expected


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------


class TestVersionMatchesEdgeCases:
    """Edge cases beyond the 17 required scenarios."""

    def test_exact_match_takes_priority_over_range(self) -> None:
        """When version is in affected_versions, return 'exact' even if ranges match."""
        assert version_matches("1.0.0", ["1.0.0"], [">=1.0.0"]) == "exact"

    def test_empty_versions_and_ranges(self) -> None:
        """No affected versions or ranges → None."""
        assert version_matches("1.0.0", [], []) is None

    def test_whitespace_around_operator(self) -> None:
        """Whitespace around operator/version is handled."""
        assert version_matches("1.5.0", [], [">= 1.0.0"]) == "range"

    def test_compound_range_with_spaces(self) -> None:
        """Compound range with spaces around comma."""
        assert version_matches("1.5.0", [], [">=1.0.0, <2.0.0"]) == "range"

    def test_multiple_ranges_first_matches(self) -> None:
        """Multiple range entries — first match wins."""
        assert version_matches("1.5.0", [], ["<1.0.0", ">=1.0.0"]) == "range"

    def test_compound_with_three_conditions(self) -> None:
        """Compound range with three conditions (all must pass)."""
        assert version_matches("1.5.0", [], [">=1.0.0,<2.0.0,!=1.3.0"]) == "range"

    def test_compound_with_three_conditions_fails(self) -> None:
        """Compound range with three conditions — one fails → all fail."""
        assert version_matches("1.3.0", [], [">=1.0.0,<2.0.0,!=1.3.0"]) is None
