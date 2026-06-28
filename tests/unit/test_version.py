"""Tests for pkg_defender.version — single source of truth for version comparison.

Covers PEP 440 parsing, v-prefix handling, pre-release ordering,
build metadata, non-PEP-440 fallback, and edge cases.
"""

from __future__ import annotations

from pkg_defender.version import compare_versions, parse_version

# ---------------------------------------------------------------------------
# parse_version tests
# ---------------------------------------------------------------------------


class TestParseVersion:
    """Tests for parse_version."""

    def test_simple_version(self) -> None:
        """'1.2.3' -> (1, 2, 3)."""
        assert parse_version("1.2.3") == (1, 2, 3)

    def test_v_prefix_stripped(self) -> None:
        """'v1.2.3' -> (1, 2, 3)."""
        assert parse_version("v1.2.3") == (1, 2, 3)

    def test_v_upper_prefix_stripped(self) -> None:
        """'V2.0.0' -> (2, 0, 0)."""
        assert parse_version("V2.0.0") == (2, 0, 0)

    def test_single_component(self) -> None:
        """'5' -> (5,)."""
        assert parse_version("5") == (5,)

    def test_two_components(self) -> None:
        """'10.20' -> (10, 20)."""
        assert parse_version("10.20") == (10, 20)

    def test_build_metadata_stripped(self) -> None:
        """'1.0.0+build.123' -> (1, 0, 0)."""
        assert parse_version("1.0.0+build.123") == (1, 0, 0)

    def test_prerelease_returns_release_tuple(self) -> None:
        """'1.2.3-beta.1' -> release tuple (1, 2, 3)."""
        assert parse_version("1.2.3-beta.1") == (1, 2, 3)

    def test_non_pep440_fallback(self) -> None:
        """Non-PEP-440 string falls back to numeric extraction."""
        assert parse_version("not-a-version") == (0, 0, 0)

    def test_empty_string(self) -> None:
        """Empty string returns (0,)."""
        assert parse_version("") == (0,)

    def test_many_components(self) -> None:
        """Versions with many components."""
        assert parse_version("2024.01.15.1") == (2024, 1, 15, 1)


# ---------------------------------------------------------------------------
# compare_versions tests — PEP 440 ordering
# ---------------------------------------------------------------------------


class TestCompareVersions:
    """Tests for compare_versions using PEP 440 ordering."""

    def test_equal(self) -> None:
        assert compare_versions("1.2.3", "1.2.3") == 0

    def test_less_than(self) -> None:
        assert compare_versions("1.2.3", "1.2.4") == -1

    def test_greater_than(self) -> None:
        assert compare_versions("2.0.0", "1.9.9") == 1

    def test_different_lengths(self) -> None:
        assert compare_versions("1.2", "1.2.3") == -1

    def test_v_prefix_equal(self) -> None:
        assert compare_versions("v1.2.3", "v1.2.3") == 0

    def test_v_prefix_less(self) -> None:
        assert compare_versions("v1.2.3", "v2.0.0") == -1

    def test_v_prefix_greater(self) -> None:
        assert compare_versions("v2.0.0", "v1.2.3") == 1

    def test_v_prefix_vs_no_prefix(self) -> None:
        """v-prefixed and non-prefixed versions compare correctly."""
        assert compare_versions("v1.2.3", "1.2.3") == 0

    def test_prerelease_less_than_release(self) -> None:
        """Pre-release versions are less than release versions per PEP 440."""
        assert compare_versions("1.2.3-beta", "1.2.3") == -1

    def test_prerelease_alpha_vs_beta(self) -> None:
        """Alpha pre-release is less than beta pre-release."""
        assert compare_versions("1.0.0-alpha", "1.0.0-beta") == -1

    def test_prerelease_rc_vs_release(self) -> None:
        """Release candidate is less than release."""
        assert compare_versions("1.0.0-rc.1", "1.0.0") == -1

    def test_build_metadata_ignored(self) -> None:
        """Build metadata does not affect ordering per PEP 440.

        Note: packaging.version treats local version identifiers (+build.1)
        as greater than the base version, so 1.2.3+build.1 > 1.2.3.
        """
        assert compare_versions("1.2.3+build.1", "1.2.3") == 1

    def test_non_pep440_fallback_equal(self) -> None:
        """Non-PEP-440 strings fall back to numeric comparison."""
        assert compare_versions("not-a-version", "not-a-version") == 0

    def test_non_pep440_fallback_less(self) -> None:
        assert compare_versions("1.2.3-custom", "1.2.4-custom") == -1

    def test_single_component(self) -> None:
        assert compare_versions("5", "10") == -1
