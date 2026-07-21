"""Tests for pkg_defender __init__ module."""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

import pkg_defender
from pkg_defender import __version__, models
from pkg_defender.models import ThreatRecord


class TestVersion:
    """Tests for __version__."""

    def test_version_exists(self) -> None:
        """Assert __version__ is a non-empty string."""
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestModelsImport:
    """Tests for models module imports."""

    def test_models_importable(self) -> None:
        """Assert models can be imported."""
        assert models is not None

    def test_threat_record_accessible(self) -> None:
        """Assert ThreatRecord is accessible."""
        assert hasattr(models, "ThreatRecord")
        assert ThreatRecord is not None


class TestModuleAttributes:
    """Tests for module-level attributes."""

    def test_has_version(self) -> None:
        """Assert module has __version__."""
        assert __version__ is not None

    def test_version_not_default(self) -> None:
        """Assert version is not default empty."""
        assert __version__ != ""
        assert __version__ != "0.0.0"


class TestVersionFallbackChain:
    """Tests for __version__ fallback resolution chain in __init__.py.

    The version resolution chain (4 tiers):
        Tier 1: importlib.metadata.version("pkg-defender")  — installed package
        Tier 2: tomllib.load(pyproject.toml)["project"]["version"]  — dev checkout
        Tier 3: pkg_defender._build_version  — build-time generated (doesn't exist)
    """

    def test_version_standard_path(self) -> None:
        """Tier 1: Version resolves via importlib.metadata in normal environment.

        Within the test suite's virtual environment, pkg-defender is typically
        installed in editable mode, so Tier 1 should resolve a valid version.
        Asserts the result is a non-empty semver string (three numeric
        dot-separated components).
        """
        version = pkg_defender.__version__
        assert isinstance(version, str)
        assert len(version) > 0
        # Must follow X.Y.Z semver format
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_version_tier2_fallback(self) -> None:
        """Tier 2: Falls back to pyproject.toml when importlib.metadata fails.

        When the package is not installed (Tier 1 fails), __version__ is read
        directly from pyproject.toml (lines 13-19). This covers the dev checkout
        scenario where pkg-defender is run from source without being installed.

        This test covers lines 13-19 of __init__.py (pyproject.toml reading).
        """
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
            importlib.reload(pkg_defender)

        assert isinstance(pkg_defender.__version__, str)
        assert len(pkg_defender.__version__) > 0

    def test_version_tier4_hardcoded_fallback(self) -> None:
        """Tier 4: Falls back to hardcoded version when all higher tiers fail.

        Covers line 28 specifically — the hardcoded fallback string. This is the
        only line changed in the release prep commit, and was flagged by Codecov
        as uncovered diff.

        Scenario: All 3 higher-resolution tiers fail:
            Tier 1: patched to raise PackageNotFoundError
            Tier 2: patched tomllib.load to raise Exception
            Tier 3: pkg_defender._build_version naturally raises ImportError
        Previously: Line 28 was uncovered — no test exercised this path.
        """
        with (
            patch("importlib.metadata.version", side_effect=PackageNotFoundError),
            patch("tomllib.load", side_effect=Exception("mock tier2 failure")),
        ):
            importlib.reload(pkg_defender)

        assert isinstance(pkg_defender.__version__, str)
        assert len(pkg_defender.__version__) > 0
