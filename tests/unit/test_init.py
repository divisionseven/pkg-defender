"""Tests for pkg_defender __init__ module."""

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
