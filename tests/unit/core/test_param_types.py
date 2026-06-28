"""Tests for custom Click ParameterTypes."""

import pytest
from click import UsageError

from pkg_defender.cli._param_types import PACKAGE_SPECIFIER


class TestPackageSpecifier:
    """Test PackageSpecifier ParamType validation."""

    def test_valid_at_format(self) -> None:
        """Test name@version format is valid."""
        param = PACKAGE_SPECIFIER
        assert param.convert("lodash@4.17.21", None, None) == "lodash@4.17.21"

    def test_valid_equals_format(self) -> None:
        """Test name==version format is valid."""
        assert PACKAGE_SPECIFIER.convert("requests==2.28.0", None, None) == "requests==2.28.0"

    def test_valid_scoped_package(self) -> None:
        """Test @scope/name@version format is valid."""
        assert PACKAGE_SPECIFIER.convert("@types/node@18.0.0", None, None) == "@types/node@18.0.0"

    def test_invalid_no_separator(self) -> None:
        """Test that missing @ or == raises error."""
        with pytest.raises(UsageError):
            PACKAGE_SPECIFIER.convert("lodash", None, None)

    def test_invalid_empty_version(self) -> None:
        """Test that empty version raises error."""
        with pytest.raises(UsageError):
            PACKAGE_SPECIFIER.convert("lodash@", None, None)

    def test_non_string_fails(self) -> None:
        """Test that non-string input raises error."""
        with pytest.raises(UsageError):
            PACKAGE_SPECIFIER.convert(123, None, None)
