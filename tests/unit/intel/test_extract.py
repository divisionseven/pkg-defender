"""Tests for intel/extract.py helpers."""

from __future__ import annotations

import pytest

from pkg_defender.intel.extract import _is_plausible_package_name


class TestIsPlausiblePackageName:
    """Tests for _is_plausible_package_name."""

    @pytest.mark.parametrize(
        "name",
        [
            "lodash",
            "requests",
            "@types/node",
            "@babel/core",
            "axios",
            "express",
        ],
        ids=[
            "simple-lodash",
            "simple-requests",
            "scoped-types-node",
            "scoped-babel-core",
            "simple-axios",
            "simple-express",
        ],
    )
    def test_accepts_plausible_names(self, name: str) -> None:
        """Should accept valid package names."""
        assert _is_plausible_package_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            ".netrc",
            ".env",
            "response.conn_info",
            "config.json",
            "src/utils",
            "3com",
            "a",
            ".gitignore",
        ],
        ids=[
            "dotfile-netrc",
            "dotfile-env",
            "dotted-reference",
            "file-extension",
            "path-separator",
            "starts-with-digit",
            "too-short",
            "dotfile-gitignore",
        ],
    )
    def test_rejects_implausible_names(self, name: str) -> None:
        """Should reject file paths, dotfiles, dotted references, and too-short names."""
        assert _is_plausible_package_name(name) is False
