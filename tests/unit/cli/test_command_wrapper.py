"""Tests for the pkgd command wrapper (pkgd pip install xyz).

This test module verifies the complete command wrapper implementation,
including data models, parsing functions, adapters, and CLI integration.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import click
import pytest

# Import CLI components - these work now that models/__init__.py is fixed
from pkg_defender.cli import (
    ManagerDispatcher,
    ManagerGroup,
    make_manager_passthrough_command,
)
from pkg_defender.models.command import (
    CommandIntent,
    InstallSource,
    PackageRef,
    ParsedCommand,
)
from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY
from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.base import UnifiedRegistryAdapter
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter
from pkg_defender.registry.bun_unified import BunUnifiedAdapter
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter
from pkg_defender.registry.conda_unified import CondaUnifiedAdapter
from pkg_defender.registry.dnf_unified import DnfUnifiedAdapter
from pkg_defender.registry.gem_unified import GemUnifiedAdapter
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.parsing import (
    parse_apt_package,
    parse_brew_package,
    parse_cargo_package,
    parse_composer_package,
    parse_conda_package,
    parse_dnf_package,
    parse_gem_package,
    parse_npm_package,
    parse_python_package,
)
from pkg_defender.registry.pipenv_unified import PipenvUnifiedAdapter
from pkg_defender.registry.pnpm_unified import PnpmUnifiedAdapter
from pkg_defender.registry.poetry_unified import PoetryUnifiedAdapter
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter
from pkg_defender.registry.uv_unified import UvUnifiedAdapter
from pkg_defender.registry.yarn_unified import YarnUnifiedAdapter
from pkg_defender.registry.yum_unified import YumUnifiedAdapter

# =============================================================================
# Data Model Tests
# =============================================================================


class TestCommandIntent:
    """Tests for CommandIntent enum values."""

    def test_all_intents_defined(self) -> None:
        """Verify all expected intent values are defined."""
        assert CommandIntent.INSTALL is not None
        assert CommandIntent.UPDATE is not None
        assert CommandIntent.SYNC is not None
        assert CommandIntent.REMOVE is not None
        assert CommandIntent.SAFE_PASSTHROUGH is not None
        assert CommandIntent.UNKNOWN is not None

    def test_intent_values_are_distinct(self) -> None:
        """Verify each intent has a distinct value."""
        intents = [
            CommandIntent.INSTALL,
            CommandIntent.UPDATE,
            CommandIntent.SYNC,
            CommandIntent.REMOVE,
            CommandIntent.SAFE_PASSTHROUGH,
            CommandIntent.UNKNOWN,
        ]
        # All values should be different (auto() assigns unique values)
        assert len(set(i.value for i in intents)) == len(intents)


class TestInstallSource:
    """Tests for InstallSource enum values."""

    def test_all_sources_defined(self) -> None:
        """Verify all expected source values are defined."""
        assert InstallSource.REGISTRY is not None
        assert InstallSource.FILE is not None
        assert InstallSource.LOCAL_PATH is not None
        assert InstallSource.VCS is not None
        assert InstallSource.URL is not None
        assert InstallSource.UNKNOWN is not None


class TestPackageRef:
    """Tests for PackageRef dataclass."""

    def test_simple_package(self) -> None:
        """Test basic package reference creation."""
        pkg = PackageRef(name="requests", raw="requests")
        assert pkg.name == "requests"
        assert pkg.version is None
        assert pkg.source == InstallSource.REGISTRY

    def test_is_pinned_exact_version(self) -> None:
        """Test is_pinned returns True for exact version."""
        pkg = PackageRef(
            name="requests",
            version="2.31.0",
            version_constraint=None,
            extras=[],
            source=InstallSource.REGISTRY,
            raw="requests==2.31.0",
        )
        assert pkg.is_pinned is True

    def test_is_pinned_version_constraint(self) -> None:
        """Test is_pinned returns False for version constraint."""
        pkg = PackageRef(
            name="requests",
            version=None,
            version_constraint=">=2.0,<3.0",
            extras=[],
            source=InstallSource.REGISTRY,
            raw="requests>=2.0,<3.0",
        )
        assert pkg.is_pinned is False

    def test_is_pinned_no_version(self) -> None:
        """Test is_pinned returns False when no version."""
        pkg = PackageRef(
            name="requests",
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.REGISTRY,
            raw="requests",
        )
        assert pkg.is_pinned is False

    def test_extras_parsed(self) -> None:
        """Test extras are correctly stored."""
        pkg = PackageRef(
            name="requests",
            version="2.31.0",
            version_constraint=None,
            extras=["security", "socks"],
            source=InstallSource.REGISTRY,
            raw="requests[security,socks]==2.31.0",
        )
        assert pkg.extras == ["security", "socks"]
        assert len(pkg.extras) == 2

    def test_raw_preserved(self) -> None:
        """Test raw input is preserved."""
        raw_input = "requests[security,socks]==2.31.0"
        pkg = PackageRef(
            name="requests",
            version="2.31.0",
            version_constraint=None,
            extras=["security", "socks"],
            source=InstallSource.REGISTRY,
            raw=raw_input,
        )
        assert pkg.raw == raw_input


class TestParsedCommand:
    """Tests for ParsedCommand dataclass."""

    def test_default_values(self) -> None:
        """Test default values for optional fields."""
        cmd = ParsedCommand()
        assert cmd.manager == ""
        assert cmd.intent == CommandIntent.SAFE_PASSTHROUGH
        assert cmd.packages == []
        assert cmd.manager_subcommand == ""
        assert cmd.manager_flags == []
        assert cmd.pkgd_flags == {}
        assert cmd.file_targets == []
        assert cmd.raw_args == []
        assert cmd.requires_file_audit is False
        assert cmd.is_global is False
        assert cmd.is_dev_dependency is False

    def test_with_packages(self) -> None:
        """Test creating parsed command with packages."""
        pkg = PackageRef(name="requests", raw="requests")
        cmd = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager_subcommand="install",
        )
        assert cmd.manager == "pip"
        assert cmd.intent == CommandIntent.INSTALL
        assert len(cmd.packages) == 1
        assert cmd.packages[0].name == "requests"


# =============================================================================
# Parsing Function Tests
# =============================================================================


class TestParsePythonPackage:
    """Tests for parse_python_package function."""

    def test_simple_package(self) -> None:
        """Test parsing a simple package name."""
        pkg = parse_python_package("requests")
        assert pkg.name == "requests"
        assert pkg.version is None
        assert pkg.source == InstallSource.REGISTRY

    def test_pinned_version(self) -> None:
        """Test parsing a pinned version."""
        pkg = parse_python_package("requests==2.31.0")
        assert pkg.name == "requests"
        assert pkg.version == "2.31.0"
        assert pkg.source == InstallSource.REGISTRY

    def test_pinned_version_with_extras(self) -> None:
        """Test parsing version with extras."""
        pkg = parse_python_package("requests[security]==2.31.0")
        assert pkg.name == "requests"
        assert pkg.version == "2.31.0"
        assert "security" in pkg.extras

    def test_multiple_extras(self) -> None:
        """Test parsing multiple extras."""
        pkg = parse_python_package("requests[security,socks]==2.31.0")
        assert pkg.name == "requests"
        assert pkg.extras == ["security", "socks"]
        assert pkg.version == "2.31.0"

    def test_version_constraint(self) -> None:
        """Test parsing version constraint."""
        pkg = parse_python_package("requests>=2.0,<3.0")
        assert pkg.name == "requests"
        assert pkg.version is None
        assert pkg.version_constraint == ">=2.0,<3.0"

    def test_version_constraint_not_pinned(self) -> None:
        """Test constraint is not considered pinned."""
        pkg = parse_python_package("requests>=2.0,<3.0")
        assert pkg.is_pinned is False

    def test_version_greater_than(self) -> None:
        """Test parsing >= constraint."""
        pkg = parse_python_package("requests>=2.0")
        assert pkg.version_constraint == ">=2.0"
        assert pkg.is_pinned is False

    def test_version_less_than(self) -> None:
        """Test parsing < constraint."""
        pkg = parse_python_package("requests<3.0")
        assert pkg.version_constraint == "<3.0"
        assert pkg.is_pinned is False

    def test_version_tilde(self) -> None:
        """Test parsing ~ constraint."""
        pkg = parse_python_package("requests~=2.0")
        assert pkg.version_constraint == "~=2.0"

    def test_version_exact_not_equal(self) -> None:
        """Test parsing != constraint."""
        pkg = parse_python_package("requests!=2.31.0")
        assert pkg.version_constraint == "!=2.31.0"

    def test_with_extras_no_version(self) -> None:
        """Test parsing extras without version."""
        pkg = parse_python_package("requests[security,socks]")
        assert pkg.name == "requests"
        assert pkg.extras == ["security", "socks"]
        assert pkg.version is None

    def test_vcs_source_git(self) -> None:
        """Test parsing VCS source with git."""
        pkg = parse_python_package("git+https://github.com/user/repo.git")
        assert pkg.source == InstallSource.VCS
        assert pkg.name == "git+https://github.com/user/repo.git"

    def test_vcs_source_hg(self) -> None:
        """Test parsing VCS source with hg."""
        pkg = parse_python_package("hg+https://bitbucket.org/user/repo")
        assert pkg.source == InstallSource.VCS

    def test_url_source(self) -> None:
        """Test parsing URL source."""
        pkg = parse_python_package("https://example.com/pkg.tar.gz")
        assert pkg.source == InstallSource.URL
        assert pkg.name == "https://example.com/pkg.tar.gz"

    def test_local_path_relative(self) -> None:
        """Test parsing relative local path."""
        pkg = parse_python_package("./mypackage")
        assert pkg.source == InstallSource.LOCAL_PATH

    def test_local_path_absolute(self) -> None:
        """Test parsing absolute local path."""
        pkg = parse_python_package("/path/to/package")
        assert pkg.source == InstallSource.LOCAL_PATH

    def test_local_path_home(self) -> None:
        """Test parsing home directory path."""
        pkg = parse_python_package("~/my-package")
        assert pkg.source == InstallSource.LOCAL_PATH

    def test_local_path_dot(self) -> None:
        """Test parsing current directory."""
        pkg = parse_python_package(".")
        assert pkg.source == InstallSource.LOCAL_PATH


class TestParseNpmPackage:
    """Tests for parse_npm_package function."""

    def test_simple_package(self) -> None:
        """Test parsing a simple package name."""
        pkg = parse_npm_package("express")
        assert pkg.name == "express"
        assert pkg.version is None
        assert pkg.source == InstallSource.REGISTRY

    def test_pinned_version(self) -> None:
        """Test parsing a pinned version."""
        pkg = parse_npm_package("express@4.18.0")
        assert pkg.name == "express"
        assert pkg.version == "4.18.0"
        assert pkg.source == InstallSource.REGISTRY

    def test_scoped_package(self) -> None:
        """Test parsing a scoped package."""
        pkg = parse_npm_package("@angular/core")
        assert pkg.name == "@angular/core"
        assert pkg.version is None

    def test_scoped_with_version(self) -> None:
        """Test parsing scoped package with version."""
        pkg = parse_npm_package("@angular/core@17.0.0")
        assert pkg.name == "@angular/core"
        assert pkg.version == "17.0.0"

    def test_caret_range(self) -> None:
        """Test parsing caret range."""
        pkg = parse_npm_package("express@^4.0.0")
        assert pkg.name == "express"
        assert pkg.version_constraint == "^4.0.0"

    def test_tilde_range(self) -> None:
        """Test parsing tilde range."""
        pkg = parse_npm_package("express@~4.18.0")
        assert pkg.name == "express"
        assert pkg.version_constraint == "~4.18.0"

    def test_latest_keyword(self) -> None:
        """Test parsing @latest."""
        pkg = parse_npm_package("express@latest")
        assert pkg.name == "express"
        assert pkg.version_constraint == "latest"

    def test_next_keyword(self) -> None:
        """Test parsing @next."""
        pkg = parse_npm_package("express@next")
        assert pkg.name == "express"
        assert pkg.version_constraint == "next"

    def test_beta_keyword(self) -> None:
        """Test parsing @beta."""
        pkg = parse_npm_package("express@beta")
        assert pkg.name == "express"
        assert pkg.version_constraint == "beta"

    def test_alpha_keyword(self) -> None:
        """Test parsing @alpha."""
        pkg = parse_npm_package("express@alpha")
        assert pkg.name == "express"
        assert pkg.version_constraint == "alpha"

    def test_github_source(self) -> None:
        """Test parsing GitHub source."""
        pkg = parse_npm_package("github:user/repo")
        assert pkg.source == InstallSource.VCS

    def test_gitlab_source(self) -> None:
        """Test parsing GitLab source."""
        pkg = parse_npm_package("gitlab:user/repo")
        assert pkg.source == InstallSource.VCS

    def test_url_source(self) -> None:
        """Test parsing URL source."""
        pkg = parse_npm_package("https://example.com/pkg.tgz")
        assert pkg.source == InstallSource.URL


class TestParseBrewPackage:
    """Tests for parse_brew_package function."""

    def test_simple_formula(self) -> None:
        """Test parsing a simple formula."""
        pkg = parse_brew_package("tree")
        assert pkg.name == "tree"
        assert pkg.version is None

    def test_versioned_formula(self) -> None:
        """Test parsing versioned formula."""
        pkg = parse_brew_package("python@3.12")
        assert pkg.name == "python"
        assert pkg.version == "3.12"

    def test_multipart_name(self) -> None:
        """Test parsing multipart formula name."""
        pkg = parse_brew_package("gcc@13.2.0")
        assert pkg.name == "gcc"
        assert pkg.version == "13.2.0"


# =============================================================================
# Adapter Tests
# =============================================================================


class TestPipAdapter:
    """Tests for PyPIUnifiedAdapter (replaces PipAdapter)."""

    def test_parse_install(self) -> None:
        """Test parsing pip install command."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["install", "requests"])

        assert result.manager == "pip"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"

    def test_parse_install_with_version(self) -> None:
        """Test parsing install with version."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["install", "requests==2.31.0"])

        assert result.packages[0].name == "requests"
        assert result.packages[0].version == "2.31.0"

    def test_parse_multiple_packages(self) -> None:
        """Test parsing multiple packages."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["install", "requests", "flask", "django==4.2.0"])

        assert len(result.packages) == 3
        assert result.packages[0].name == "requests"
        assert result.packages[1].name == "flask"
        assert result.packages[2].name == "django"
        assert result.packages[2].version == "4.2.0"

    def test_parse_file_requirements(self) -> None:
        """Test parsing requirements file."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["install", "-r", "requirements.txt"])

        assert result.requires_file_audit is True
        assert "requirements.txt" in result.file_targets

    def test_parse_safe_passthrough(self) -> None:
        """Test parsing safe passthrough command."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["list"])

        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_split_pkgd_flags(self) -> None:
        """Test splitting pkgd-specific flags."""
        adapter = PyPIUnifiedAdapter()
        args = ["install", "requests", "--dry-run", "--cooldown", "48"]
        clean, flags = adapter.split_pkgd_flags(args)

        assert clean == ["install", "requests"]
        assert flags.get("dry_run") is True
        assert flags.get("cooldown") == "48"

    def test_split_pkgd_flags_multiple(self) -> None:
        """Test splitting multiple pkgd flags."""
        adapter = PyPIUnifiedAdapter()
        args = ["install", "requests", "--dry-run", "--verbose", "--force", "--explain"]
        clean, flags = adapter.split_pkgd_flags(args)

        assert clean == ["install", "requests"]
        assert flags.get("dry_run") is True
        assert flags.get("verbose") is True
        assert flags.get("force") is True
        assert flags.get("explain") is True

    def test_tokenize_value_flags(self) -> None:
        """Test tokenizing value flags."""
        adapter = PyPIUnifiedAdapter()
        tokens = adapter.tokenize_args(["install", "-i", "https://pypi.org/simple", "requests"])

        assert tokens[0] == "install"
        assert isinstance(tokens[1], tuple)
        assert tokens[1] == ("-i", "https://pypi.org/simple")
        assert tokens[2] == "requests"

    def test_tokenize_equals_form(self) -> None:
        """Test tokenizing --flag=value form."""
        adapter = PyPIUnifiedAdapter()
        tokens = adapter.tokenize_args(["install", "--index-url=https://pypi.org/simple", "requests"])

        assert isinstance(tokens[1], tuple)
        assert tokens[1] == ("--index-url", "https://pypi.org/simple")

    def test_build_exec_args(self) -> None:
        """Test building exec arguments."""
        adapter = PyPIUnifiedAdapter()
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[
                PackageRef(
                    name="requests",
                    version="2.31.0",
                    version_constraint=None,
                    extras=[],
                    source=InstallSource.REGISTRY,
                    raw="requests==2.31.0",
                )
            ],
            manager_subcommand="install",
            manager_flags=["--no-cache-dir"],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "requests==2.31.0", "--no-cache-dir"],
        )
        args = adapter.build_exec_args(parsed)

        assert args[0] == "pip"
        assert args[1] == "install"
        assert "--no-cache-dir" in args
        assert "requests==2.31.0" in args

    def test_parse_download(self) -> None:
        """Test parsing pip download command."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["download", "requests"])

        assert result.intent == CommandIntent.INSTALL


class TestNpmAdapter:
    """Tests for NpmUnifiedAdapter (replaces NpmAdapter)."""

    def test_parse_install(self) -> None:
        """Test parsing npm install command."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "express"])

        assert result.manager == "npm"
        assert result.intent == CommandIntent.INSTALL

    def test_parse_scoped_package(self) -> None:
        """Test parsing scoped npm package."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "@angular/core@17.0.0"])

        assert result.packages[0].name == "@angular/core"
        assert result.packages[0].version == "17.0.0"

    def test_parse_no_args_sync(self) -> None:
        """Test parsing npm install with no packages."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install"])

        # npm install with no args is SYNC (from package.json)
        assert result.intent == CommandIntent.SYNC

    def test_parse_dev_dependency(self) -> None:
        """Test parsing dev dependency flag."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "--save-dev", "jest"])

        assert result.is_dev_dependency is True

    def test_parse_dev_dependency_short(self) -> None:
        """Test parsing -D dev dependency flag."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "-D", "jest"])

        assert result.is_dev_dependency is True

    def test_parse_global(self) -> None:
        """Test parsing global install."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "-g", "typescript"])

        assert result.is_global is True

    def test_parse_global_long(self) -> None:
        """Test parsing --global install."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "--global", "typescript"])

        assert result.is_global is True

    def test_parse_update(self) -> None:
        """Test parsing npm update."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["update", "express"])

        assert result.intent == CommandIntent.UPDATE

    def test_parse_update_short_i(self) -> None:
        """Test parsing npm i (shorthand for install)."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["i", "express"])

        assert result.intent == CommandIntent.INSTALL

    def test_parse_add(self) -> None:
        """Test parsing npm add."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["add", "express"])

        assert result.intent == CommandIntent.INSTALL


class TestBrewAdapter:
    """Tests for BrewUnifiedAdapter (replaces BrewAdapter)."""

    def test_parse_install(self) -> None:
        """Test parsing brew install."""
        adapter = BrewUnifiedAdapter()
        result = adapter.parse(["install", "tree"])

        assert result.manager == "brew"
        assert result.intent == CommandIntent.INSTALL
        assert result.is_global is True  # brew is always global

    def test_upgrade_no_args_sync(self) -> None:
        """Test parsing brew upgrade with no args."""
        adapter = BrewUnifiedAdapter()
        result = adapter.parse(["upgrade"])

        # brew upgrade with no args = upgrade all = SYNC
        assert result.intent == CommandIntent.SYNC

    def test_parse_reinstall(self) -> None:
        """Test parsing brew reinstall."""
        adapter = BrewUnifiedAdapter()
        result = adapter.parse(["reinstall", "tree"])

        assert result.intent == CommandIntent.INSTALL


class TestUvAdapter:
    """Tests for UvUnifiedAdapter (replaces UvAdapter)."""

    def test_parse_add(self) -> None:
        """Test parsing uv add."""
        adapter = UvUnifiedAdapter()
        result = adapter.parse(["add", "httpx"])

        assert result.manager == "uv"
        assert result.intent == CommandIntent.INSTALL

    def test_parse_pip_install(self) -> None:
        """Test parsing uv pip install."""
        adapter = UvUnifiedAdapter()
        result = adapter.parse(["pip", "install", "requests"])

        assert result.intent == CommandIntent.INSTALL

    def test_parse_sync(self) -> None:
        """Test parsing uv sync."""
        adapter = UvUnifiedAdapter()
        result = adapter.parse(["sync"])

        assert result.intent == CommandIntent.SYNC

    def test_parse_upgrade(self) -> None:
        """Test parsing uv upgrade."""
        adapter = UvUnifiedAdapter()
        result = adapter.parse(["upgrade"])

        assert result.intent == CommandIntent.UPDATE


class TestYarnAdapter:
    """Tests for YarnUnifiedAdapter (replaces YarnAdapter)."""

    def test_parse_add(self) -> None:
        """Test parsing yarn add."""
        adapter = YarnUnifiedAdapter()
        result = adapter.parse(["add", "lodash"])

        assert result.manager == "yarn"
        assert result.intent == CommandIntent.INSTALL

    def test_bare_yarn_sync(self) -> None:
        """Test bare yarn command is SYNC."""
        adapter = YarnUnifiedAdapter()
        result = adapter.parse([])

        assert result.intent == CommandIntent.SYNC

    def test_bare_yarn_install_sync(self) -> None:
        """Test yarn install is SYNC."""
        adapter = YarnUnifiedAdapter()
        result = adapter.parse(["install"])

        assert result.intent == CommandIntent.SYNC

    def test_parse_remove(self) -> None:
        """Test parsing yarn remove."""
        adapter = YarnUnifiedAdapter()
        result = adapter.parse(["remove", "lodash"])

        assert result.intent == CommandIntent.REMOVE


class TestPnpmAdapter:
    """Tests for PnpmUnifiedAdapter (replaces PnpmAdapter)."""

    def test_parse_add(self) -> None:
        """Test parsing pnpm add."""
        adapter = PnpmUnifiedAdapter()
        result = adapter.parse(["add", "axios"])

        assert result.manager == "pnpm"
        assert result.intent == CommandIntent.INSTALL

    def test_parse_install_sync(self) -> None:
        """Test pnpm install is SYNC."""
        adapter = PnpmUnifiedAdapter()
        result = adapter.parse(["install"])

        assert result.intent == CommandIntent.SYNC

    def test_parse_i_sync(self) -> None:
        """Test pnpm i is SYNC."""
        adapter = PnpmUnifiedAdapter()
        result = adapter.parse(["i"])

        assert result.intent == CommandIntent.SYNC


# =============================================================================
# Registry Tests
# =============================================================================


class TestManagerRegistry:
    """Tests for UNIFIED_MANAGER_REGISTRY."""

    def test_all_expected_managers_registered(self) -> None:
        """Verify all expected managers are registered."""
        assert "pip" in UNIFIED_MANAGER_REGISTRY
        assert "pip3" in UNIFIED_MANAGER_REGISTRY
        assert "pipx" in UNIFIED_MANAGER_REGISTRY
        assert "uv" in UNIFIED_MANAGER_REGISTRY
        assert "npm" in UNIFIED_MANAGER_REGISTRY
        assert "yarn" in UNIFIED_MANAGER_REGISTRY
        assert "pnpm" in UNIFIED_MANAGER_REGISTRY
        assert "brew" in UNIFIED_MANAGER_REGISTRY

    def test_pip3_is_pypi_unified_adapter(self) -> None:
        """Verify pip3 maps to PyPIUnifiedAdapter (same as pip)."""
        assert UNIFIED_MANAGER_REGISTRY["pip3"] is UNIFIED_MANAGER_REGISTRY["pip"]

    def test_all_adapters_have_parse(self) -> None:
        """Verify all registered adapters have parse method."""
        for _, adapter_cls in UNIFIED_MANAGER_REGISTRY.items():
            adapter = adapter_cls()
            assert hasattr(adapter, "parse")
            assert callable(adapter.parse)

    def test_all_adapters_have_build_exec_args(self) -> None:
        """Verify all adapters can build exec args."""
        for _, adapter_cls in UNIFIED_MANAGER_REGISTRY.items():
            adapter = adapter_cls()
            assert hasattr(adapter, "build_exec_args")
            assert callable(adapter.build_exec_args)

    def test_all_adapters_inherit_from_unified_registry_adapter(self) -> None:
        """Verify all adapters inherit from UnifiedRegistryAdapter."""
        for _, adapter_cls in UNIFIED_MANAGER_REGISTRY.items():
            assert issubclass(adapter_cls, UnifiedRegistryAdapter)


# =============================================================================
# ManagerGroup Tests
# =============================================================================
# These tests verify CLI components work correctly.
# They were previously skipped due to models/__init__.py import issues
# that have since been fixed.


class TestManagerGroup:
    """Tests for ManagerGroup CLI component."""

    def test_get_command_unknown(self) -> None:
        """Test getting unknown manager returns None."""
        import unittest.mock as mock

        group = ManagerGroup()
        mock_ctx = mock.MagicMock(spec=click.Context)
        cmd = group.get_command(mock_ctx, "nonexistent-manager-xyz")
        assert cmd is None

    def test_get_command_pip(self) -> None:
        """Test getting pip command returns a command."""
        import unittest.mock as mock

        group = ManagerGroup()
        mock_ctx = mock.MagicMock(spec=click.Context)
        cmd = group.get_command(mock_ctx, "pip")
        assert cmd is not None
        assert cmd.name == "pip"

    def test_get_command_npm(self) -> None:
        """Test getting npm command returns a command."""
        import unittest.mock as mock

        group = ManagerGroup()
        mock_ctx = mock.MagicMock(spec=click.Context)
        cmd = group.get_command(mock_ctx, "npm")
        assert cmd is not None
        assert cmd.name == "npm"

    def test_get_command_all_managers(self) -> None:
        """Test all registered managers are recognized."""
        import unittest.mock as mock

        group = ManagerGroup()
        mock_ctx = mock.MagicMock(spec=click.Context)
        for manager_name in UNIFIED_MANAGER_REGISTRY:
            cmd = group.get_command(mock_ctx, manager_name)
            assert cmd is not None, f"Manager {manager_name} not found"


class TestManagerGroupListCommands:
    """Tests for ManagerGroup.list_commands() override."""

    def test_list_commands_sorts_alphabetically(self) -> None:
        """Commands are returned in alphabetical order."""
        group = ManagerGroup(name="test")
        group.commands = {}
        mock_a = MagicMock(spec=click.Command)
        mock_b = MagicMock(spec=click.Command)
        mock_c = MagicMock(spec=click.Command)
        group.commands = {"zulu": mock_a, "alpha": mock_b, "beta": mock_c}
        ctx = MagicMock()
        result = group.list_commands(ctx)
        assert result == ["alpha", "beta", "zulu"]

    def test_list_commands_empty(self) -> None:
        """Empty group returns an empty list."""
        group = ManagerGroup(name="test")
        group.commands = {}
        ctx = MagicMock()
        result = group.list_commands(ctx)
        assert result == []


class TestManagerGroupGetCommandFuzzyMatch:
    """Tests for fuzzy matching in ManagerGroup.get_command() override."""

    def test_exact_match_returns_command(self) -> None:
        """Exact command name match returns the command."""
        group = ManagerGroup(name="test")
        group.commands = {}
        mock_cmd = MagicMock(spec=click.Command)
        group.commands["install"] = mock_cmd
        ctx = MagicMock()
        result = group.get_command(ctx, "install")
        assert result == mock_cmd

    def test_manager_name_returns_passthrough(self) -> None:
        """Manager name at the top-level group returns a passthrough command."""
        group = ManagerGroup(name="test")
        group.commands = {}
        ctx = MagicMock()
        result = group.get_command(ctx, "pip")
        assert result is not None
        assert result.name == "pip"

    def test_no_match_resilient_returns_none(self) -> None:
        """Resilient parsing returns None for unknown commands."""
        group = ManagerGroup(name="test")
        group.commands = {"install": MagicMock()}
        ctx = MagicMock()
        ctx.resilient_parsing = True
        result = group.get_command(ctx, "nonexistent")
        assert result is None

    def test_no_match_normal_calls_ctx_fail(self) -> None:
        """Normal parsing calls ctx.fail for unknown commands."""
        group = ManagerGroup(name="test")
        group.commands = {"install": MagicMock()}
        ctx = MagicMock()
        ctx.resilient_parsing = False
        group.get_command(ctx, "nonexistent")
        ctx.fail.assert_called_once()


class TestMakeManagerPassthroughCommand:
    """Tests for make_manager_passthrough_command."""

    def test_creates_command(self) -> None:
        """Test function creates a Click command."""
        cmd = make_manager_passthrough_command("pip")
        assert cmd is not None
        assert cmd.name == "pip"

    def test_command_accepts_args(self) -> None:
        """Test created command accepts arbitrary args."""
        cmd = make_manager_passthrough_command("pip")
        # The command should accept variable args (manager_args)
        assert cmd.context_settings.get("allow_extra_args") is True


class TestManagerDispatcher:
    """Tests for ManagerDispatcher."""

    def test_dispatcher_initializes(self) -> None:
        """Test dispatcher initializes correctly."""
        dispatcher = ManagerDispatcher("pip")
        assert dispatcher.manager_name == "pip"
        assert dispatcher.adapter is not None

    def test_dispatcher_unknown_manager_raises(self) -> None:
        """Test unknown manager raises ValueError."""
        with pytest.raises(ValueError, match="Unknown package manager"):
            ManagerDispatcher("unknown-manager")

    def test_dispatcher_has_run_method(self) -> None:
        """Test dispatcher has run method."""
        dispatcher = ManagerDispatcher("pip")
        assert hasattr(dispatcher, "run")
        assert callable(dispatcher.run)


# =============================================================================
# Integration Tests
# =============================================================================


class TestFullParseFlow:
    """Integration tests for the full parse pipeline."""

    def test_pip_full_pipeline(self) -> None:
        """Test full pip parse pipeline."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["install", "requests[security]==2.31.0", "--no-cache-dir", "--dry-run"])

        assert result.manager == "pip"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"
        assert result.packages[0].version == "2.31.0"
        assert result.packages[0].extras == ["security"]

    def test_npm_full_pipeline(self) -> None:
        """Test full npm parse pipeline."""
        adapter = NpmUnifiedAdapter()
        result = adapter.parse(["install", "@types/node@20.0.0", "--save-dev", "-g"])

        assert result.manager == "npm"
        assert result.intent == CommandIntent.INSTALL
        assert result.packages[0].name == "@types/node"
        assert result.packages[0].version == "20.0.0"
        assert result.is_dev_dependency is True
        assert result.is_global is True

    def test_brew_full_pipeline(self) -> None:
        """Test full brew parse pipeline."""
        adapter = BrewUnifiedAdapter()
        result = adapter.parse(["install", "tree", "--verbose"])

        assert result.manager == "brew"
        assert result.intent == CommandIntent.INSTALL
        assert result.packages[0].name == "tree"
        assert result.is_global is True


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_args(self) -> None:
        """Test parsing empty args returns safe passthrough."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse([])

        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_unknown_subcommand(self) -> None:
        """Test unknown subcommand returns safe passthrough."""
        adapter = PyPIUnifiedAdapter()
        result = adapter.parse(["unknown-command", "package"])

        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_invalid_package_name(self) -> None:
        """Test invalid package name is handled gracefully."""
        pkg = parse_python_package("not-a-valid-name!!!")
        # Should still return a PackageRef but with UNKNOWN source
        assert pkg.source == InstallSource.UNKNOWN

    def test_complex_version_constraint(self) -> None:
        """Test complex multi-part version constraint."""
        pkg = parse_python_package("requests>=2.0.0,<3.0.0,!=2.31.0")
        assert pkg.name == "requests"
        assert pkg.version_constraint is not None
        assert ">=" in pkg.version_constraint
        assert "<" in pkg.version_constraint


class TestParseFunctionsEcosystem:
    """Verify parse functions propagate ecosystem to PackageRef."""

    @pytest.mark.parametrize(
        ("parse_fn", "adapter_ecosystem", "package_str", "expected_name"),
        [
            (parse_python_package, "pypi", "requests", "requests"),
            (parse_npm_package, "npm", "express", "express"),
            (parse_brew_package, "homebrew", "tree", "tree"),
            (parse_gem_package, "rubygems", "rails", "rails"),
            (parse_composer_package, "composer", "vendor/pkg", "vendor/pkg"),
            (parse_cargo_package, "cargo", "serde", "serde"),
            (parse_apt_package, "apt", "curl", "curl"),
            (parse_dnf_package, "dnf", "httpd", "httpd"),
            (parse_conda_package, "conda", "numpy", "numpy"),
        ],
    )
    def test_parse_function_propagates_ecosystem(
        self,
        parse_fn: Any,
        adapter_ecosystem: str,
        package_str: str,
        expected_name: str,
    ) -> None:
        """Parse function should propagate ecosystem to PackageRef."""
        # When called WITH ecosystem
        pkg = parse_fn(package_str, ecosystem=adapter_ecosystem)
        assert pkg.ecosystem == adapter_ecosystem
        assert pkg.name == expected_name

        # When called WITHOUT ecosystem (backward compatibility)
        pkg_default = parse_fn(package_str)
        assert pkg_default.ecosystem == ""
        assert pkg_default.name == expected_name

    @pytest.mark.parametrize(
        ("adapter_cls", "subcommand", "package_arg", "ecosystem_expected"),
        [
            (PyPIUnifiedAdapter, "install", "requests", "pypi"),
            (NpmUnifiedAdapter, "install", "express", "npm"),
            (BrewUnifiedAdapter, "install", "tree", "homebrew"),
            (GemUnifiedAdapter, "install", "rails", "rubygems"),
            (ComposerUnifiedAdapter, "install", "vendor/pkg", "composer"),
            (CargoUnifiedAdapter, "install", "serde", "cargo"),
            (AptUnifiedAdapter, "install", "curl", "apt"),
            (DnfUnifiedAdapter, "install", "httpd", "dnf"),
            (CondaUnifiedAdapter, "install", "numpy", "conda"),
            (PipenvUnifiedAdapter, "install", "requests", "pypi"),
            (PoetryUnifiedAdapter, "add", "requests", "pypi"),
            (UvUnifiedAdapter, "add", "requests", "pypi"),
            (BunUnifiedAdapter, "add", "express", "npm"),
            (BundlerUnifiedAdapter, "add", "rails", "rubygems"),
            (PnpmUnifiedAdapter, "add", "express", "npm"),
            (YarnUnifiedAdapter, "add", "lodash", "npm"),
            (YumUnifiedAdapter, "install", "httpd", "yum"),
        ],
    )
    def test_adapter_parse_propagates_ecosystem(
        self,
        adapter_cls: Any,
        subcommand: str,
        package_arg: str,
        ecosystem_expected: str,
    ) -> None:
        """Adapter parse() should propagate self.ecosystem to PackageRef."""
        adapter = adapter_cls()
        result = adapter.parse([subcommand, package_arg])
        assert len(result.packages) >= 1
        assert result.packages[0].ecosystem == ecosystem_expected
        assert result.ecosystem == ecosystem_expected  # ParsedCommand too
