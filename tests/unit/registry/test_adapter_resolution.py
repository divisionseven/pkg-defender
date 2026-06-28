"""Tests for get_adapter_for_ecosystem()."""

from __future__ import annotations

import pytest

from pkg_defender.registry import RegistryAdapter, get_adapter_for_ecosystem
from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter
from pkg_defender.registry.bun_unified import BunUnifiedAdapter
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter
from pkg_defender.registry.conda_unified import CondaUnifiedAdapter
from pkg_defender.registry.dnf_unified import DnfUnifiedAdapter
from pkg_defender.registry.gem_unified import GemUnifiedAdapter
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.pipenv_unified import PipenvUnifiedAdapter
from pkg_defender.registry.pnpm_unified import PnpmUnifiedAdapter
from pkg_defender.registry.poetry_unified import PoetryUnifiedAdapter
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter
from pkg_defender.registry.uv_unified import UvUnifiedAdapter
from pkg_defender.registry.yarn_unified import YarnUnifiedAdapter
from pkg_defender.registry.yum_unified import YumUnifiedAdapter


class TestGetAdapterForEcosystem:
    """Tests for get_adapter_for_ecosystem()."""

    @pytest.mark.parametrize(
        "ecosystem, expected_type",
        [
            ("pip", PyPIUnifiedAdapter),
            ("pip3", PyPIUnifiedAdapter),
            ("pipenv", PipenvUnifiedAdapter),
            ("pipx", PyPIUnifiedAdapter),
            ("poetry", PoetryUnifiedAdapter),
            ("uv", UvUnifiedAdapter),
            ("bun", BunUnifiedAdapter),
            ("npm", NpmUnifiedAdapter),
            ("pnpm", PnpmUnifiedAdapter),
            ("yarn", YarnUnifiedAdapter),
            ("gem", GemUnifiedAdapter),
            ("bundler", BundlerUnifiedAdapter),
            ("apt", AptUnifiedAdapter),
            ("brew", BrewUnifiedAdapter),
            ("cargo", CargoUnifiedAdapter),
            ("composer", ComposerUnifiedAdapter),
            ("conda", CondaUnifiedAdapter),
            ("dnf", DnfUnifiedAdapter),
            ("yum", YumUnifiedAdapter),
        ],
    )
    def test_direct_key_returns_correct_adapter(
        self,
        ecosystem: str,
        expected_type: type,
    ) -> None:
        """All direct keys in UNIFIED_MANAGER_REGISTRY return correct adapter."""
        adapter = get_adapter_for_ecosystem(ecosystem)
        assert isinstance(adapter, expected_type)

    @pytest.mark.parametrize(
        "alias, expected_type",
        [
            ("pypi", PyPIUnifiedAdapter),
            ("rubygems", GemUnifiedAdapter),
            ("crates", CargoUnifiedAdapter),
            ("homebrew", BrewUnifiedAdapter),
            ("packagist", ComposerUnifiedAdapter),
        ],
    )
    def test_alias_resolves_to_correct_adapter(
        self,
        alias: str,
        expected_type: type,
    ) -> None:
        """All aliases in ECOSYSTEM_ALIAS_MAP resolve to correct adapter."""
        adapter = get_adapter_for_ecosystem(alias)
        assert isinstance(adapter, expected_type)

    @pytest.mark.parametrize(
        "unknown",
        [
            "nuget",
            "",
            "PYPI",
            "NuGet",
            "GO",
            "swift",
        ],
    )
    def test_unknown_ecosystem_returns_none(self, unknown: str) -> None:
        """Unknown ecosystems return None."""
        assert get_adapter_for_ecosystem(unknown) is None

    def test_returns_registry_adapter_type(self) -> None:
        """Return type is RegistryAdapter (not just ManagerAdapter)."""
        adapter = get_adapter_for_ecosystem("pip")
        assert isinstance(adapter, RegistryAdapter)
