"""Tests for UNIFIED_MANAGER_REGISTRY and get_adapter_class_for_manager()."""

from pkg_defender.registry import (
    UNIFIED_MANAGER_REGISTRY,
    get_adapter_class_for_manager,
)
from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.base import ManagerAdapter, UnifiedRegistryAdapter
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter
from pkg_defender.registry.bun_unified import BunUnifiedAdapter
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter
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


class TestUnifiedManagerRegistry:
    """Verify UNIFIED_MANAGER_REGISTRY contents."""

    def test_has_nineteen_entries(self) -> None:
        """Unified registry must have exactly 19 entries covering all supported managers."""
        assert len(UNIFIED_MANAGER_REGISTRY) == 19

    def test_pip_maps_to_pypi_unified(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["pip"] is PyPIUnifiedAdapter

    def test_pip3_maps_to_pypi_unified(self) -> None:
        """pip3 is an alias that also maps to PyPIUnifiedAdapter."""
        assert UNIFIED_MANAGER_REGISTRY["pip3"] is PyPIUnifiedAdapter

    def test_pipx_maps_to_pypi_unified(self) -> None:
        """pipx now maps to PyPIUnifiedAdapter via the unified registry."""
        assert UNIFIED_MANAGER_REGISTRY["pipx"] is PyPIUnifiedAdapter

    def test_pipenv_maps_to_pipenv_unified(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["pipenv"] is PipenvUnifiedAdapter

    def test_poetry_maps_to_poetry_unified(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["poetry"] is PoetryUnifiedAdapter

    def test_uv_maps_to_uv_unified(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["uv"] is UvUnifiedAdapter

    def test_npm_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["npm"] is NpmUnifiedAdapter

    def test_yarn_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["yarn"] is YarnUnifiedAdapter

    def test_pnpm_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["pnpm"] is PnpmUnifiedAdapter

    def test_bun_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["bun"] is BunUnifiedAdapter

    def test_gem_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["gem"] is GemUnifiedAdapter

    def test_bundler_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["bundler"] is BundlerUnifiedAdapter

    # --- Phase 4: Remaining 7 ecosystems ---

    def test_cargo_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["cargo"] is CargoUnifiedAdapter

    def test_apt_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["apt"] is AptUnifiedAdapter

    def test_brew_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["brew"] is BrewUnifiedAdapter

    def test_composer_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["composer"] is ComposerUnifiedAdapter

    def test_dnf_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["dnf"] is DnfUnifiedAdapter

    def test_yum_registry_entry(self) -> None:
        assert UNIFIED_MANAGER_REGISTRY["yum"] is YumUnifiedAdapter

    def test_all_entries_are_unified_registry_adapter_subclasses(self) -> None:
        """Every entry must be a UnifiedRegistryAdapter subclass."""
        for name, cls in UNIFIED_MANAGER_REGISTRY.items():
            assert issubclass(cls, UnifiedRegistryAdapter), (
                f"{name} -> {cls.__name__} is not a UnifiedRegistryAdapter subclass"
            )

    def test_all_entries_satisfy_manager_adapter_protocol(self) -> None:
        """Every entry must satisfy the ManagerAdapter Protocol."""
        for name, cls in UNIFIED_MANAGER_REGISTRY.items():
            instance = cls()
            assert isinstance(instance, ManagerAdapter), (
                f"{name} -> {cls.__name__} does not satisfy ManagerAdapter Protocol"
            )


class TestGetAdapterClassForManager:
    """Verify get_adapter_class_for_manager() lookup semantics."""

    # --- Unified adapters (PyPI ecosystem) ---

    def test_pip_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("pip")
        assert cls is PyPIUnifiedAdapter

    def test_pip3_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("pip3")
        assert cls is PyPIUnifiedAdapter

    def test_pipx_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("pipx")
        assert cls is PyPIUnifiedAdapter

    def test_pipenv_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("pipenv")
        assert cls is PipenvUnifiedAdapter

    def test_poetry_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("poetry")
        assert cls is PoetryUnifiedAdapter

    def test_uv_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("uv")
        assert cls is UvUnifiedAdapter

    # --- Fallback to MANAGER_REGISTRY (non-PyPI) ---

    def test_npm_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("npm")
        assert cls is NpmUnifiedAdapter

    def test_yarn_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("yarn")
        assert cls is YarnUnifiedAdapter

    def test_pnpm_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("pnpm")
        assert cls is PnpmUnifiedAdapter

    def test_bun_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("bun")
        assert cls is BunUnifiedAdapter

    def test_gem_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("gem")
        assert cls is GemUnifiedAdapter

    def test_bundler_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("bundler")
        assert cls is BundlerUnifiedAdapter

    def test_brew_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("brew")
        assert cls is BrewUnifiedAdapter

    def test_cargo_returns_unified(self) -> None:
        cls = get_adapter_class_for_manager("cargo")
        assert cls is CargoUnifiedAdapter

    def test_yum_returns_unified(self) -> None:
        """yum now has its own unified adapter."""
        cls = get_adapter_class_for_manager("yum")
        assert cls is YumUnifiedAdapter

    # --- Unknown managers ---

    def test_unknown_returns_none(self) -> None:
        cls = get_adapter_class_for_manager("nonexistent-manager-xyz")
        assert cls is None

    # --- Unified adapters have the required interface ---

    def test_unified_adapters_have_parse(self) -> None:
        """Unified adapters must have parse() for dispatcher compatibility."""
        for name in (
            "pip",
            "pip3",
            "pipenv",
            "pipx",
            "poetry",
            "uv",
            "npm",
            "yarn",
            "pnpm",
            "bun",
            "gem",
            "bundler",
            "cargo",
            "apt",
            "brew",
            "composer",
            "conda",
            "dnf",
            "yum",
        ):
            cls = get_adapter_class_for_manager(name)
            assert cls is not None
            adapter = cls()
            assert hasattr(adapter, "parse"), f"{name} adapter missing parse()"
            assert callable(adapter.parse)

    def test_unified_adapters_have_build_exec_args(self) -> None:
        """Unified adapters must have build_exec_args() for exec compatibility."""
        for name in (
            "pip",
            "pip3",
            "pipenv",
            "pipx",
            "poetry",
            "uv",
            "npm",
            "yarn",
            "pnpm",
            "bun",
            "gem",
            "bundler",
            "cargo",
            "apt",
            "brew",
            "composer",
            "conda",
            "dnf",
            "yum",
        ):
            cls = get_adapter_class_for_manager(name)
            assert cls is not None
            adapter = cls()
            assert hasattr(adapter, "build_exec_args"), f"{name} adapter missing build_exec_args()"
            assert callable(adapter.build_exec_args)

    # --- Unified adapters satisfy the Protocol ---

    def test_unified_adapters_satisfy_manager_adapter_protocol(self) -> None:
        """All unified adapters satisfy the ManagerAdapter Protocol."""
        for name, cls in UNIFIED_MANAGER_REGISTRY.items():
            instance = cls()
            assert isinstance(instance, ManagerAdapter), (
                f"{name} -> {cls.__name__} does not satisfy ManagerAdapter Protocol"
            )


class TestUnifiedAdapterParseSmoke:
    """Quick smoke tests: unified adapters can parse commands correctly."""

    def test_pip_parse_install(self) -> None:
        adapter = PyPIUnifiedAdapter()
        parsed = adapter.parse(["install", "requests"])
        assert parsed.manager == "pip"
        assert parsed.intent.name == "INSTALL"
        assert len(parsed.packages) == 1
        assert parsed.packages[0].name == "requests"

    def test_uv_parse_add(self) -> None:
        adapter = UvUnifiedAdapter()
        parsed = adapter.parse(["add", "flask"])
        assert parsed.manager == "uv"
        assert parsed.intent.name == "INSTALL"
        assert len(parsed.packages) == 1
        assert parsed.packages[0].name == "flask"

    def test_poetry_parse_add(self) -> None:
        adapter = PoetryUnifiedAdapter()
        parsed = adapter.parse(["add", "requests"])
        assert parsed.manager == "poetry"
        assert parsed.intent.name == "INSTALL"

    def test_pipenv_parse_install(self) -> None:
        adapter = PipenvUnifiedAdapter()
        parsed = adapter.parse(["install", "requests"])
        assert parsed.manager == "pipenv"
        assert parsed.intent.name == "INSTALL"

    def test_pip_build_exec_args(self) -> None:
        """Verify build_exec_args produces correct output."""
        adapter = PyPIUnifiedAdapter()
        parsed = adapter.parse(["install", "requests"])
        exec_args = adapter.build_exec_args(parsed)
        assert exec_args[0] == "pip"
        assert "install" in exec_args
        assert "requests" in exec_args

    def test_gem_parse_install(self) -> None:
        adapter = GemUnifiedAdapter()
        parsed = adapter.parse(["install", "rails"])
        assert parsed.manager == "gem"
        assert parsed.intent.name == "INSTALL"
        assert len(parsed.packages) == 1
        assert parsed.packages[0].name == "rails"

    def test_bundler_parse_add(self) -> None:
        adapter = BundlerUnifiedAdapter()
        parsed = adapter.parse(["add", "rails"])
        assert parsed.manager == "bundle"
        assert parsed.intent.name == "INSTALL"
        assert len(parsed.packages) == 1
        assert parsed.packages[0].name == "rails"
