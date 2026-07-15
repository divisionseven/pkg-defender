# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Registry adapter layer — unified adapters only."""

from typing import cast

from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.base import (
    CoverageTier,
    EcosystemCapability,
    ManagerAdapter,
    PipelineAdapter,
    RegistryAdapter,
    UnifiedRegistryAdapter,
)
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter
from pkg_defender.registry.bun_unified import BunUnifiedAdapter
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter
from pkg_defender.registry.conda_unified import CondaUnifiedAdapter
from pkg_defender.registry.dnf_unified import DnfUnifiedAdapter
from pkg_defender.registry.flags import (
    APT_VALUE_FLAGS,
    BREW_VALUE_FLAGS,
    BUN_VALUE_FLAGS,
    BUNDLER_VALUE_FLAGS,
    CARGO_VALUE_FLAGS,
    COMPOSER_VALUE_FLAGS,
    CONDA_VALUE_FLAGS,
    DNF_VALUE_FLAGS,
    GEM_VALUE_FLAGS,
    NPM_VALUE_FLAGS,
    PIP_VALUE_FLAGS,
    PIPENV_VALUE_FLAGS,
    PNPM_VALUE_FLAGS,
    POETRY_VALUE_FLAGS,
    UV_VALUE_FLAGS,
    YARN_VALUE_FLAGS,
)
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

__all__ = [
    "AptUnifiedAdapter",
    "APT_VALUE_FLAGS",
    "BrewUnifiedAdapter",
    "BREW_VALUE_FLAGS",
    "BunUnifiedAdapter",
    "BUN_VALUE_FLAGS",
    "BundlerUnifiedAdapter",
    "BUNDLER_VALUE_FLAGS",
    "CargoUnifiedAdapter",
    "CARGO_VALUE_FLAGS",
    "ComposerUnifiedAdapter",
    "COMPOSER_VALUE_FLAGS",
    "CondaUnifiedAdapter",
    "CONDA_VALUE_FLAGS",
    "CoverageTier",
    "DnfUnifiedAdapter",
    "DNF_VALUE_FLAGS",
    "EcosystemCapability",
    "ECOSYSTEM_ALIAS_MAP",
    "GemUnifiedAdapter",
    "GEM_VALUE_FLAGS",
    "NpmUnifiedAdapter",
    "NPM_VALUE_FLAGS",
    "PipenvUnifiedAdapter",
    "PIPENV_VALUE_FLAGS",
    "PnpmUnifiedAdapter",
    "PNPM_VALUE_FLAGS",
    "PoetryUnifiedAdapter",
    "POETRY_VALUE_FLAGS",
    "PyPIUnifiedAdapter",
    "PIP_VALUE_FLAGS",
    "RegistryAdapter",
    "UvUnifiedAdapter",
    "UV_VALUE_FLAGS",
    "UnifiedRegistryAdapter",
    "YarnUnifiedAdapter",
    "YARN_VALUE_FLAGS",
    "YumUnifiedAdapter",
    "ManagerAdapter",
    "PipelineAdapter",
    "UNIFIED_MANAGER_REGISTRY",
    "get_adapter_class_for_manager",
    "get_adapter_for_ecosystem",
    "get_pipeline_adapter",
    "parse_apt_package",
    "parse_brew_package",
    "parse_cargo_package",
    "parse_composer_package",
    "parse_conda_package",
    "parse_dnf_package",
    "parse_gem_package",
    "parse_npm_package",
    "parse_python_package",
]

ECOSYSTEM_ALIAS_MAP: dict[str, str] = {
    "pypi": "pip",
    "rubygems": "gem",
    "crates": "cargo",
    "homebrew": "brew",
    "packagist": "composer",
}


def get_adapter_for_ecosystem(ecosystem: str) -> RegistryAdapter | None:
    """Return a registry adapter instance for the given ecosystem.

    Supports both manager-style keys (e.g. "pip", "npm", "gem")
    and ecosystem-style keys (e.g. "pypi", "rubygems", "crates",
    "packagist") via ECOSYSTEM_ALIAS_MAP normalization.

    Args:
        ecosystem: Ecosystem or manager name (e.g. ``"pip"``, ``"pypi"``, ``"npm"``).

    Returns:
        A RegistryAdapter instance, or None if the ecosystem is not supported.
    """
    adapter_cls = UNIFIED_MANAGER_REGISTRY.get(ecosystem)
    if adapter_cls is not None:
        return cast(RegistryAdapter, adapter_cls())

    manager_key = ECOSYSTEM_ALIAS_MAP.get(ecosystem)
    if manager_key is not None:
        adapter_cls = UNIFIED_MANAGER_REGISTRY.get(manager_key)
        if adapter_cls is not None:
            return cast(RegistryAdapter, adapter_cls())

    return None


# Unified adapter registry: CLI manager name -> unified adapter class.
# Contains all unified adapters covering every supported package manager.
# Consumers should use get_adapter_class_for_manager() for lookups.
UNIFIED_MANAGER_REGISTRY: dict[str, type[ManagerAdapter]] = {
    "pip": PyPIUnifiedAdapter,
    "pip3": PyPIUnifiedAdapter,
    "pipenv": PipenvUnifiedAdapter,
    "pipx": PyPIUnifiedAdapter,
    "poetry": PoetryUnifiedAdapter,
    "uv": UvUnifiedAdapter,
    # --- npm ecosystem ---
    "bun": BunUnifiedAdapter,
    "npm": NpmUnifiedAdapter,
    "pnpm": PnpmUnifiedAdapter,
    "yarn": YarnUnifiedAdapter,
    # --- RubyGems ecosystem ---
    "gem": GemUnifiedAdapter,
    "bundler": BundlerUnifiedAdapter,
    # --- Remaining ecosystems ---
    "apt": AptUnifiedAdapter,
    "brew": BrewUnifiedAdapter,
    "cargo": CargoUnifiedAdapter,
    "composer": ComposerUnifiedAdapter,
    "conda": CondaUnifiedAdapter,
    "dnf": DnfUnifiedAdapter,
    "yum": YumUnifiedAdapter,
}


def get_adapter_class_for_manager(
    manager_name: str,
) -> type[ManagerAdapter] | None:
    """Return the adapter class for a manager name, preferring unified adapters.

    Lookup order:
    1. UNIFIED_MANAGER_REGISTRY — all 19 unified adapters that provide
       both registry and manager interfaces

    Args:
        manager_name: CLI manager name (e.g., "pip", "npm", "brew").

    Returns:
        Adapter class for the manager, or None if not found.
    """
    unified_cls = UNIFIED_MANAGER_REGISTRY.get(manager_name)
    if unified_cls is not None:
        return unified_cls

    return None


def get_pipeline_adapter(ecosystem: str) -> PipelineAdapter | None:
    """Return a pipeline-compatible adapter for the given ecosystem.

    Normalizes ecosystem-style keys (e.g. "pypi") to manager-style
    keys (e.g. "pip") via ECOSYSTEM_ALIAS_MAP, then looks up the
    adapter in UNIFIED_MANAGER_REGISTRY.

    Args:
        ecosystem: Ecosystem or manager name (e.g. "pip", "pypi", "npm").

    Returns:
        A PipelineAdapter instance, or None if the ecosystem is not
        supported. The adapter's ``ecosystem`` property returns the
        originally-requested key.
    """
    import logging

    logger = logging.getLogger(__name__)

    key = ECOSYSTEM_ALIAS_MAP.get(ecosystem, ecosystem)

    unified_cls = UNIFIED_MANAGER_REGISTRY.get(key)
    if unified_cls is not None:
        return PipelineAdapter(cast(type[RegistryAdapter], unified_cls)(), requested_ecosystem=ecosystem)

    logger.debug(
        "get_pipeline_adapter(%r): no adapter found after alias resolution (key=%r).",
        ecosystem,
        key,
    )
    return None
