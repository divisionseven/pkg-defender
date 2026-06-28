"""Tests for CoverageTier annotation on all 19 unified adapters.

Verifies:
- Base class default is AUDIT (fail-closed).
- Each concrete adapter has the correct tier per the A-008 design.
- Conda moved from AUDIT to FULL (Anaconda API provides verified timestamps).
- AUDIT-tier adapters no longer claim THREAT_INTEL_SUPPORT.
- FULL-tier adapters still include THREAT_INTEL_SUPPORT.
- pip3/pipx (aliased to PyPIUnifiedAdapter) inherit FULL.
- Enum integrity (values, membership).
- YUM/DNF (AUDIT-tier) base + unified adapters declare PROXIED
  (not VERIFIED) per the timestamp-reliability cascade refactor.
- YUM/DNF base adapters do NOT claim THREAT_INTEL_SUPPORT
  (was previously asserted only on the unified adapters).
"""

from __future__ import annotations

import pytest

from pkg_defender.registry.apt_unified import AptUnifiedAdapter
from pkg_defender.registry.base import (
    CoverageTier,
    EcosystemCapability,
    UnifiedRegistryAdapter,
)
from pkg_defender.registry.brew_unified import BrewUnifiedAdapter
from pkg_defender.registry.bun_unified import BunUnifiedAdapter
from pkg_defender.registry.bundler_unified import BundlerUnifiedAdapter
from pkg_defender.registry.cargo_unified import CargoUnifiedAdapter
from pkg_defender.registry.composer_unified import ComposerUnifiedAdapter
from pkg_defender.registry.conda_unified import CondaUnifiedAdapter
from pkg_defender.registry.dnf import DNFAdapter
from pkg_defender.registry.dnf_unified import DnfUnifiedAdapter
from pkg_defender.registry.gem_unified import GemUnifiedAdapter
from pkg_defender.registry.npm_unified import NpmUnifiedAdapter
from pkg_defender.registry.pipenv_unified import PipenvUnifiedAdapter
from pkg_defender.registry.pnpm_unified import PnpmUnifiedAdapter
from pkg_defender.registry.poetry_unified import PoetryUnifiedAdapter
from pkg_defender.registry.pypi_unified import PyPIUnifiedAdapter
from pkg_defender.registry.uv_unified import UvUnifiedAdapter
from pkg_defender.registry.yarn_unified import YarnUnifiedAdapter
from pkg_defender.registry.yum import YUMAdapter
from pkg_defender.registry.yum_unified import YumUnifiedAdapter

# ---------------------------------------------------------------------------
# Enum stability
# ---------------------------------------------------------------------------


class TestCoverageTierEnum:
    """CoverageTier enum values and membership."""

    def test_enum_has_exactly_three_members(self) -> None:
        """CoverageTier must have exactly 3 members — no more, no less."""
        assert len(CoverageTier) == 3

    def test_enum_values_are_strings(self) -> None:
        """All CoverageTier values must be strings (for JSON serialization compat)."""
        assert CoverageTier.FULL.value == "full"
        assert CoverageTier.PARTIAL.value == "partial"
        assert CoverageTier.AUDIT.value == "audit"

    def test_str_returns_value(self) -> None:
        """str(tier) must return the value string."""
        assert str(CoverageTier.FULL) == "full"
        assert str(CoverageTier.PARTIAL) == "partial"
        assert str(CoverageTier.AUDIT) == "audit"

    @pytest.mark.parametrize("tier", [CoverageTier.FULL, CoverageTier.PARTIAL, CoverageTier.AUDIT])
    def test_members_are_enum_instances(self, tier: CoverageTier) -> None:
        """Each member is a CoverageTier instance."""
        assert isinstance(tier, CoverageTier)


# ---------------------------------------------------------------------------
# Base class default
# ---------------------------------------------------------------------------


class TestBaseClassDefault:
    """UnifiedRegistryAdapter default must be AUDIT (fail-closed)."""

    def test_base_default_is_audit(self) -> None:
        """Unannotated adapter defaults to AUDIT (fail-closed on omission)."""
        assert UnifiedRegistryAdapter.coverage_tier == CoverageTier.AUDIT


# ---------------------------------------------------------------------------
# FULL-tier adapters (6 classes)
# ---------------------------------------------------------------------------


class TestFullTierAdapters:
    """FULL-tier adapters must have coverage_tier == CoverageTier.FULL."""

    def test_npm_coverage_tier_is_full(self) -> None:
        assert NpmUnifiedAdapter().coverage_tier == CoverageTier.FULL

    def test_pypi_coverage_tier_is_full(self) -> None:
        assert PyPIUnifiedAdapter().coverage_tier == CoverageTier.FULL

    def test_gem_coverage_tier_is_full(self) -> None:
        assert GemUnifiedAdapter().coverage_tier == CoverageTier.FULL

    def test_cargo_coverage_tier_is_full(self) -> None:
        assert CargoUnifiedAdapter().coverage_tier == CoverageTier.FULL

    def test_composer_coverage_tier_is_full(self) -> None:
        assert ComposerUnifiedAdapter().coverage_tier == CoverageTier.FULL

    def test_conda_coverage_tier_is_full(self) -> None:
        assert CondaUnifiedAdapter().coverage_tier == CoverageTier.FULL

    # FULL-tier adapters still claim THREAT_INTEL_SUPPORT in capabilities

    def test_npm_still_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in NpmUnifiedAdapter().capabilities

    def test_pypi_still_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in PyPIUnifiedAdapter().capabilities

    def test_gem_still_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in GemUnifiedAdapter().capabilities

    def test_cargo_still_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in CargoUnifiedAdapter().capabilities

    def test_composer_still_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in ComposerUnifiedAdapter().capabilities

    def test_conda_has_threat_intel(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in CondaUnifiedAdapter().capabilities


# ---------------------------------------------------------------------------
# PARTIAL-tier adapters (8 classes)
# ---------------------------------------------------------------------------


class TestPartialTierAdapters:
    """PARTIAL-tier adapters must have coverage_tier == CoverageTier.PARTIAL."""

    def test_brew_coverage_tier_is_partial(self) -> None:
        """Brew upgraded to PARTIAL after adding GitHub Releases API timestamps."""
        adapter = BrewUnifiedAdapter()
        assert adapter.coverage_tier == CoverageTier.PARTIAL

    def test_brew_has_threat_intel(self) -> None:
        """PARTIAL-tier adapters must declare THREAT_INTEL_SUPPORT."""
        adapter = BrewUnifiedAdapter()
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in adapter.capabilities

    def test_bun_coverage_tier_is_partial(self) -> None:
        assert BunUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_pnpm_coverage_tier_is_partial(self) -> None:
        assert PnpmUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_yarn_coverage_tier_is_partial(self) -> None:
        assert YarnUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_pipenv_coverage_tier_is_partial(self) -> None:
        assert PipenvUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_poetry_coverage_tier_is_partial(self) -> None:
        assert PoetryUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_uv_coverage_tier_is_partial(self) -> None:
        assert UvUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL

    def test_bundler_coverage_tier_is_partial(self) -> None:
        assert BundlerUnifiedAdapter().coverage_tier == CoverageTier.PARTIAL


# ---------------------------------------------------------------------------
# AUDIT-tier adapters (3 classes)
# ---------------------------------------------------------------------------


class TestAuditTierAdapters:
    """AUDIT-tier adapters must have coverage_tier == CoverageTier.AUDIT."""

    def test_apt_coverage_tier_is_audit(self) -> None:
        assert AptUnifiedAdapter().coverage_tier == CoverageTier.AUDIT

    def test_dnf_coverage_tier_is_audit(self) -> None:
        assert DnfUnifiedAdapter().coverage_tier == CoverageTier.AUDIT

    def test_yum_coverage_tier_is_audit(self) -> None:
        assert YumUnifiedAdapter().coverage_tier == CoverageTier.AUDIT

    # AUDIT-tier adapters must NOT have THREAT_INTEL_SUPPORT in capabilities
    # (unified adapters)

    def test_apt_threat_intel_removed(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in AptUnifiedAdapter().capabilities

    def test_dnf_threat_intel_removed(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in DnfUnifiedAdapter().capabilities

    def test_yum_threat_intel_removed(self) -> None:
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in YumUnifiedAdapter().capabilities


# ---------------------------------------------------------------------------
# pip3 / pipx alias inheritance
# ---------------------------------------------------------------------------


class TestPipAliasInheritance:
    """pip3 is mapped to PyPIUnifiedAdapter — inherits FULL tier."""

    def test_pip3_resolves_to_pypi_full(self) -> None:
        """pip3 uses the same adapter class as pip, which is FULL."""
        from pkg_defender.registry import get_adapter_class_for_manager

        cls = get_adapter_class_for_manager("pip3")
        assert cls is not None
        assert cls.coverage_tier == CoverageTier.FULL

    def test_pipx_resolves_to_pypi_full(self) -> None:
        """pipx maps to PyPIUnifiedAdapter (FULL tier) via get_adapter_class_for_manager."""
        from pkg_defender.registry import get_adapter_class_for_manager

        cls = get_adapter_class_for_manager("pipx")
        assert cls is not None
        assert cls is PyPIUnifiedAdapter
        assert cls.coverage_tier == CoverageTier.FULL


# ---------------------------------------------------------------------------
# YUM/DNF capability assertions (Phase 2 of timestamp-reliability overhaul)
# ---------------------------------------------------------------------------


class TestYumDnfCapabilities:
    """Verify YUM/DNF capabilities are PROXIED (not VERIFIED) per the cascade.

    The legacy ``VERIFIED_PUBLISH_TIMESTAMPS`` claim was only true for
    Fedora+EPEL packages via Bodhi. The new cascade falls through to
    repodata ``<time file>`` for all 11 RPM distros, which is a
    *proxied* timestamp — not cryptographically attested. Per
    ``EcosystemCapability`` semantics, the capability must reflect the
    honest tier (PROXIED). VERIFIED is excluded because it's false
    advertising for non-Fedora distros. THREAT_INTEL is excluded
    because the AUDIT-tier rule prohibits it (existing test asserts
    this for the unified adapters; this test class extends coverage
    to the base adapters as well).
    """

    def test_yum_unified_capabilities_include_proxied(self) -> None:
        """YumUnifiedAdapter declares PROXIED_PUBLISH_TIMESTAMPS."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in YumUnifiedAdapter().capabilities

    def test_dnf_unified_capabilities_include_proxied(self) -> None:
        """DnfUnifiedAdapter declares PROXIED_PUBLISH_TIMESTAMPS."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in DnfUnifiedAdapter().capabilities

    def test_yum_unified_capabilities_exclude_verified(self) -> None:
        """YumUnifiedAdapter does NOT declare VERIFIED_PUBLISH_TIMESTAMPS.

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``YumUnifiedAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in YumUnifiedAdapter().capabilities

    def test_dnf_unified_capabilities_exclude_verified(self) -> None:
        """DnfUnifiedAdapter does NOT declare VERIFIED_PUBLISH_TIMESTAMPS.

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``DnfUnifiedAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in DnfUnifiedAdapter().capabilities

    def test_yum_base_adapter_capabilities_include_proxied(self) -> None:
        """YUMAdapter (base) declares PROXIED_PUBLISH_TIMESTAMPS."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in YUMAdapter().capabilities

    def test_dnf_base_adapter_capabilities_include_proxied(self) -> None:
        """DNFAdapter (base) declares PROXIED_PUBLISH_TIMESTAMPS."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in DNFAdapter().capabilities

    def test_yum_base_adapter_capabilities_exclude_verified(self) -> None:
        """YUMAdapter (base) does NOT declare VERIFIED_PUBLISH_TIMESTAMPS.

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``YUMAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in YUMAdapter().capabilities

    def test_dnf_base_adapter_capabilities_exclude_verified(self) -> None:
        """DNFAdapter (base) does NOT declare VERIFIED_PUBLISH_TIMESTAMPS.

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``DNFAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in DNFAdapter().capabilities


# ---------------------------------------------------------------------------
# YUM/DNF base-adapter THREAT_INTEL assertion (Phase 2 — fills test gap)
# ---------------------------------------------------------------------------


class TestYumDnfBaseAdapterThreatIntelRemoved:
    """Base ``YUMAdapter``/``DNFAdapter`` MUST NOT advertise THREAT_INTEL_SUPPORT.

    The pre-existing ``test_dnf_threat_intel_removed`` /
    ``test_yum_threat_intel_removed`` tests in
    :class:`TestAuditTierAdapters` cover only the *unified* adapters.
    The base ``YUMAdapter``/``DNFAdapter`` classes were previously
    unaffected by any test — the cascade refactor fixes this gap by
    aligning the base capabilities with the unified ones (PROXIED
    only, no THREAT_INTEL).
    """

    def test_yum_base_adapter_threat_intel_removed(self) -> None:
        """``YUMAdapter().capabilities`` does NOT include ``THREAT_INTEL_SUPPORT``.

        MUTATION CONTRACT: re-adding ``THREAT_INTEL_SUPPORT`` to
        ``YUMAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in YUMAdapter().capabilities

    def test_dnf_base_adapter_threat_intel_removed(self) -> None:
        """``DNFAdapter().capabilities`` does NOT include ``THREAT_INTEL_SUPPORT``.

        MUTATION CONTRACT: re-adding ``THREAT_INTEL_SUPPORT`` to
        ``DNFAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in DNFAdapter().capabilities
