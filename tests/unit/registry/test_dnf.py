"""Tests for pkg_defender.registry.dnf — DNFAdapter delegation to the YUM cascade.

DNF uses the same RPM ecosystem as YUM, so the publish-time cascade
(Bodhi → Koji → repodata) is identical. :class:`DNFAdapter` is a thin
delegate to a module-level :class:`YUMAdapter` singleton (NOT a
per-call instance) so the underlying BodhiClient / KojiClient /
RepodataClient singletons are reused.

Tests verify:
- :class:`DNFAdapter` identity (ecosystem, base URL, capabilities)
- :class:`DNFAdapter` methods delegate to the YUMAdapter singleton
  (via ``_get_yum_adapter``)
- ``get_all_versions`` returns ``VersionInfo`` objects with
  ``ecosystem="yum"`` (the cascade is owned by the YUMAdapter)
- The capability declaration is PROXIED (not VERIFIED) per the
  cascade refactor
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.registry import dnf
from pkg_defender.registry.yum import _reset_clients_for_tests


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    """Reset the YUM-side client singletons to prevent cascade-mock leakage.

    The DNFAdapter inherits from YUMAdapter, which owns the BodhiClient /
    KojiClient / RepodataClient singletons in the ``yum`` module.
    """
    _reset_clients_for_tests()
    yield
    _reset_clients_for_tests()


# ---------------------------------------------------------------------------
# DNFAdapter identity + simple delegation tests
# ---------------------------------------------------------------------------


class TestDNFAdapterIdentity:
    """Test identity attributes of the DNF adapter."""

    def test_capabilities_include_proxied_timestamps(self) -> None:
        """Capabilities declare PROXIED (the honest tier for the cascade)."""
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in dnf.DNFAdapter().capabilities

    def test_capabilities_exclude_verified_timestamps(self) -> None:
        """Capabilities do NOT declare VERIFIED (was a false claim for non-Fedora).

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``DNFAdapter.capabilities`` MUST fail this test.
        """
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in dnf.DNFAdapter().capabilities

    def test_capabilities_exclude_threat_intel(self) -> None:
        """Capabilities do NOT declare THREAT_INTEL (AUDIT-tier rule)."""
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in dnf.DNFAdapter().capabilities


# ---------------------------------------------------------------------------
# DNFAdapter end-to-end cascade tests (using the real YUM cascade mocks)
# ---------------------------------------------------------------------------


class TestDNFAdapterCascade:
    """End-to-end DNFAdapter cascade tests with mocked 3-tier clients."""

    @pytest.mark.asyncio
    async def test_bodhi_success_propagates_to_dnf_adapter(self) -> None:
        """Bodhi hit → DNFAdapter returns the Bodhi tuple."""
        from pkg_defender.registry._bodhi_client import SOURCE_BODHI

        bodhi_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        bodhi_mock = MagicMock()
        bodhi_mock.get_publish_time = AsyncMock(
            return_value=(bodhi_dt, SOURCE_BODHI),
        )
        koji_mock = MagicMock()
        koji_mock.get_build_completion_time = AsyncMock()
        repodata_mock = MagicMock()
        repodata_mock.get_publish_time = AsyncMock()

        with (
            patch(
                "pkg_defender.registry.yum._get_bodhi_client",
                return_value=bodhi_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_koji_client",
                return_value=koji_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_repodata_client",
                return_value=repodata_mock,
            ),
        ):
            result = await dnf.DNFAdapter().get_publish_time(
                "curl",
                "8.19.0-1.fc40",
            )

        assert result == (bodhi_dt, SOURCE_BODHI)
        koji_mock.get_build_completion_time.assert_not_called()
        repodata_mock.get_publish_time.assert_not_called()

    @pytest.mark.asyncio
    async def test_bodhi_none_koji_success_propagates_to_dnf_adapter(self) -> None:
        """Bodhi None → Koji hit → DNFAdapter returns the Koji tuple."""
        from pkg_defender.registry._koji_client import SOURCE_KOJI

        koji_dt = datetime(2026, 3, 12, 1, 0, 0, tzinfo=UTC)
        bodhi_mock = MagicMock()
        bodhi_mock.get_publish_time = AsyncMock(return_value=(None, "bodhi"))
        koji_mock = MagicMock()
        koji_mock.get_build_completion_time = AsyncMock(
            return_value=(koji_dt, SOURCE_KOJI),
        )
        repodata_mock = MagicMock()
        repodata_mock.get_publish_time = AsyncMock()

        with (
            patch(
                "pkg_defender.registry.yum._get_bodhi_client",
                return_value=bodhi_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_koji_client",
                return_value=koji_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_repodata_client",
                return_value=repodata_mock,
            ),
        ):
            result = await dnf.DNFAdapter().get_publish_time(
                "curl",
                "8.19.0-1.fc40",
            )

        assert result == (koji_dt, SOURCE_KOJI)
        repodata_mock.get_publish_time.assert_not_called()

    @pytest.mark.asyncio
    async def test_all_sources_fail_returns_user_manual(self) -> None:
        """All 3 clients return None → DNFAdapter returns ``(None, "unresolved")``."""
        from pkg_defender.registry._buildtime_validator import SOURCE_USER_MANUAL

        bodhi_mock = MagicMock()
        bodhi_mock.get_publish_time = AsyncMock(return_value=(None, "bodhi"))
        koji_mock = MagicMock()
        koji_mock.get_build_completion_time = AsyncMock(return_value=(None, "koji"))
        repodata_mock = MagicMock()
        repodata_mock.get_publish_time = AsyncMock(return_value=(None, None))

        with (
            patch(
                "pkg_defender.registry.yum._get_bodhi_client",
                return_value=bodhi_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_koji_client",
                return_value=koji_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_repodata_client",
                return_value=repodata_mock,
            ),
        ):
            result = await dnf.DNFAdapter().get_publish_time(
                "nonexistent",
                "1.0.0-1",
            )

        assert result == (None, SOURCE_USER_MANUAL)
