"""DNF registry adapter — YUM alias (DNF is a fork of YUM, same RPM ecosystem).

DNFAdapter inherits from YUMAdapter — the publish-time cascade
(Bodhi → Koji → repodata) and all RPM database queries are identical.
The identity is in the ``ecosystem`` and ``registry_base_url`` properties.

Standalone convenience functions have been removed — unified adapters now
use class composition with YUMAdapter directly.
"""

from __future__ import annotations

from typing import ClassVar

from pkg_defender.registry.base import EcosystemCapability, ManagerConfig
from pkg_defender.registry.yum import (  # noqa: F401
    YUMAdapter,
    dnf_get_installed_version,
    yum_get_installed_version,
)


class DNFAdapter(YUMAdapter):
    """Adapter for DNF package repositories (YUM alias).

    DNF is a fork of YUM with the same RPM ecosystem. This adapter
    inherits the full Bodhi → Koji → repodata cascade from
    :class:`YUMAdapter`. The only differences are the ``ecosystem``
    and ``registry_base_url`` identity properties.
    """

    ecosystem: str = "dnf"
    registry_base_url: str = "local://dnf"

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="dnf",
        registry_url="local://dnf",
        capabilities=[EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS],
    )
