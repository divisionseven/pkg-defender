"""YUM/DNF registry adapter — package version queries via dnf repoquery + Bodhi/Koji/repodata publish-time cascade.

The publish-time cascade delegates to three specialized clients (Phase 0 modules):

    1. :class:`pkg_defender.registry._bodhi_client.BodhiClient` — Fedora/EPEL
       updates ``date_pushed`` (preferred) or ``date_submitted`` (fallback).
    2. :class:`pkg_defender.registry._koji_client.KojiClient` — Koji
       ``getBuild(nvr)`` ``completion_time`` as a tiebreaker when Bodhi has
       no record.
    3. :class:`pkg_defender.registry._repodata_client.RepodataClient` — YUM
       repodata ``<time file>`` as a universal fallback across 11 RPM distros.

After the repodata step the result is passed through
:func:`pkg_defender.registry._buildtime_validator.detect_clamping` to demote
``proxied`` → ``none`` when the BUILDTIME looks clamped (Fedora 43+
reproducible-builds artifact, pagure.io/fesco/issue/2899).

Frozen-snapshot repodata URLs (openEuler 22.03 LTS) are rejected outright by
the cascade — see :data:`_FROZEN_SNAPSHOT_REPODATA_URLS`.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import ClassVar

import aiohttp

from pkg_defender.config import get_max_retries
from pkg_defender.models import VersionInfo
from pkg_defender.registry._bodhi_client import SOURCE_BODHI, BodhiClient
from pkg_defender.registry._buildtime_validator import (
    SOURCE_USER_MANUAL,
    detect_clamping,
)
from pkg_defender.registry._koji_client import SOURCE_KOJI, KojiClient
from pkg_defender.registry._repodata_client import SOURCE_REPODATA, RepodataClient
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

logger = logging.getLogger(__name__)

# Default repodata URLs (11 distros verified by YUM-001 §6.1). The cascade
# walks them in order via :class:`RepodataClient`. Each URL is validated
# lazily on first use (NOT at module import) by the client itself.
_DEFAULT_REPODATA_URLS: tuple[str, ...] = (
    # Fedora (Bodhi + Koji + repodata available) — YUM-001 §2.3
    "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os",
    # EPEL (Bodhi + repodata available) — YUM-001 §2.3
    "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64",
    # RHEL clones (repodata only) — YUM-001 §2.3
    "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os",
    "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os",
    "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os",
    # Oracle 9 — YUM-001 §2.3
    "https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64",
    # openEuler (frozen snapshot — cascade rejects via
    # :data:`_FROZEN_SNAPSHOT_REPODATA_URLS`, but URL kept for forward
    # compat) — YUM-001 §2.3 (line 343)
    "https://repo.openeuler.org/openEuler-22.03-LTS/OS/x86_64",
    # Mageia — YUM-001 §2.3 (line 363)
    "https://mirrors.kernel.org/mageia/distrib/9/x86_64/media/core/release",
    # openSUSE Tumbleweed — YUM-001 §2.3
    "https://download.opensuse.org/tumbleweed/repo/oss",
    # RPM Fusion free (EL9) — YUM-001 §2.3 (line 400)
    "https://download1.rpmfusion.org/free/el/updates/9/x86_64",
    # Amazon Linux 2 — YUM-001 §6.5 (line 790-792)
    "https://cdn.amazonlinux.com/2/core/2.0/x86_64/793d6c328e20f10fdc29a8f88d8488406da73e29f40b3912f49fbe03947df76a",
)

# Frozen-snapshot repodata URLs (Q7): these URLs are kept in
# :data:`_DEFAULT_REPODATA_URLS` for forward-compat, but the cascade
# REJECTS their matches because ``<time file>`` returns the same value
# for every package in the repo (the snapshot's rebuild time, not a
# per-package timestamp).
_FROZEN_SNAPSHOT_REPODATA_URLS: frozenset[str] = frozenset(
    {
        # openEuler 22.03 LTS — frozen snapshot since 2023
        # (downloads.atom RSS is frozen, ``<time file>`` is the repo rebuild time)
        "https://repo.openeuler.org/openEuler-22.03-LTS/OS/x86_64",
    }
)

# Module-level client singletons (shared across all YUMAdapter instances).
# Avoids re-instantiating clients per get_publish_time call (was wasteful:
# each call created a new RepodataClient with 11 URLs, walked all 11,
# and re-validated URLs that had already been validated in this process).
# The aiohttp session is created lazily on first use.
_bodhi_client: BodhiClient | None = None
_koji_client: KojiClient | None = None
_repodata_client: RepodataClient | None = None

# Module-level YUMAdapter singleton. Reused by both the YUMAdapter class
# methods (via the standalone module-level ``get_publish_time`` etc.)
# AND the DNFAdapter (via :func:`pkg_defender.registry.dnf._get_yum_adapter`).
_yum_adapter: YUMAdapter | None = None


def _get_bodhi_client(session: aiohttp.ClientSession | None = None) -> BodhiClient:
    """Return the module-level BodhiClient singleton, creating it on first use.

    A new client is created per process unless an explicit session is passed
    in (in which case a one-off client is returned, since the session is
    owned by the caller and we cannot share the singleton's lifecycle with
    it).
    """
    global _bodhi_client
    if session is not None:
        return BodhiClient(session=session)
    if _bodhi_client is None:
        _bodhi_client = BodhiClient()
    return _bodhi_client


def _get_koji_client(session: aiohttp.ClientSession | None = None) -> KojiClient:
    """Return the module-level KojiClient singleton, creating it on first use."""
    global _koji_client
    if session is not None:
        return KojiClient(session=session)
    if _koji_client is None:
        _koji_client = KojiClient()
    return _koji_client


def _get_repodata_client(session: aiohttp.ClientSession | None = None) -> RepodataClient:
    """Return the module-level RepodataClient singleton, creating it on first use."""
    global _repodata_client
    if session is not None:
        return RepodataClient(session=session)
    if _repodata_client is None:
        _repodata_client = RepodataClient()
    return _repodata_client


def _get_yum_adapter() -> YUMAdapter:
    """Return the module-level YUMAdapter singleton, creating it on first use.

    The YUMAdapter owns the cascade via :func:`_get_bodhi_client`,
    :func:`_get_koji_client`, and :func:`_get_repodata_client` — the
    adapter itself holds no per-call state, so a single shared instance
    is sufficient and avoids re-instantiation.
    """
    global _yum_adapter
    if _yum_adapter is None:
        _yum_adapter = YUMAdapter()
    return _yum_adapter


def _reset_clients_for_tests() -> None:
    """Reset module-level singletons. **Test-only — DO NOT call from production code.**"""
    global _bodhi_client, _koji_client, _repodata_client, _yum_adapter
    _bodhi_client = None
    _koji_client = None
    _repodata_client = None
    _yum_adapter = None


# Security constants
TIMEOUT_SECONDS = 30


async def _run_dnf_command(args: list[str]) -> str | None:
    """Run a dnf command and return stdout, or None on failure.

    Uses asyncio.create_subprocess_exec with list form (not shell=True)
    for security. Implements fail-closed behavior: returns None on any
    error.

    Args:
        args: Command arguments (e.g., ['dnf', 'repoquery', ...]).

    Returns:
        stdout as string, or None if command fails or times out.
    """
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        proc: asyncio.subprocess.Process | None = None
        stdout_bytes: bytes | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()
            if attempt == _max_retries - 1:
                return None
            continue
        except FileNotFoundError:
            # dnf not installed - fail closed
            logger.warning("dnf command not found - is DNF installed?")
            return None
        except OSError as e:
            logger.warning(
                "OS error running dnf command (attempt %d/%d): %s",
                attempt + 1,
                _max_retries,
                e,
            )
            if attempt == _max_retries - 1:
                return None
            continue

        if proc is not None and proc.returncode == 0:
            assert stdout_bytes is not None
            return stdout_bytes.decode().strip()
        # Package not found or other error - fail closed
        return None
    return None


async def _run_yum_command(args: list[str]) -> str | None:
    """Run a yum command and return stdout, or None on failure.

    Fallback for systems with yum but not dnf.

    Args:
        args: Command arguments (e.g., ['yum', 'list', ...]).

    Returns:
        stdout as string, or None if command fails or times out.
    """
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        proc: asyncio.subprocess.Process | None = None
        stdout_bytes: bytes | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()
            if attempt == _max_retries - 1:
                return None
            continue
        except FileNotFoundError:
            logger.warning("yum command not found - is YUM installed?")
            return None
        except OSError as e:
            logger.warning(
                "OS error running yum command (attempt %d/%d): %s",
                attempt + 1,
                _max_retries,
                e,
            )
            if attempt == _max_retries - 1:
                return None
            continue

        if proc is not None and proc.returncode == 0:
            assert stdout_bytes is not None
            return stdout_bytes.decode().strip()
        return None
    return None


async def _dnf_get_latest_version(package: str) -> str | None:
    """Get the latest version of a package using dnf repoquery.

    Args:
        package: Package name.

    Returns:
        Latest version string, or None if not found.
    """
    # Try dnf first
    output = await _run_dnf_command(
        [
            "dnf",
            "repoquery",
            "--latest",
            "--available",
            "--queryformat",
            "%{VERSION}-%{RELEASE}",
            package,
        ]
    )
    if output:
        return output

    # Fallback to yum
    output = await _run_yum_command(
        [
            "yum",
            "list",
            "available",
            package,
        ]
    )
    if output:
        # Parse yum output - typically format: package.name.arch    version-repo
        lines = output.split("\n")
        for line in lines:
            if line.startswith(package):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].rsplit(".", 1)[0]  # Remove arch suffix

    return None


async def _dnf_get_all_versions(package: str) -> list[str]:
    """Get all available versions of a package.

    Note: dnf repoquery can return multiple versions but format varies.
    This implementation returns the single latest version as a fallback
    since historical version tracking in YUM/DNF is limited.

    Args:
        package: Package name.

    Returns:
        List of version strings, or empty list if not found.
    """
    # Try dnf first
    output = await _run_dnf_command(
        [
            "dnf",
            "repoquery",
            "--all",
            "--queryformat",
            "%{VERSION}-%{RELEASE}",
            package,
        ]
    )
    if output:
        versions = [v for v in output.split("\n") if v]
        # Deduplicate while preserving order
        seen = set()
        unique_versions = []
        for v in versions:
            if v not in seen:
                seen.add(v)
                unique_versions.append(v)
        return unique_versions

    # Fallback to yum
    output = await _run_yum_command(
        [
            "yum",
            "list",
            "all",
            package,
        ]
    )
    if output:
        versions = []
        for line in output.split("\n"):
            if line.startswith(package):
                parts = line.split()
                if len(parts) >= 2:
                    versions.append(parts[1].rsplit(".", 1)[0])
        return versions

    return []


class YUMAdapter(RegistryAdapter):
    """Adapter for YUM/DNF package repositories.

    Publish-time resolution follows a 3-tier cascade (Bodhi → Koji →
    repodata) with two extra protections:

    * **Frozen-snapshot rejection** (Q7): repodata matches from URLs in
      :data:`_FROZEN_SNAPSHOT_REPODATA_URLS` (openEuler 22.03 LTS) are
      rejected and the cascade returns
      ``(None, SOURCE_USER_MANUAL)``.
    * **BUILDTIME clamping detection** (C2): repodata matches that look
      clamped (same epoch-second value appears N>5 times from the same
      source in the current build window — a Fedora 43+ reproducible-
      builds artifact) are demoted to ``(None, SOURCE_USER_MANUAL)`` so
      the STORED tier is demoted from ``"proxied"`` to ``"none"``.

    **RHEL rejection is "by accident", not by design:** RHEL's package
    URLs are not in :data:`_DEFAULT_REPODATA_URLS` (Q8) AND
    ``koji.fedoraproject.org`` has no RHEL builds AND
    ``bodhi.fedoraproject.org`` only tracks Fedora/EPEL. So for an RHEL
    package, all three sources return ``None`` and the cascade falls
    through to ``return None, SOURCE_USER_MANUAL`` at the bottom. This
    is the correct behavior, but it is the absence of a code path, not
    a dedicated rejection branch. Documenting this here so future
    engineers don't "fix" it by adding RHEL support.
    """

    ecosystem: str = "yum"
    registry_base_url: str = "local://yum"

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="yum",
        registry_url="local://yum",
        capabilities=[EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS],
    )

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Return the publish time for *package* at *version*.

        Cascade (per BC-1 through BC-10):

            1. Bodhi ``date_pushed`` (preferred) or ``date_submitted`` —
               verified.
            2. Koji ``completion_time`` — verified (but build time, not
               push time).
            3. repodata ``<time file>`` — proxied (universal fallback).
            4. ``(None, SOURCE_USER_MANUAL)`` — no source available.

        After the repodata step, the result is passed through
        :func:`pkg_defender.registry._buildtime_validator.detect_clamping`.
        If the BUILDTIME looks clamped (N>5 packages sharing the same
        value in the same build window), the cascade returns
        ``(None, SOURCE_USER_MANUAL)`` — which ``schema.py`` maps to
        ``timestamp_type="none"`` at insert time, so the STORED tier is
        demoted from ``"proxied"`` to ``"none"`` (per BC-10).

        Args:
            package: Package name (e.g., ``"curl"``).
            version: Exact NVR (e.g., ``"8.21.0~rc1-1.fc45"``).
            session: Optional ``aiohttp`` session for connection pooling.

        Returns:
            Tuple of (timezone-aware datetime or ``None``, source
            string). Source is one of:
            ``SOURCE_BODHI``, ``SOURCE_KOJI``, ``SOURCE_REPODATA``,
            ``SOURCE_USER_MANUAL``. Never raises.
        """
        # Tier 1: Bodhi (VERIFIED).
        bodhi = _get_bodhi_client(session)
        bodhi_time, _bodhi_source = await bodhi.get_publish_time(package, version)
        if bodhi_time is not None:
            # ``_bodhi_source`` is the BodhiClient's return value
            # (always ``SOURCE_BODHI`` per the client contract) — we
            # use the constant directly so the cascade's return
            # contract is auditable here. See constraint #10
            # (no free-form source strings).
            return bodhi_time, SOURCE_BODHI

        # Tier 2: Koji (VERIFIED).
        koji = _get_koji_client(session)
        koji_time, _koji_source = await koji.get_build_completion_time(version)
        if koji_time is not None:
            return koji_time, SOURCE_KOJI

        # Tier 3: repodata (PROXIED).
        repodata = _get_repodata_client(session)
        # RepodataClient returns ``(dt, matched_url)`` — NOT a source
        # string. The cascade is the source of the public "repodata"
        # string per BC-8. ``matched_url`` is needed for per-URL
        # rejection (openEuler per Q7) AND for the per-URL validator
        # source key (per-URL clamping detection per Constraint C2).
        repodata_time, matched_url = await repodata.get_publish_time(package, version)
        if repodata_time is not None:
            # Per Q7: reject frozen-snapshot repos where ``<time file>``
            # returns the rebuild time of the entire repo (not a
            # per-package timestamp). Returning a wrong-but-valid
            # datetime would silently deceive the cooldown check.
            if matched_url is not None and matched_url in _FROZEN_SNAPSHOT_REPODATA_URLS:
                logger.debug(
                    "yum: frozen-snapshot repo rejected for %s %s (url=%s), returning NO_PUBLISH_TIMESTAMPS",
                    package,
                    version,
                    matched_url,
                )
                return None, SOURCE_USER_MANUAL

            # Per Constraint C2: demote to SOURCE_USER_MANUAL if
            # BUILDTIME looks clamped. The validator buckets BUILDTIMEs
            # by (source, hour) and flags windows where N>5 packages
            # share the same BUILDTIME. Use the per-URL matched_url as
            # the bucket key so we can detect per-repo clamping
            # artifacts. If matched_url is None (shouldn't happen when
            # repodata_time is set, but defensive), fall back to a
            # sentinel.
            if detect_clamping(
                buildtime=repodata_time,
                source=matched_url or "repodata:unknown",
                package=package,
                version=version,
            ):
                logger.debug(
                    "yum: BUILDTIME clamping detected for %s %s, demoting to 'unresolved'",
                    package,
                    version,
                )
                return None, SOURCE_USER_MANUAL
            return repodata_time, SOURCE_REPODATA

        # Fall through: no source found.
        return None, SOURCE_USER_MANUAL

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Return all available versions for *package*.

        Per BC-5: ``publish_time`` is the result of the per-version
        :meth:`get_publish_time` cascade. Returns ``None`` for versions
        that cannot be resolved (instead of the previous
        ``datetime.now(UTC)`` placeholder that deceived consumers into
        thinking every YUM/DNF version had a real publish timestamp).

        Args:
            package: Package name.
            session: Optional ``aiohttp`` session forwarded to the
                cascade.

        Returns:
            List of :class:`VersionInfo`, sorted in the order returned
            by :func:`_dnf_get_all_versions` (typically version
            descending). ``publish_time`` is ``None`` when no source
            could resolve the version; ``date_source`` mirrors the
            cascade's source string.
        """
        raw_versions = await _dnf_get_all_versions(package)
        results: list[VersionInfo] = []
        for version_str in raw_versions:
            dt, source = await self.get_publish_time(package, version_str, session)
            results.append(
                VersionInfo(
                    ecosystem="yum",
                    package_name=package,
                    version=version_str,
                    publish_time=dt,  # may be None
                    date_source=source,  # may be SOURCE_USER_MANUAL
                )
            )
        return results

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Return the latest version of *package*.

        Args:
            package: Package name.
            session: Unused (included for interface compatibility).

        Returns:
            Latest version string, or None if not found.
        """
        return await _dnf_get_latest_version(package)

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await yum_get_installed_version(package)


async def yum_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a YUM package.

    Uses rpm to query the installed version.

    Args:
        package: Package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "rpm",
            "-q",
            "--queryformat",
            "%{VERSION}-%{RELEASE}",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except TimeoutError:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        if proc.returncode == 0:
            stdout = stdout_bytes.decode().strip()
            if stdout:
                return stdout
    except Exception:
        logger.debug("yum/dnf: rpm -q failed for %s", package)
    return None


async def dnf_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a DNF package.

    Uses rpm to query the installed version (same as YUM).

    Args:
        package: Package name.

    Returns:
        Installed version string, or None if not installed.
    """
    # DNF uses the same RPM database as YUM
    return await yum_get_installed_version(package)
