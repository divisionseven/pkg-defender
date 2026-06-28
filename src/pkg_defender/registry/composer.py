"""Composer registry adapter — publish times, version lists, metadata.

Composer uses the Packagist API - endpoint verified:
https://packagist.org/packages/{vendor}/{package}.json

Date field: package.versions[].time
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

import aiohttp
from packaging.version import Version

from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

PACKAGIST_URL = "https://packagist.org"

logger = logging.getLogger(__name__)


def _sort_key(version: VersionInfo) -> datetime:
    """Sort key for VersionInfo — oldest first, None mapped to epoch for stable sort."""
    pt: datetime | None = version.publish_time
    return pt if pt is not None else datetime.min.replace(tzinfo=UTC)


def _parse_package_name(package: str) -> tuple[str, str]:
    """Parse vendor/package format for Packagist.

    Composer packages are in vendor/package format.

    Args:
        package: Composer package name (e.g. "laravel/framework").

    Returns:
        Tuple of (vendor, package).
    """
    if "/" in package:
        parts = package.split("/", 1)
        return parts[0], parts[1]
    return package, package


async def _fetch_json(
    url: str,
    session: aiohttp.ClientSession | None = None,
    manager: str | None = "composer",
) -> dict[str, Any]:
    """Fetch JSON from *url* with timeout and retry (bridge to shared HTTP utility).

    Delegates to ``pkg_defender._http.fetch_json`` — the shared
    HTTP utility with exponential backoff, jitter, and config-driven
    defaults.

    Args:
        url: Fully-qualified URL to fetch.
        session: Optional existing session for connection pooling.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: On transport-level failure after retries.
        asyncio.TimeoutError: When the request times out after retries.
    """
    from pkg_defender._http import fetch_json as _fetch_json_impl

    result = await _fetch_json_impl(
        url,
        timeout=15,
        max_retries=3,
        session=session,
        on_404="raise",
        manager=manager,
    )
    if not result.success or result.data is None:
        raise RuntimeError(f"Failed to fetch {url}: {result.error}")
    return dict(result.data)


class ComposerAdapter(RegistryAdapter):
    """Adapter for Composer (PHP) using Packagist API."""

    ecosystem: str = "composer"
    registry_base_url: str = PACKAGIST_URL

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="composer",
        registry_url=PACKAGIST_URL,
        capabilities=[
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ],
    )

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Return the UTC publish time for *package* at *version*.

        Uses native Packagist API first, then falls back to the shared
        TimestampResolver (GitHub Releases \u2192 Tags \u2192 Libraries.io).

        Note: Libraries.io does not support Packagist packages, so
        Tier 3 is automatically skipped by the resolver.

        Args:
            package: Composer package name (vendor/package).
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source), where source is one of:
            - "registry"
            - "github_releases"
            - "github_tags"
            - "user_manual"
        """
        vendor, name = _parse_package_name(package)
        packagist_url = f"{PACKAGIST_URL}/packages/{vendor}/{name}.json"
        github_repo_url: str | None = None

        try:
            packagist_data = await _fetch_json(packagist_url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("composer: Packagist API failed for %s", package)
            pass
        else:
            package_data: dict[str, Any] = packagist_data.get("package", {})
            versions: dict[str, dict[str, Any]] = package_data.get("versions", {})
            version_data = versions.get(version)
            if version_data is not None:
                ts = version_data.get("time")
                if ts is not None:
                    return datetime.fromisoformat(ts), "registry"
            github_repo_url = self._extract_github_repo(package_data)

        if github_repo_url is None:
            return None, "user_manual"
        ts_result = await resolve_timestamp(
            package=package,
            version=version,
            github_url=github_repo_url,
            ecosystem="packagist",
            session=session,
            is_latest=is_latest,
        )
        return ts_result.publish_time, ts_result.source_label

    def _extract_github_repo(self, package_data: dict[str, Any]) -> str | None:
        """Extract GitHub repository URL from Packagist package data.

        Args:
            package_data: Package data from Packagist API.

        Returns:
            GitHub repository URL if available and recognized, else None.
        """
        repo_info: dict[str, Any] = package_data.get("repository", {})
        repo_url: str | None = repo_info.get("url")
        if repo_url and "github.com" in repo_url:
            return repo_url
        return None

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Return all published versions with their publish times.

        Fetches from Packagist API and builds VersionInfo objects.

        Args:
            package: Composer package name (vendor/package).
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of :class:`VersionInfo` sorted by publish_time
            descending (newest first), or empty list if the package
            was not found.
        """
        vendor, name = _parse_package_name(package)
        url = f"{PACKAGIST_URL}/packages/{vendor}/{name}.json"
        try:
            data = await _fetch_json(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("composer: Packagist API failed for %s", package)
            return []

        package_data: dict[str, Any] = data.get("package", {})
        versions: dict[str, dict[str, Any]] = package_data.get("versions", {})

        results: list[VersionInfo] = []
        for ver, version_data in versions.items():
            ts = version_data.get("time")
            if ts is None:
                continue
            publish_time = datetime.fromisoformat(ts)
            results.append(
                VersionInfo(
                    ecosystem="composer",
                    package_name=package,
                    version=ver,
                    publish_time=publish_time,
                )
            )

        results.sort(key=_sort_key, reverse=True)
        return results

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Return the latest stable version of *package*.

        Reads from ``package.versions`` keys.

        Args:
            package: Composer package name (vendor/package).
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or ``None`` if the package was not found.
        """
        vendor, name = _parse_package_name(package)
        url = f"{PACKAGIST_URL}/packages/{vendor}/{name}.json"
        try:
            data = await _fetch_json(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("composer: Packagist API failed for %s", package)
            return None

        package_data: dict[str, Any] = data.get("package", {})
        versions: dict[str, dict[str, Any]] = package_data.get("versions", {})
        if not versions:
            return None

        # Filter out dev/unstable version patterns
        stable_versions = [
            v
            for v in versions
            if not v.startswith("dev-")
            and not v.endswith("-dev")
            and not v.endswith("-alpha")
            and not v.endswith("-beta")
            and not v.endswith("-RC")
            and v not in ("dev-master", "dev-main")
        ]
        if not stable_versions:
            return None
        # Sort by version and return highest
        try:
            stable_versions.sort(key=lambda v: Version(v))
        except Exception:
            logger.warning(
                "Failed to sort Composer versions for one or more packages; returning last entry as fallback"
            )
        return stable_versions[-1]

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await composer_get_installed_version(package)


# ---------------------------------------------------------------------------
# Standalone convenience functions
# ---------------------------------------------------------------------------


async def composer_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a Composer package.

    Uses composer show to query the installed version.

    Args:
        package: Composer package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "composer",
            "show",
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
            stdout = stdout_bytes.decode()
            for line in stdout.splitlines():
                if line.startswith("versions"):
                    # Format: versions : v1.2.3
                    parts = line.split(":", 1)
                    if len(parts) >= 2:
                        return parts[1].strip().lstrip("v")
    except Exception:
        logger.debug("composer: failed to get installed version for %s", package)
    return None
