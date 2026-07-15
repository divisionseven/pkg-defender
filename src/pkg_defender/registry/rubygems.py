# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""RubyGems registry adapter — publish times, version lists, metadata."""

from __future__ import annotations

import asyncio
from datetime import datetime
from logging import getLogger
from typing import Any, ClassVar

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

logger = getLogger(__name__)

RUBYGEMS_URL = "https://rubygems.org"


def _sort_key(version: VersionInfo) -> tuple[bool, datetime | None]:
    """Sort key for VersionInfo — None sorts last in descending order."""
    return (version.publish_time is None, version.publish_time)


async def _rubygems_fetch(
    url: str,
    session: aiohttp.ClientSession | None = None,
    manager: str | None = "gem",
) -> dict[str, Any] | list[Any]:
    """Fetch JSON from RubyGems API with retry logic.

    Delegates to ``pkg_defender._http.fetch_json`` — the shared
    HTTP utility with exponential backoff, jitter, and config-driven
    defaults.

    Args:
        url: The URL to fetch from.
        session: Optional existing aiohttp session for connection reuse.

    Returns:
        Parsed JSON response — either a dictionary or list depending
        on the API endpoint.

    Raises:
        aiohttp.ClientResponseError: On HTTP errors (4xx, 5xx).
        aiohttp.ClientError: On other client errors.
        asyncio.TimeoutError: On request timeout.
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
    # fetch_json with on_404="raise" always raises on errors (404s
    # raise, timeouts raise, transport errors raise). This assert
    # is a type-narrowing safety net — it never fires in practice.
    if result.data is None:
        raise RuntimeError(f"Failed to fetch {url}: {result.error}")
    return result.data


class RubyGemsAdapter(RegistryAdapter):
    """Adapter for the RubyGems registry API."""

    ecosystem: str = "rubygems"
    registry_base_url: str = RUBYGEMS_URL

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="rubygems",
        registry_url=RUBYGEMS_URL,
        capabilities=[
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ],
    )

    async def _try_ecosystem_api(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
    ) -> datetime | None:
        """Try to get publish time from RubyGems registry API."""
        url = f"{RUBYGEMS_URL}/api/v1/versions/{package}.json"
        data = await _rubygems_fetch(url, session)
        if not isinstance(data, list):
            return None
        for entry in data:
            if entry.get("number") == version:
                ts = entry.get("created_at")
                if ts is None:
                    return None
                return datetime.fromisoformat(ts)
        return None

    async def _get_github_url(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Extract GitHub repository URL from RubyGems gem metadata."""
        url = f"{RUBYGEMS_URL}/api/v1/gems/{package}.json"
        try:
            data = await _rubygems_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("rubygems: registry API failed for %s", package)
            return None

        if not isinstance(data, dict):
            return None
        repo_url = str(data.get("source_code_uri", "") or data.get("homepage_uri", ""))
        if "github.com" not in repo_url:
            return None
        return repo_url

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Return the UTC publish time for *package* at *version*.

        Uses native RubyGems API first, then falls back to the shared
        TimestampResolver (GitHub Releases \u2192 Tags \u2192 Libraries.io).

        Args:
            package: RubyGems gem name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source), where source is one of:
            - "registry_api"
            - "github_releases"
            - "github_tags"
            - "libraries_io"
            - "user_manual"
        """
        try:
            result = await self._try_ecosystem_api(package, version, session)
            if result:
                return (result, "registry_api")
        except Exception:
            logger.debug("rubygems: registry API failed for %s %s", package, version)

        github_url = await self._get_github_url(package, session)
        ts_result = await resolve_timestamp(
            package=package,
            version=version,
            github_url=github_url,
            ecosystem="rubygems",
            session=session,
            is_latest=is_latest,
        )
        return ts_result.publish_time, ts_result.source_label

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Return all published versions with their publish times.

        Fetches the version list from ``GET /api/v1/versions/{name}.json``
        and builds :class:`VersionInfo` objects for each non-prerelease
        version with a ``created_at`` timestamp.

        Args:
            package: RubyGems gem name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of :class:`VersionInfo` sorted by publish_time
            descending (newest first), or empty list if the package
            was not found.
        """
        url = f"{RUBYGEMS_URL}/api/v1/versions/{package}.json"
        try:
            data = await _rubygems_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("rubygems: registry API failed for %s", package)
            return []

        if not isinstance(data, list):
            return []

        results: list[VersionInfo] = []
        for entry in data:
            if entry.get("prerelease", False):
                continue
            ts = entry.get("created_at")
            ver = entry.get("number")
            if ts is None or ver is None:
                continue
            publish_time = datetime.fromisoformat(ts)
            results.append(
                VersionInfo(
                    ecosystem="rubygems",
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

        Uses ``GET /api/v1/versions/{name}/latest.json``.

        Args:
            package: RubyGems gem name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or ``None`` if the package was not found.
        """
        url = f"{RUBYGEMS_URL}/api/v1/versions/{package}/latest.json"
        try:
            data = await _rubygems_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("rubygems: registry API failed for %s", package)
            return None

        if not isinstance(data, dict):
            return None

        version: str | None = data.get("version")
        return version

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await rubygems_get_installed_version(package)


# ---------------------------------------------------------------------------
# Standalone convenience functions (matches pypi.py pattern)
# ---------------------------------------------------------------------------


async def rubygems_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a gem.

    Uses gem list to query the installed version from the system.

    Args:
        package: Gem name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "gem",
            "list",
            package,
            "--local",
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
                # Format: package (version)
                line = stdout.splitlines()[0]
                if "(" in line and ")" in line:
                    return line.split("(")[1].rstrip(")")
    except Exception:
        logger.debug("rubygems: gem list failed for %s", package)
    return None
