# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""PyPI registry adapter — publish times, version lists, metadata."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from logging import getLogger
from typing import Any, ClassVar

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

logger = getLogger(__name__)

PYPI_REGISTRY_URL = "https://pypi.org"


def _sort_key(version: VersionInfo) -> datetime | None:
    """Sort key for VersionInfo — None sorts last in descending order."""
    pt: datetime | None = version.publish_time
    return pt


class PyPIAdapter(RegistryAdapter):
    """Adapter for the Python Package Index (PyPI) JSON API."""

    ecosystem: str = "pypi"
    registry_base_url: str = PYPI_REGISTRY_URL

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="pypi",
        registry_url=PYPI_REGISTRY_URL,
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
        """Try to get publish time from PyPI registry API."""
        url = f"{PYPI_REGISTRY_URL}/pypi/{package}/{version}/json"
        data = await self._fetch_json(url, session=session, manager="pypi")
        urls: list[dict[str, Any]] = data.get("urls", [])
        if not urls:
            return None
        ts = urls[0].get("upload_time_iso_8601")
        if ts is None:
            return None
        return datetime.fromisoformat(ts)

    async def _get_github_url(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Extract GitHub repository URL from PyPI package metadata."""
        url = f"{PYPI_REGISTRY_URL}/pypi/{package}/json"
        try:
            data = await self._fetch_json(url, session=session, manager="pypi")
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("pypi: registry API failed for %s", package)
            return None

        info = data.get("info", {})
        repo_url = ""
        project_urls = info.get("project_urls", {})
        if isinstance(project_urls, dict):
            repo_url = (
                project_urls.get("Source", "") or project_urls.get("source", "") or project_urls.get("Repository", "")
            )
        if not repo_url:
            repo_url = info.get("home_page") or ""

        if not repo_url or "github.com" not in repo_url:
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

        Uses native PyPI API first, then falls back to the shared
        TimestampResolver (GitHub Releases \u2192 Tags \u2192 Libraries.io).

        Args:
            package: PyPI package name.
            version: Exact version string (PEP 440).
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
            if result is not None:
                return (result, "registry_api")
        except Exception as e:
            logger.warning("pypi: ecosystem API failed for %s@%s: %s", package, version, e)

        # Fallback via shared timestamp resolver
        github_url = await self._get_github_url(package, session)
        ts_result = await resolve_timestamp(
            package=package,
            version=version,
            github_url=github_url,
            ecosystem="pypi",
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

        Fetches version list from PyPI and builds VersionInfo objects.

        Args:
            package: PyPI package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of VersionInfo sorted by publish_time descending.
        """
        url = f"{PYPI_REGISTRY_URL}/pypi/{package}/json"
        try:
            data = await self._fetch_json(url, session=session, manager="pypi")
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("pypi: registry API failed for %s", package)
            return []

        versions: dict[str, list[dict[str, Any]]] = data.get("releases", {})
        results: list[VersionInfo] = []

        for version_str, release_list in versions.items():
            if not release_list:
                continue
            upload_time = release_list[0].get("upload_time_iso_8601")
            publish_time = datetime.fromisoformat(upload_time) if upload_time else None
            results.append(
                VersionInfo(
                    ecosystem="pypi",
                    package_name=package,
                    version=version_str,
                    publish_time=publish_time or datetime.now(UTC),
                )
            )

        results.sort(key=lambda v: v.publish_time or datetime.min.replace(tzinfo=UTC), reverse=True)
        return results

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Return the latest stable version of *package*.

        Reads ``info.version`` from the PyPI JSON API.

        Args:
            package: PyPI package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or None if not found.
        """
        url = f"{PYPI_REGISTRY_URL}/pypi/{package}/json"
        try:
            data = await self._fetch_json(url, session=session, manager="pypi")
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("pypi: registry API failed for %s", package)
            return None

        info: dict[str, Any] = data.get("info", {})
        return info.get("version")

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a PyPI package.

        Uses pip show to query the installed version.

        Args:
            package: PyPI package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await pypi_get_installed_version(package)


async def pypi_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a PyPI package.

    Uses pip show to query the installed version.

    Args:
        package: PyPI package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "pip",
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
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        logger.debug("pypi/pip: failed to get installed version for %s", package)
    return None


async def pipx_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a pipx package.

    Uses pipx list to query the installed version.

    Args:
        package: pipx package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "pipx",
            "list",
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
                if package in line and "v" in line:
                    # Format: package v1.2.3
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == package and i + 1 < len(parts):
                            return parts[i + 1].lstrip("v")
    except Exception:
        logger.debug("pypi/pipx: failed to get installed version for %s", package)
    return None


async def uv_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a uv package.

    Uses uv pip show to query the installed version.

    Args:
        package: uv package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "uv",
            "pip",
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
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        logger.debug("pypi/uv: failed to get installed version for %s", package)
    return None
