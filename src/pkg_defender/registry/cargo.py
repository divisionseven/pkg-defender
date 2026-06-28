"""Cargo (crates.io) registry adapter — publish times, version lists, metadata."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from logging import getLogger
from typing import Any, ClassVar

import aiohttp

from pkg_defender import __version__
from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

logger = getLogger(__name__)

CRATES_IO_URL = "https://crates.io"
USER_AGENT = f"pkg-defender/{__version__}"


def _sort_key(version: VersionInfo) -> datetime | None:
    """Sort key for VersionInfo — None sorts last in descending order."""
    pt: datetime | None = version.publish_time
    return pt


async def _cargo_fetch(
    url: str,
    session: aiohttp.ClientSession | None = None,
    manager: str | None = "cargo",
) -> dict[str, Any]:
    """Fetch JSON from crates.io with retry logic and custom User-Agent.

    Delegates to ``pkg_defender._http.fetch_json`` — the shared
    HTTP utility with exponential backoff, jitter, and config-driven
    defaults.

    Args:
        url: The URL to fetch from.
        session: Optional existing aiohttp session for connection reuse.

    Returns:
        Parsed JSON response as a dictionary.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors (4xx, 5xx).
        aiohttp.ClientError: On transport-level failure after retries.
        asyncio.TimeoutError: On request timeout after retries.
    """
    from pkg_defender._http import fetch_json as _fetch_json_impl

    result = await _fetch_json_impl(
        url,
        timeout=15,
        max_retries=3,
        session=session,
        headers={"User-Agent": USER_AGENT},
        on_404="raise",
        manager=manager,
    )
    # fetch_json with on_404="raise" always raises on errors (404s
    # raise, timeouts raise, transport errors raise).  This assert
    # is a type-narrowing safety net — it never fires in practice.
    if not result.success or result.data is None:
        raise RuntimeError(f"Failed to fetch {url}: {result.error}")
    return dict(result.data)


class CargoAdapter(RegistryAdapter):
    """Adapter for the crates.io (Cargo) registry API."""

    ecosystem: str = "cargo"
    registry_base_url: str = CRATES_IO_URL

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="cargo",
        registry_url=CRATES_IO_URL,
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
        """Try to get publish time from crates.io API."""
        url = f"{CRATES_IO_URL}/api/v1/crates/{package}/versions"
        data = await _cargo_fetch(url, session)
        versions: list[dict[str, Any]] = data.get("versions", [])
        for entry in versions:
            if entry.get("num") == version:
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
        """Extract GitHub repository URL from crates.io crate metadata."""
        url = f"{CRATES_IO_URL}/api/v1/crates/{package}"
        try:
            data = await _cargo_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("cargo: registry API failed for %s", package)
            return None

        crate_info = data.get("crate", {})
        repo_url = str(crate_info.get("repository", ""))
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

        Uses native crates.io API first, then falls back to the shared
        TimestampResolver (GitHub Releases \u2192 Tags \u2192 Libraries.io).

        Args:
            package: Cargo crate name.
            version: Exact version string (SemVer).
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
            logger.debug("cargo: registry API failed for %s %s", package, version)

        github_url = await self._get_github_url(package, session)
        ts_result = await resolve_timestamp(
            package=package,
            version=version,
            github_url=github_url,
            ecosystem="cargo",
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

        Fetches version list from ``GET /api/v1/crates/{name}/versions``.
        Yanked versions are excluded.

        Args:
            package: Cargo crate name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of :class:`VersionInfo` sorted by publish_time
            descending (newest first), or empty list if the package
            was not found.
        """
        url = f"{CRATES_IO_URL}/api/v1/crates/{package}/versions"
        try:
            data = await _cargo_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("cargo: registry API failed for %s", package)
            return []

        versions: list[dict[str, Any]] = data.get("versions", [])
        results: list[VersionInfo] = []
        for entry in versions:
            if entry.get("yanked", False):
                continue
            ver = entry.get("num")
            ts = entry.get("created_at")
            if ver is None or ts is None:
                continue
            publish_time = datetime.fromisoformat(ts)
            results.append(
                VersionInfo(
                    ecosystem="cargo",
                    package_name=package,
                    version=ver,
                    publish_time=publish_time,
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

        Reads ``crate.max_version`` from
        ``GET /api/v1/crates/{name}``.

        Args:
            package: Cargo crate name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest version string, or ``None`` if the package was not found.
        """
        url = f"{CRATES_IO_URL}/api/v1/crates/{package}"
        try:
            data = await _cargo_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("cargo: registry API failed for %s", package)
            return None

        crate_info: dict[str, Any] = data.get("crate", {})
        version: str | None = crate_info.get("max_version")
        return version

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await cargo_get_installed_version(package)


# ---------------------------------------------------------------------------
# Standalone convenience functions (matches pypi.py pattern)
# ---------------------------------------------------------------------------


async def cargo_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a Cargo crate.

    Uses cargo install --list to query installed crates.

    Args:
        package: Cargo crate name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "cargo",
            "install",
            "--list",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except TimeoutError:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        if proc.returncode == 0:
            stdout = stdout_bytes.decode()
            for line in stdout.splitlines():
                if line.startswith(package):
                    # Format: package v1.2.3
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].lstrip("v")
    except Exception:
        logger.debug("cargo: failed to get installed version for %s", package)
    return None
