"""npm registry adapter — publish times, version lists, metadata."""

from __future__ import annotations

import asyncio
from datetime import datetime
from logging import getLogger
from typing import Any, cast
from urllib.parse import quote

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import ManagerConfig

logger = getLogger(__name__)

NPM_REGISTRY_URL = "https://registry.npmjs.org"

NPM_CONFIG = ManagerConfig(
    ecosystem="npm",
    registry_url="https://registry.npmjs.org",
    capabilities=[],
)


def _encode_package_name(package: str) -> str:
    """Encode scoped npm package names for URL paths.

    Scoped packages like ``@scope/name`` are encoded to
    ``%40scope%2Fname`` so they can be interpolated directly into a URL
    path.  Non-scoped package names are returned unchanged.

    Args:
        package: Raw npm package name (e.g. ``"lodash"`` or ``"@scope/name"``).

    Returns:
        URL-safe package name string.
    """
    if package.startswith("@"):
        return quote(package, safe="")
    return package


async def _fetch_json(
    url: str,
    session: aiohttp.ClientSession | None = None,
    manager: str | None = "npm",
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


async def _try_ecosystem_api(
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
) -> datetime | None:
    """Try to get publish time from npm registry API (ecosystem-specific)."""
    encoded = _encode_package_name(package)
    url = f"{NPM_REGISTRY_URL}/{encoded}"
    data = await _fetch_json(url, session)
    time_dict: dict[str, str] = data.get("time", {})
    time_dict.pop("created", None)
    time_dict.pop("modified", None)
    ts = time_dict.get(version)
    if ts is None:
        return None
    return datetime.fromisoformat(ts)


async def _get_github_url(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> str | None:
    """Extract GitHub repository URL from npm registry metadata."""
    encoded = _encode_package_name(package)
    url = f"{NPM_REGISTRY_URL}/{encoded}"
    try:
        data = await _fetch_json(url, session)
    except (TimeoutError, aiohttp.ClientError):
        logger.debug("npm: registry API failed for %s", package)
        return None

    repo_info = data.get("repository", {})
    repo_url = repo_info.get("url", "") if isinstance(repo_info, dict) else str(repo_info)
    if "github.com" not in repo_url:
        return None
    return repo_url


async def get_publish_time(
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
    is_latest: bool = False,
) -> tuple[datetime | None, str]:
    """Return the UTC publish time for *package* at *version*.

    Uses native npm registry API first, then falls back to the shared
    TimestampResolver (GitHub Releases \u2192 Tags \u2192 Libraries.io).

    Args:
        package: npm package name (scoped or plain).
        version: Exact version string (e.g. ``"1.14.1"``).
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
        result = await _try_ecosystem_api(package, version, session)
        if result:
            return (result, "registry_api")
    except Exception:
        logger.debug("npm: registry API failed for %s %s", package, version)

    github_url = await _get_github_url(package, session)
    ts_result = await resolve_timestamp(
        package=package,
        version=version,
        github_url=github_url,
        ecosystem="npm",
        session=session,
        is_latest=is_latest,
    )
    return ts_result.publish_time, ts_result.source_label


async def get_all_versions(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> list[str]:
    """Return all published version strings for *package*.

    Fetches full metadata and extracts the keys from the ``versions``
    dict.

    Args:
        package: npm package name (scoped or plain).
        session: Optional aiohttp session for connection pooling.

    Returns:
        Sorted list of version strings, or empty list if the package
        was not found.
    """
    encoded = _encode_package_name(package)
    url = f"{NPM_REGISTRY_URL}/{encoded}"
    try:
        data = await _fetch_json(url, session)
    except (TimeoutError, aiohttp.ClientError):
        logger.debug("npm: registry API failed for %s", package)
        return []

    versions_dict: dict[str, Any] = data.get("versions", {})
    return list(versions_dict.keys())


async def get_latest_version(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> str | None:
    """Return the latest published version of *package*.

    Reads ``dist-tags.latest`` from the full npm metadata.

    Args:
        package: npm package name (scoped or plain).
        session: Optional aiohttp session for connection pooling.

    Returns:
        Latest version string, or ``None`` if the package was not found.
    """
    encoded = _encode_package_name(package)
    url = f"{NPM_REGISTRY_URL}/{encoded}"
    try:
        data = await _fetch_json(url, session)
    except (TimeoutError, aiohttp.ClientError):
        logger.debug("npm: registry API failed for %s", package)
        return None

    dist_tags: dict[str, str] = data.get("dist-tags", {})
    return dist_tags.get("latest")


async def get_all_version_timestamps(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> dict[str, datetime]:
    """Return publish timestamps for every version of *package*.

    Fetches full metadata from the npm registry and extracts the ``time``
    dict.  This is a single API call that replaces multiple per-version
    lookups.  The special keys ``"created"`` and ``"modified"`` are
    excluded.

    Args:
        package: npm package name (scoped or plain).
        session: Optional aiohttp session for connection pooling.

    Returns:
        Dict mapping version strings to timezone-aware
        :class:`~datetime.datetime` objects, or empty dict if the
        package was not found or ``time`` field is missing.
    """
    encoded = _encode_package_name(package)
    url = f"{NPM_REGISTRY_URL}/{encoded}"
    try:
        data = await _fetch_json(url, session)
    except (TimeoutError, aiohttp.ClientError):
        logger.debug("npm: registry API failed for %s", package)
        return {}

    time_dict: dict[str, str] = data.get("time", {})
    time_dict.pop("created", None)
    time_dict.pop("modified", None)
    return {v: datetime.fromisoformat(ts) for v, ts in time_dict.items()}


async def get_version_info(
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
) -> VersionInfo | None:
    """Return a :class:`VersionInfo` for *package* at *version*.

    Fetches the publish time and wraps it in a
    :class:`~pkg_defender.db.schema.VersionInfo` dataclass.

    Args:
        package: npm package name (scoped or plain).
        version: Exact version string.
        session: Optional aiohttp session for connection pooling.

    Returns:
        Populated :class:`VersionInfo`, or ``None`` if the version
        was not found.
    """
    publish_time, source = await get_publish_time(package, version, session)
    if publish_time is None:
        return None
    return VersionInfo(
        version=version,
        publish_time=publish_time,
        ecosystem="npm",
        package_name=package,
    )


async def npm_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of an npm package.

    Uses npm list to get the installed version from the local node_modules.

    Args:
        package: npm package name (scoped or plain).

    Returns:
        Installed version string, or None if not installed.
    """
    import json

    try:
        proc = await asyncio.create_subprocess_exec(
            "npm",
            "list",
            package,
            "--depth=0",
            "--json",
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
            data = json.loads(stdout_bytes.decode())
            deps = data.get("dependencies", {})
            if package in deps:
                return cast(str, deps[package].get("version"))
    except Exception:
        logger.debug("npm: npm ls failed for %s", package)
    return None
