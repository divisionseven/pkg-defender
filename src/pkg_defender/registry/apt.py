"""APT registry adapter — package version queries via apt-cache."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

import aiohttp

from pkg_defender.config import get_max_retries
from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

logger = logging.getLogger(__name__)

# Track packages that have already triggered timestamp warnings to suppress repeats
_warned_apt_packages: set[str] = set()

TIMEOUT_SECONDS = 30
# Snapshot.debian.org API
SNAPSHOT_DEBIAN_URL = "https://snapshot.debian.org"


async def _snapshot_fetch(
    url: str,
    session: aiohttp.ClientSession | None = None,
    manager: str | None = "apt",
) -> dict[str, Any]:
    """Fetch JSON from snapshot.debian.org with timeout and retry (bridge to shared HTTP utility).

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


async def _get_publish_time_snapshot(
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
) -> datetime | None:
    """Get publish time from snapshot.debian.org API.

    Queries the snapshot.debian.org archive to find the first_seen timestamp
    for a package version.

    Args:
        package: Package name.
        version: Exact version string.
        session: Optional aiohttp session for connection pooling.

    Returns:
        Publish time as timezone-aware datetime in UTC, or None if not found.
    """
    # Query snapshot.debian.org API
    # URL: https://snapshot.debian.org/mr/binary/{pkg}/{ver}/?fileinfo=1
    url = f"{SNAPSHOT_DEBIAN_URL}/mr/binary/{package}/{version}/binfiles?fileinfo=1"

    try:
        data = await _snapshot_fetch(url, session)
    except (TimeoutError, aiohttp.ClientError) as e:
        logger.debug(
            "snapshot.debian.org fetch failed for %s/%s: %s",
            package,
            version,
            e,
        )
        # Don't warn when fetch fails - caller passed None or precondition failed.
        # Only warn when we TRY and GET data but it lacks timestamps.
        return None

    # Parse the response structure:
    # {
    #   "result": [...],
    #   "fileinfo": {
    #     "sha256_hash": [
    #       {
    #         "archive_name": "debian",
    #         "first_seen": "20221015T220129Z",
    #         ...
    #       }
    #     ]
    #   }
    # }
    fileinfo = data.get("fileinfo", {})
    if not fileinfo:
        cache_key = f"apt:{package}"
        if cache_key not in _warned_apt_packages:
            logger.warning(
                "APT does not expose publish timestamps for '%s' — "
                "cooldown checks will be skipped. "
                "APT vulnerability data is still checked (Steps 4-5).",
                package,
            )
            _warned_apt_packages.add(cache_key)
        return None

    # Get first entry from first fileinfo key (e.g., sha256_hash)
    first_key = next(iter(fileinfo.keys()), None)
    if not first_key:
        return None

    entries = fileinfo.get(first_key, [])
    if not entries:
        return None

    first_entry = entries[0]
    first_seen = first_entry.get("first_seen")
    if not first_seen:
        return None

    # Parse ISO 8601 timestamp: "20221015T220129Z"
    try:
        # Format: %Y%m%dT%H%M%SZ
        publish_time = datetime.strptime(first_seen, "%Y%m%dT%H%M%SZ")
        # Make it timezone-aware (UTC)
        return publish_time.replace(tzinfo=UTC)
    except ValueError:
        logger.warning(
            "Failed to parse snapshot timestamp %r for %s/%s",
            first_seen,
            package,
            version,
        )
        return None


async def _run_apt_command(args: list[str]) -> str | None:
    """Run an apt command and return stdout, or None on failure.

    Uses subprocess with list form (not shell=True) for security.
    Implements fail-closed behavior: returns None on any error.

    Args:
        args: Command arguments (e.g., ['apt-cache', 'policy', ...]).

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
            logger.warning("apt-cache command not found - is APT installed?")
            return None
        except OSError as e:
            logger.warning(
                "OS error running apt-cache command (attempt %d/%d): %s",
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


async def _apt_get_latest_version(package: str) -> str | None:
    """Get the latest version of a package using apt-cache policy.

    Args:
        package: Package name.

    Returns:
        Latest version string, or None if not found.
    """
    output = await _run_apt_command(["apt-cache", "policy", package])
    if not output:
        return None

    # Parse apt-cache policy output:
    # Package: <package>
    #   Installed: (none)
    #   Candidate: 1.2.3-4
    #   Version table:
    #       1.2.3-4 500
    #           ...

    lines = output.split("\n")
    for line in lines:
        # Look for "Candidate:" line which shows the installable version
        if line.strip().startswith("Candidate:"):
            version = line.split(":", 1)[1].strip()
            if version and version != "(none)":
                return version

    return None


async def _apt_get_all_versions(package: str) -> list[str]:
    """Get all available versions of a package using apt-cache policy.

    Args:
        package: Package name.

    Returns:
        List of version strings, newest first, or empty list if not found.
    """
    output = await _run_apt_command(["apt-cache", "policy", package])
    if not output:
        return []

    # Parse version table from apt-cache policy output
    # Example format:
    #   Version table:
    #       1.2.3-4 500
    #           http://archive.ubuntu.com/ubuntu jammy/main amd64 Packages
    #           1.2.3-3 100
    #           ...

    versions = []
    in_version_table = False

    for line in output.split("\n"):
        stripped = line.strip()

        if stripped.startswith("Version table:"):
            in_version_table = True
            continue

        if in_version_table and stripped and not stripped.startswith("http"):
            # Version lines start with spaces and a version number
            # Skip lines that are URLs or additional info
            # Try to extract version (starts with digit, contains -)
            parts = stripped.split()
            if parts:
                version = parts[0]
                if version not in versions and "-" in version:
                    versions.append(version)

    return versions


class APTAdapter(RegistryAdapter):
    """Adapter for APT package repositories."""

    ecosystem: str = "apt"
    registry_base_url: str = "local://apt"

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="apt",
        registry_url="local://apt",
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
        """Try to get publish time from snapshot.debian.org (ecosystem API)."""
        return await _get_publish_time_snapshot(package, version, session)

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Return the UTC publish time for *package* at *version*.

        Uses native snapshot.debian.org API first, then falls back to
        the shared TimestampResolver. Since APT packages are not hosted
        on GitHub, only Tier 3 (Libraries.io) is available as a fallback.

        Args:
            package: Package name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, source), where source is one of:
            - "registry_api"
            - "user_manual"
        """
        try:
            result = await self._try_ecosystem_api(package, version, session)
            if result:
                return (result, "registry_api")
        except Exception:
            logger.debug("apt: registry API failed for %s %s", package, version)

        # APT packages are not hosted on GitHub, so no GitHub URL.
        # Only Tier 3 (Libraries.io) is available for Debian packages.
        try:
            ts_result = await resolve_timestamp(
                package=package,
                version=version,
                github_url=None,
                ecosystem="apt",
                session=session,
                is_latest=is_latest,
            )
            return ts_result.publish_time, ts_result.source_label
        except Exception:
            logger.debug("apt: TimestampResolver failed for %s %s", package, version)
            return (None, "user_manual")

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Return all available versions for *package* on APT.

        Uses apt-cache policy to list all available versions.

        Args:
            package: Package name.
            session: Unused (included for interface compatibility).

        Returns:
            List of VersionInfo objects.
        """
        versions = await _apt_get_all_versions(package)
        now = datetime.now(UTC)
        return [
            VersionInfo(
                ecosystem="apt",
                package_name=package,
                version=v,
                publish_time=now,
            )
            for v in versions
        ]

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Return the latest version of *package* on APT.

        Uses apt-cache policy to get the candidate version.

        Args:
            package: Package name.
            session: Unused (included for interface compatibility).

        Returns:
            Latest version string, or None if not found.
        """
        return await _apt_get_latest_version(package)

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of an APT package.

        Uses dpkg-query to get the installed version.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await apt_get_installed_version(package)


async def apt_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of an APT package.

    Uses dpkg-query to get the installed version from the system.

    Args:
        package: Package name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "dpkg-query",
            "-W",
            "-f=${Version}",
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
        logger.debug("apt: dpkg-query failed for %s", package)
    return None
