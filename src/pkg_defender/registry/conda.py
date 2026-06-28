"""Conda registry adapter — publish times, version lists, metadata.

This adapter uses ``conda search`` to query the conda-forge channel
for package information. Note: Unlike other registry adapters that
use HTTP APIs, Conda requires subprocess invocation of the ``conda``
command-line tool.

Security notes (same as other adapters):
- TIMEOUT_SECONDS = 30
- get_max_retries(config)
- FAIL_CLOSED error handling
- Hardcoded channel (conda-forge)
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, cast

import aiohttp

from pkg_defender.config import get_max_retries
from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter

if TYPE_CHECKING:
    pass  # PKGDConfig kept for consistency with other adapters

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 30

DEFAULT_CHANNEL = "conda-forge"

ANACONDA_API_BASE = "https://api.anaconda.org"

# Track packages that have already triggered timestamp warnings to suppress repeats
_warned_conda_packages: set[str] = set()


def _warn_no_publish_time(package: str) -> None:
    """Emit a warning log once per package when publish time is unavailable.

    Args:
        package: Package name.
    """
    if package not in _warned_conda_packages:
        logger.warning(
            "Conda does not expose publish timestamps for '%s' — "
            "cooldown checks will be skipped for this package. "
            "Set PKGD_COOLDOWN_ENABLED=false to disable cooldown checks "
            "explicitly.",
            package,
        )
        _warned_conda_packages.add(package)


def _parse_search_output(output_lines: list[str]) -> dict[str, dict[str, Any]]:
    """Parse ``conda search --info`` output into a structured dict.

    Conda search output looks like:
        # Name                    Version  Build         Channel
        # _______________________________________________________
        numpy                     1.26.4   py312haa1c40_202  conda-forge

    We extract version, build, and channel for each package.

    Args:
        output_lines: Lines from ``conda search --info`` stdout.

    Returns:
        Dict mapping package name to version metadata.
    """
    results: dict[str, dict[str, Any]] = {}

    for line in output_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Conda output is whitespace-separated but build can contain
        # underscores. We parse from the right side for some fields.
        parts = stripped.split()
        if len(parts) < 3:
            continue

        package = parts[0]
        version = parts[1]
        build = parts[2] if len(parts) > 2 else ""

        if package not in results:
            results[package] = {
                "versions": [],
            }

        results[package]["versions"].append(
            {
                "version": version,
                "build": build,
            }
        )

    return results


async def _run_conda_search(
    package: str,
    info: bool = False,
    channel: str = DEFAULT_CHANNEL,
) -> str:
    """Run ``conda search`` and return stdout.

    Uses subprocess with list form for security (no shell=True).
    Raises subprocess.CalledProcessError on failure after get_max_retries(config).

    Args:
        package: Package name to search for.
        info: If True, add --info flag for detailed output.
        channel: Channel to search (default: conda-forge).

    Returns:
        stdout from conda search command.

    Raises:
        subprocess.CalledProcessError: On command failure.
        FileNotFoundError: If conda is not installed.
        asyncio.TimeoutError: On timeout.
    """
    cmd = [
        "conda",
        "search",
        package,
        "-c",
        channel,
    ]
    if info:
        cmd.append("--info")

    proc: asyncio.subprocess.Process | None = None
    stdout_bytes: bytes | None = None
    stderr_bytes: bytes | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_SECONDS)
    except TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise

    assert stdout_bytes is not None
    stdout = stdout_bytes.decode()
    assert stderr_bytes is not None
    stderr = stderr_bytes.decode()

    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            returncode=proc.returncode or 1,
            cmd=cmd,
            output=stdout,
            stderr=stderr,
        )

    return stdout


async def _conda_search_with_retry(
    package: str,
    info: bool = False,
    channel: str = DEFAULT_CHANNEL,
) -> str:
    """Run ``conda search`` with exponential backoff retry.

    Retries up to get_max_retries(config) times on transient failures.

    Args:
        package: Package name to search for.
        info: If True, add --info flag for detailed output.
        channel: Channel to search (default: conda-forge).

    Returns:
        stdout from conda search command.

    Raises:
        subprocess.CalledProcessError: On persistent failure.
    """
    last_error: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        try:
            return await _run_conda_search(package, info, channel)
        except (TimeoutError, FileNotFoundError) as e:
            last_error = e
            if attempt == _max_retries - 1:
                raise
            # Exponential backoff: 1s, 2s, 4s
            await asyncio.sleep(2**attempt)
        except subprocess.CalledProcessError:
            # Non-transient error (e.g., package not found) - don't retry
            raise

        # Should not reach here, but satisfy type checker
    raise last_error or RuntimeError("unreachable")


class CondaAdapter(RegistryAdapter):
    """Adapter for Conda package registry."""

    ecosystem: str = "conda"
    registry_base_url: str = "conda-forge"

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="conda",
        registry_url="conda-forge",
        capabilities=[
            EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS,
            EcosystemCapability.THREAT_INTEL_SUPPORT,
        ],
    )

    async def _try_anaconda_api(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
    ) -> datetime | None:
        """Fetch publish timestamp from the Anaconda API.

        The Anaconda API provides ``upload_time`` per build file per version.
        All files for a package are returned in a single response; we filter
        by the requested version and return the latest upload time.

        Args:
            package: Conda package name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            The publish timestamp, or ``None`` if not found or on error.
        """
        try:
            url = f"{ANACONDA_API_BASE}/package/conda-forge/{package}"
            data = await self._fetch_json(url, session=session, manager="conda")
        except Exception:
            logger.debug("conda: Anaconda API call failed for %s %s", package, version)
            return None
        files: list[dict[str, Any]] = data.get("files", [])
        if not files:
            return None
        matching = (f for f in files if f.get("version") == version)
        upload_times = [m["upload_time"] for m in matching if isinstance(m.get("upload_time"), str)]
        if not upload_times:
            return None
        return datetime.fromisoformat(max(upload_times))

    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Get the publish timestamp for a specific package version.

        Queries the Anaconda API for native ``upload_time`` first (VERIFIED).
        Falls back to the shared ``TimestampResolver`` (GitHub+Libraries.io)
        if the API fails or the version is not found.

        Args:
            package: Conda package name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.
            is_latest: Whether this is the latest version.

        Returns:
            Tuple of ``(publish_time, source)`` where source is ``"user_manual"``
            if all resolution attempts fail.
        """
        try:
            result = await self._try_anaconda_api(package, version, session)
            if result is not None:
                return (result, "registry_api")
        except Exception:
            logger.debug("conda: Anaconda API failed for %s %s", package, version)

        try:
            github_url = f"https://github.com/conda-forge/{package}-feedstock"
            ts_result = await resolve_timestamp(
                package=package,
                version=version,
                github_url=github_url,
                ecosystem="conda",
                session=session,
                is_latest=is_latest,
            )
            pt, source = ts_result.publish_time, ts_result.source_label
            if pt is None and ts_result.resolution_status != "resolved":
                _warn_no_publish_time(package)
            return pt, source
        except Exception:
            logger.debug("conda: TimestampResolver failed for %s %s", package, version)
            _warn_no_publish_time(package)
            return (None, "user_manual")

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Get all available versions with publish times.

        Queries the Anaconda API for per-version ``upload_time``, then
        falls back to the subprocess ``conda search`` for the version list.
        Versions found in the API response have populated ``publish_time``;
        versions only found via subprocess have ``publish_time=None``.

        Args:
            package: Conda package name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Sorted list of ``VersionInfo`` objects (newest first).
        """
        timestamps: dict[str, datetime] = {}
        try:
            url = f"{ANACONDA_API_BASE}/package/conda-forge/{package}"
            data = await self._fetch_json(url, session=session, manager="conda")
            for f in data.get("files", []):
                ver = f.get("version")
                ts_str = f.get("upload_time")
                if isinstance(ver, str) and isinstance(ts_str, str):
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ver not in timestamps or ts > timestamps[ver]:
                            timestamps[ver] = ts
                    except ValueError:
                        continue
        except Exception:
            logger.debug("conda: Anaconda API failed for %s", package)

        try:
            result = await _conda_search_with_retry(package, info=True)
        except (TimeoutError, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug("conda search failed for %s: %s", package, e)
            return []

        lines = result.strip().split("\n")
        parsed = _parse_search_output(lines)
        package_info = parsed.get(package)
        if not package_info:
            return []
        versions = package_info.get("versions", [])
        if not versions:
            return []

        result_versions: list[VersionInfo] = []
        for ver_info in versions:
            version = ver_info["version"]
            publish_time = timestamps.get(version)
            result_versions.append(
                VersionInfo(
                    ecosystem="conda",
                    package_name=package,
                    version=version,
                    publish_time=publish_time,
                ),
            )

        result_versions.sort(key=lambda v: v.version, reverse=True)
        return result_versions

    async def get_latest_version(
        self,
        package: str,
        session: Any = None,  # Unused for conda adapter
    ) -> str | None:
        """Get the latest stable version string.

        Args:
            package: Conda package name.
            session: Unused (present for interface compatibility).

        Returns:
            Latest version string, or None if package not found.
        """
        try:
            output = await _conda_search_with_retry(package, info=True)
        except (TimeoutError, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug(f"conda search failed for {package}: {e}")
            return None

        lines = output.strip().split("\n")
        parsed = _parse_search_output(lines)

        package_info = parsed.get(package)
        if not package_info or not package_info.get("versions"):
            return None

        # Return the first (newest due to conda's sort order)
        versions_list: list[dict[str, Any]] = package_info["versions"]
        if not versions_list:
            return None
        version_str = cast(str, versions_list[0]["version"])
        return version_str

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await conda_get_installed_version(package)


async def get_all_version_timestamps(
    package: str,
) -> list[tuple[str, datetime]]:
    """Return publish timestamps for every version of *package*.

    Note: Conda does not provide per-version timestamps.
    This returns an empty list as conda CLI does not expose
    this information.

    Args:
        package: Conda package name.

    Returns:
        Empty list (conda does not provide timestamps).
    """
    # Conda CLI doesn't expose per-version timestamps
    return []


async def conda_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a conda package.

    Uses conda list to query the installed version from the environment.

    Args:
        package: Conda package name.

    Returns:
        Installed version string, or None if not installed.
    """
    import json

    try:
        proc = await asyncio.create_subprocess_exec(
            "conda",
            "list",
            package,
            "-n",
            "base",
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
            if data and isinstance(data, list):
                return cast(str, data[0].get("version"))
    except Exception:
        logger.debug("conda: conda list failed for %s", package)
        pass
    return None
