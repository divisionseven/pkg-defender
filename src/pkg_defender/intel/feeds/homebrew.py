"""Homebrew vulnerability feed using OSV GIT ecosystem.

This module queries the OSV API using the GIT ecosystem with Homebrew
formula repository URLs to provide vulnerability data for locally
installed Homebrew packages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import shutil
import subprocess
from datetime import datetime
from typing import TYPE_CHECKING, Any

import aiohttp
from rich.console import Console

from pkg_defender._http import calc_retry_wait
from pkg_defender.config import get_http_timeout, get_max_retries
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger: logging.Logger = logging.getLogger(__name__)
console = Console(stderr=True)

OSV_API_BASE = "https://api.osv.dev/v1"
REQUEST_TIMEOUT: int | None = None  # None = use config default


def _normalize_brew_version(version: str) -> str:
    """Normalize a Homebrew version string for OSV compatibility.

    Homebrew versions may include underscore suffixes (e.g., "1.9.2_1")
    indicating rebuilds. OSV requires strict semver, so strip these suffixes.

    Args:
        version: Version string from Homebrew (e.g., "1.9.2_1").

    Returns:
        Version string with underscore suffix removed (e.g., "1.9.2").
    """
    # Strip trailing underscore suffix (e.g., "1.9.2_1" -> "1.9.2")
    # This handles rebuild versions like "1.9.2_1", "1.5.7_2", etc.
    # Only strip if there's actual version content before the underscore
    # (e.g., "_1" should not become empty string)
    if "_" in version:
        # Find the last underscore and check if what follows looks like a number
        parts = version.rsplit("_", 1)
        if len(parts) == 2 and parts[1].isdigit() and parts[0]:
            return parts[0]
    return version


class BrewNotInstalledError(Exception):
    """Raised when Homebrew is not installed on the system."""

    pass


def get_installed_formulae() -> list[dict[str, Any]]:
    """Get list of installed Homebrew formulae with their metadata.

    Runs ``brew info --json=v2 --installed`` to get JSON output of all
    installed packages.

    Returns:
        List of formula dictionaries from brew JSON output.

    Raises:
        BrewNotInstalledError: If brew is not installed.
        subprocess.TimeoutExpired: If brew command times out.
        subprocess.CalledProcessError: If brew command fails.
    """
    # Check if brew is available
    brew_path = shutil.which("brew")
    if brew_path is None:
        raise BrewNotInstalledError("Homebrew is not installed")

    result = subprocess.run(
        ["brew", "info", "--json=v2", "--installed"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse brew JSON output: %s", e)
        return []

    # Extract formulae from the JSON output
    # brew info --json=v2 --installed returns {"formulae": [...], "casks": [...]}
    formulae: list[dict[str, Any]] = data.get("formulae", [])
    return formulae


def _parse_brew_formula(
    formula: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Parse a single brew formula dict to extract name, repo URL, and version.

    Args:
        formula: A formula dictionary from brew JSON output.

    Returns:
        Tuple of (name, repo_url, version) or None if required fields missing.
    """
    name = formula.get("name")
    if not name:
        return None

    # Get version from installed array
    version = "unknown"
    installed = formula.get("installed", [])
    if installed and isinstance(installed, list):
        first_installed = installed[0]
        if isinstance(first_installed, dict):
            version = first_installed.get("version", "unknown")

    # Get upstream project URL (not Homebrew tap URL)
    # Priority: homepage > repository_url > urls.stable.url > tap-constructed > None
    repo_url = formula.get("homepage")

    # Validate homepage URL if present
    # Ensure it's an absolute URL, not a relative path or special format
    if repo_url and not repo_url.startswith(("http://", "https://")):
        # homepage might be a relative path or unusual format
        repo_url = None

    # Fallback: try repository_url (some formulae have this field)
    if not repo_url:
        repo_url = formula.get("repository_url")

    # Fallback: try urls.stable.url
    if not repo_url:
        urls = formula.get("urls", {})
        if urls and isinstance(urls, dict):
            stable = urls.get("stable", {})
            if stable and isinstance(stable, dict):
                repo_url = stable.get("url")

    # Fallback: construct from tap (last resort)
    if not repo_url:
        tap = formula.get("tap")
        if tap:
            if tap == "homebrew/core":
                repo_url = "https://github.com/Homebrew/homebrew-core"
            elif tap == "homebrew/cask":
                repo_url = "https://github.com/Homebrew/homebrew-cask"
            else:
                repo_url = f"https://github.com/{tap.replace('/', '/')}"

    if not repo_url:
        return None

    return (name, repo_url, version)


async def check_brew_package(
    package: str,
    version: str,
    repo_url: str,
    session: aiohttp.ClientSession | None = None,
) -> list[ThreatRecord]:
    """Check a single Homebrew package against OSV using GIT ecosystem.

    Args:
        package: Package name (from brew formula name).
        version: Package version.
        repo_url: Repository URL (e.g., https://github.com/python/cpython).
        session: Optional existing aiohttp session.

    Returns:
        List of ThreatRecord objects for any known vulnerabilities.
    """
    url = f"{OSV_API_BASE}/query"

    # Normalize version for OSV compatibility (strip rebuild suffix like "_1")
    normalized_version = _normalize_brew_version(version)

    # Query OSV using GIT ecosystem with repo URL as package name
    query = {
        "package": {"name": repo_url, "ecosystem": "GIT"},
        "version": normalized_version,
    }

    own_session = session is None
    if own_session:
        _timeout = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout()
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_timeout))

    # mypy doesn't know session is non-None after creation
    assert session is not None

    _max_retries = get_max_retries()
    last_exc: Exception | None = None

    try:
        for attempt in range(_max_retries):
            resp: aiohttp.ClientResponse | None = None
            try:
                _timeout = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout()
                timeout = aiohttp.ClientTimeout(total=_timeout)
                async with session.post(url, json=query, timeout=timeout) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    vulns = data.get("vulns", [])

                    return [
                        _parse_osv_vuln(
                            v,
                            ecosystem="homebrew",
                            package=package,
                            id_prefix="homebrew_osv:",
                            source="homebrew_osv",
                            include_eco_in_id=False,
                        )
                        for v in vulns
                    ]

            except aiohttp.ClientResponseError as exc:
                if exc.status in (429, 500, 502, 503, 504):
                    last_exc = exc
                    if attempt < _max_retries - 1:
                        if resp is not None:
                            wait = calc_retry_wait(attempt, exc.status, resp)
                        else:
                            wait = 2**attempt + random.uniform(0, 1)
                        logger.warning(
                            "OSV API query for Homebrew %s returned %d; retry %d/%d in %ds",
                            package,
                            exc.status,
                            attempt + 1,
                            _max_retries,
                            wait,
                        )
                        await asyncio.sleep(wait)
                        continue
                    raise
                raise

            except (aiohttp.ClientError, TimeoutError) as exc:
                last_exc = exc
                if attempt < _max_retries - 1:
                    wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "OSV API query for Homebrew %s failed: %s; retry %d/%d in %ds",
                        package,
                        repr(exc),
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError(f"Failed to query OSV for {package} after {_max_retries} retries")

    except Exception as e:
        console.print(
            f"[yellow]Query error[/yellow] for [cyan]{package}@{version}[/cyan] "
            f"[link={repo_url}]{repo_url}[/link]: {type(e).__name__}"
        )
        raise
    finally:
        if own_session and session is not None:
            await session.close()


class HomebrewFeedAdapter(FeedSource):
    """FeedSource implementation for Homebrew vulnerability checking.

    Queries OSV API using the GIT ecosystem with Homebrew formula
    repository URLs to find vulnerabilities for locally installed
    Homebrew packages.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "homebrew"

    @property
    def supports_incremental(self) -> bool:
        """Homebrew feed does not support incremental sync."""
        return False

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if Homebrew is installed and available.

        Args:
            config: The current configuration object.

        Returns:
            True if brew is installed, False otherwise.
        """
        return shutil.which("brew") is not None

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch vulnerabilities for all installed Homebrew packages.

        Args:
            since: Ignored — Homebrew feed doesn't support time filtering.
            ecosystems: Ignored — Homebrew feed checks all installed packages.
            session: Shared aiohttp session.
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult containing ThreatRecord objects for vulnerable packages.
        """
        logger.info("Fetching Homebrew vulnerabilities")

        try:
            formulae = await asyncio.to_thread(get_installed_formulae)
        except BrewNotInstalledError:
            logger.debug("Homebrew not installed, skipping feed")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
        except Exception as e:
            logger.warning("Failed to get installed formulae: %s", e)
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        if not formulae:
            logger.debug("No formulae installed")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        all_records: list[ThreatRecord] = []

        for formula in formulae:
            parsed = _parse_brew_formula(formula)
            if parsed is None:
                continue

            name, repo_url, version = parsed

            try:
                records = await check_brew_package(name, version, repo_url, session)
                all_records.extend(records)
            except Exception as e:
                logger.warning("Failed to check package %s@%s: %s", name, version, e)
                continue

        logger.info(
            "Found %d vulnerabilities for %d formulae",
            len(all_records),
            len(formulae),
        )
        return FeedFetchResult(records=all_records, feed_metadata={}, status=FetchStatus.SUCCESS)

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Check a single Homebrew package for vulnerabilities.

        Note: For Homebrew, the 'ecosystem' parameter is ignored since
        all Homebrew packages use the same GIT ecosystem approach.

        Args:
            package: Package name.
            version: Package version.
            ecosystem: Ignored for Homebrew.
            session: Shared aiohttp session.
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult containing ThreatRecord objects (empty if none found).
        """
        # Get the repo URL for the package
        try:

            def _brew_info_sync() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["brew", "info", package, "--json=v2"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            result = await asyncio.to_thread(_brew_info_sync)
            if result.returncode != 0:
                logger.warning("Failed to get info for %s", package)
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

            data = json.loads(result.stdout)
            formulae = data.get("formulae", [])
            if not formulae:
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

            formula = formulae[0]
            parsed = _parse_brew_formula(formula)
            if parsed is None:
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

            name, repo_url, _ = parsed

            records = await check_brew_package(name, version, repo_url, session)
            return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)

        except BrewNotInstalledError:
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
        except Exception as e:
            logger.warning("Failed to check package %s: %s", package, e)
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
