# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Homebrew registry adapter — publish times, version lists, metadata."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.registry._timestamp import resolve_timestamp
from pkg_defender.registry.base import EcosystemCapability, ManagerConfig, RegistryAdapter
from pkg_defender.registry.parsing import BREW_PKG_RE

logger = logging.getLogger(__name__)


# Homebrew API endpoint - uses the hardcoded allowlist from registry_domains.py
BREW_REGISTRY_URL = "https://formulae.brew.sh"
TIMEOUT_SECONDS = 30
MAX_RESPONSE_SIZE_MB = 10

# ── Input validation (SSRF prevention) ──────────────────────────────
# Package name must match BREW_PKG_RE before URL construction.
# This prevents path traversal, null-byte injection, and other
# URL manipulation attacks via crafted package names.

# ruby_source_path must match Homebrew's formula file layout.
# Rejects any value that could cause path traversal in GitHub API URLs.
BREW_RUBY_SOURCE_PATH_RE = re.compile(r"^Formula/[a-z]/[a-z0-9._-]+\.rb$")

# tap must follow Homebrew's "owner/repo" format.
BREW_TAP_RE = re.compile(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$")

# Whitelist: only these taps map to known GitHub repositories.
# All other taps are rejected to prevent arbitrary GitHub API calls.
BREW_TAP_WHITELIST: dict[str, str] = {
    "homebrew/core": "Homebrew/homebrew-core",
    "homebrew/cask": "Homebrew/homebrew-cask",
}


async def _brew_fetch(
    url: str,
    session: aiohttp.ClientSession | None = None,
    on_404: Literal["raise", "return_none"] = "raise",
    manager: str | None = "brew",
) -> dict[str, Any] | None:
    """Fetch JSON from Homebrew API with retry logic.

    Args:
        url: The URL to fetch from.
        session: Optional existing aiohttp session for connection reuse.
        on_404: Behavior when the server returns HTTP 404.
            ``"raise"`` (default) propagates the error to the caller;
            ``"return_none"`` returns ``None`` so callers can implement
            fallback chains (e.g., try multiple tag formats against the
            GitHub Releases API).

    Returns:
        Parsed JSON response as a dictionary, or ``None`` if
        ``on_404="return_none"`` and the server returned 404.

    Raises:
        aiohttp.ClientResponseError: On HTTP errors (4xx, 5xx) when
            ``on_404="raise"`` (the default). 404 is not raised when
            ``on_404="return_none"``.
        aiohttp.ClientError: On other client errors.
        asyncio.TimeoutError: On request timeout.
    """
    from pkg_defender._http import fetch_json as _fetch_json_impl

    result = await _fetch_json_impl(
        url,
        timeout=30,
        max_retries=3,
        session=session,
        on_404=on_404,
        manager=manager,
    )
    if not result.success:
        raise RuntimeError(f"Failed to fetch {url}: {result.error}")
    if result.data is None:
        return None
    return dict(result.data)


class BrewAdapter(RegistryAdapter):
    """Adapter for the Homebrew Formulae JSON API."""

    ecosystem: str = "homebrew"
    registry_base_url: str = BREW_REGISTRY_URL

    config: ClassVar[ManagerConfig] = ManagerConfig(
        ecosystem="homebrew",
        registry_url=BREW_REGISTRY_URL,
        capabilities=[
            EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS,
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

        Uses the GitHub Releases API \u2192 Tags API \u2192 Libraries.io fallback
        chain via the shared TimestampResolver.

        Supports ``PKGD_GITHUB_TOKEN`` environment variable for
        authenticated GitHub API access (recommended to avoid rate
        limiting).

        Args:
            package: Homebrew formula name.
            version: Exact version string.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Tuple of (publish_time, date_source) where date_source is one of:
            - "github_releases" (Tier 1: GitHub Releases API)
            - "github_tags" (Tier 2: GitHub Tags \u2192 Commits)
            - "libraries_io" (Tier 3: Libraries.io, latest only)
            - "unresolved" (all sources failed)
        """
        # SSRF prevention: validate package name before URL construction.
        if not BREW_PKG_RE.match(package):
            logger.warning(
                "brew: rejecting invalid package name %r (SSRF prevention)",
                package,
            )
            return None, "unresolved"

        url = f"{BREW_REGISTRY_URL}/api/formula/{package}.json"
        try:
            data = await _brew_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("brew: registry API failed for %s", package)
            return None, "unresolved"
        if data is None:
            return None, "unresolved"

        # Validate ruby_source_path and tap from API response before use.
        ruby_source_path = data.get("ruby_source_path")
        tap = data.get("tap")

        if ruby_source_path is not None and not BREW_RUBY_SOURCE_PATH_RE.match(str(ruby_source_path)):
            logger.warning(
                "brew: rejecting invalid ruby_source_path %r for %s",
                ruby_source_path,
                package,
            )
            ruby_source_path = None

        if tap is not None and not BREW_TAP_RE.match(str(tap)):
            logger.warning(
                "brew: rejecting invalid tap %r for %s",
                tap,
                package,
            )
            tap = None

        # Tier 0: Homebrew formula commit resolution (fastest, most reliable)
        # Uses ruby_source_path + tap from the API response to query the
        # homebrew-core commit history directly. No GitHub URL extraction needed.
        from pkg_defender.config import load_config

        _config = load_config()
        if _config.enable_homebrew_formula_commit and ruby_source_path and tap and tap in BREW_TAP_WHITELIST:
            ts, label = await self._resolve_via_homebrew_core(package, str(ruby_source_path), str(tap), session)
            if ts is not None:
                return ts, label

        # Extract GitHub repo URL from formula metadata
        repository_url = data.get("repository")
        github_url = str(repository_url) if repository_url and "github.com" in str(repository_url).lower() else None

        # Fallback: extract GitHub URL from urls.stable.url.
        # Many Homebrew formulas (e.g. broot) don't populate the top-level
        # "repository" field but the download URL in urls.stable.url contains
        # the full GitHub archive URL like:
        #   https://github.com/owner/repo/archive/refs/tags/v1.2.3.tar.gz
        if not github_url:
            urls = data.get("urls")
            if isinstance(urls, dict):
                stable_urls = urls.get("stable")
                if isinstance(stable_urls, dict):
                    download_url = stable_urls.get("url")
                    if isinstance(download_url, str) and "github.com" in download_url.lower():
                        from urllib.parse import urlparse as _urlparse

                        _parsed = _urlparse(download_url)
                        _parts = _parsed.path.strip("/").split("/")
                        if len(_parts) >= 2:
                            _repo = _parts[1][:-4] if _parts[1].endswith(".git") else _parts[1]
                            github_url = f"https://github.com/{_parts[0]}/{_repo}"

        # Delegate to shared timestamp resolver
        try:
            ts_result = await resolve_timestamp(
                package=package,
                version=version,
                github_url=github_url,
                ecosystem="homebrew",
                session=session,
                is_latest=is_latest,
            )
            return ts_result.publish_time, ts_result.source_label
        except Exception:
            logger.debug("brew: TimestampResolver failed for %s %s", package, version)
            return (None, "unresolved")

    async def _resolve_via_homebrew_core(
        self,
        package: str,
        ruby_source_path: str,
        tap: str,
        session: aiohttp.ClientSession | None = None,
    ) -> tuple[datetime | None, str]:
        """Resolve publish time via the homebrew-core formula file commit.

        Queries the GitHub Commits API for the most recent commit to the
        formula file in ``homebrew-core``. The commit date reflects when
        the formula was last updated (typically a version bump).

        Note:
            This method accesses ``TimestampResolver._github_headers()`` and
            ``_fetch_json()`` directly rather than constructing headers from
            ``PKGD_GITHUB_TOKEN`` env var. This ensures the rate-limit cache
            (``_rate_limited_domains``) is respected — if GitHub returns 403,
            subsequent resolver tiers short-circuit instead of retrying.

        Args:
            package: Homebrew formula name (for logging).
            ruby_source_path: Path to the formula file in the repo
                (e.g., ``"Formula/a/aview.rb"``). Must match
                ``BREW_RUBY_SOURCE_PATH_RE``.
            tap: Homebrew tap name (e.g., ``"homebrew/core"``). Must be
                in ``BREW_TAP_WHITELIST``.
            session: Optional aiohttp session for connection pooling.
                If ``None``, a session is created and closed automatically
                (following the pattern in ``resolve_timestamp()`` at
                ``_timestamp.py:767-768``).

        Returns:
            Tuple of ``(publish_time, source_label)`` where
            ``source_label`` is ``"homebrew_formula_commit"`` on success,
            or ``(None, "")`` on failure.
        """
        from pkg_defender.registry._timestamp import get_resolver

        github_repo = BREW_TAP_WHITELIST.get(tap)
        if github_repo is None:
            logger.debug(
                "brew: tap %r not in whitelist for %s — skipping homebrew-core resolution",
                tap,
                package,
            )
            return None, ""

        owner, repo = github_repo.split("/", 1)
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?path={ruby_source_path}&per_page=1"

        # _fetch_json() declares session: aiohttp.ClientSession (not Optional),
        # so we must create one if None. This mirrors resolve_timestamp() at
        # _timestamp.py:767-768.
        own_session = session is None
        s = session or aiohttp.ClientSession()
        try:
            resolver = get_resolver()
            headers = resolver._github_headers()
            data, reason = await resolver._fetch_json(url, s, headers, manager="homebrew")
        except Exception:
            logger.debug("brew: failed to get GitHub headers for %s", package)
            return None, ""
        finally:
            if own_session:
                await s.close()

        if reason is not None or data is None:
            logger.debug(
                "brew: homebrew-core commit lookup failed for %s: %s",
                package,
                reason,
            )
            return None, ""

        commits = data
        if not isinstance(commits, list) or len(commits) == 0:
            logger.debug(
                "brew: no commits found for %s in %s",
                package,
                ruby_source_path,
            )
            return None, ""

        commit = commits[0]
        commit_info = commit.get("commit", {}) if isinstance(commit, dict) else {}
        committer = commit_info.get("committer", {}) if isinstance(commit_info, dict) else {}
        date_str = committer.get("date")

        if not date_str:
            logger.debug(
                "brew: no committer date in commit for %s",
                package,
            )
            return None, ""

        # Parse the ISO 8601 date
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")).astimezone(UTC)

        # Log commit message at debug level for accuracy auditing
        commit_message = commit_info.get("message", "")
        logger.debug(
            "brew: homebrew_formula_commit resolved for %s: %s (message: %s)",
            package,
            dt.isoformat(),
            commit_message[:80] if commit_message else "(no message)",
        )

        return dt, "homebrew_formula_commit"

    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Return all published versions with their publish times.

        Fetches formula metadata from the Homebrew API and returns
        the stable version with its approximated publish time
        (generated_date). Note: The Homebrew API only exposes
        the current stable version, not historical versions.

        Note:
            This method uses ``generated_date`` as a proxy for the publish
            time. A warning will be emitted when calling
            :meth:`get_publish_time` to alert users that cooldown checks
            may be slightly inaccurate.

        Args:
            package: Homebrew formula name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            List of :class:`VersionInfo` sorted by publish_time
            descending (newest first), or empty list if the formula
            was not found.
        """
        url = f"{BREW_REGISTRY_URL}/api/formula/{package}.json"
        try:
            data = await _brew_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("brew: registry API failed for %s", package)
            return []
        if data is None:
            return []

        versions: dict[str, Any] = data.get("versions", {})
        stable_version = versions.get("stable")
        if stable_version is None:
            return []

        generated = data.get("generated_date")
        publish_time = (
            datetime.strptime(generated, "%Y-%m-%d").replace(tzinfo=UTC) if generated is not None else datetime.now(UTC)
        )

        return [
            VersionInfo(
                ecosystem="homebrew",
                package_name=package,
                version=stable_version,
                publish_time=publish_time,
            )
        ]

    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Return the latest stable version of *package*.

        Reads ``versions.stable`` from the formula metadata.

        Args:
            package: Homebrew formula name.
            session: Optional aiohttp session for connection pooling.

        Returns:
            Latest stable version string, or ``None`` if the
            formula was not found.
        """
        url = f"{BREW_REGISTRY_URL}/api/formula/{package}.json"
        try:
            data = await _brew_fetch(url, session)
        except (TimeoutError, aiohttp.ClientError):
            logger.debug("brew: registry API failed for %s", package)
            return None
        if data is None:
            return None

        versions: dict[str, Any] = data.get("versions", {})
        return versions.get("stable")

    async def get_installed_version(self, package: str) -> str | None:
        """Return the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if not installed.
        """
        return await brew_get_installed_version(package)


async def get_all_version_timestamps(
    package: str,
    session: aiohttp.ClientSession | None = None,
) -> list[tuple[str, datetime]]:
    """Return publish timestamps for every version of *package*.

    Fetches formula metadata from the Homebrew API and extracts
    available version timestamps. Note: The Homebrew API only
    provides the current stable version, so this returns a single
    entry with the stable version and the generated_date.

    Args:
        package: Homebrew formula name.
        session: Optional aiohttp session for connection pooling.

    Returns:
        List of tuples ``(version, timestamp)``, or empty list if the
        formula was not found.
    """
    url = f"{BREW_REGISTRY_URL}/api/formula/{package}.json"
    try:
        data = await _brew_fetch(url, session)
    except (TimeoutError, aiohttp.ClientError):
        logger.debug("brew: registry API failed for %s", package)
        return []
    if data is None:
        return []

    versions: dict[str, Any] = data.get("versions", {})
    stable_version = versions.get("stable")
    if stable_version is None:
        return []

    generated = data.get("generated_date")
    timestamp = (
        datetime.strptime(generated, "%Y-%m-%d").replace(tzinfo=UTC) if generated is not None else datetime.now(UTC)
    )

    return [(stable_version, timestamp)]


async def brew_get_installed_version(package: str) -> str | None:
    """Return the currently installed version of a Homebrew formula.

    Uses `brew list` to get the installed version from the local formula.

    Args:
        package: Homebrew formula name.

    Returns:
        Installed version string, or None if not installed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "brew",
            "list",
            "--versions",
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
            versions = stdout.strip().split()
            return versions[0] if versions else None
    except Exception:
        logger.debug("brew: failed to get installed version for %s", package)
    return None
