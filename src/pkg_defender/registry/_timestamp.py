"""Centralized timestamp resolution across multiple fallback sources.

Provides a single TimestampResolver class that all ecosystem adapters
use for fallback timestamp lookups. The resolver implements a 3-tier
fallback chain:
    1. Libraries.io — per-version, no authentication required, 6 platforms
    2. GitHub Releases API (single /releases/tags/{tag} call)
    3. GitHub Tags API → Commits API (paginated tag list → commit date)
    4. (None, "unresolved") — honest unknown (user can manually fill in)

The resolver tracks per-session error codes via ``get_session_errors()``
(e.g., ``{"rate_limited"}``) for user-facing degradation warnings.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import aiohttp

from pkg_defender._http import fetch_json

logger = logging.getLogger(__name__)

# ── Cache settings ──────────────────────────────────────────────────
# TTL cache for resolve_timestamp: avoids redundant API calls for the
# same (package, version) pair within a short window.
_TIMESTAMP_CACHE_TTL: float = 60.0  # seconds
_timestamp_cache: dict[tuple[str, str], tuple[ResolutionResult, float]] = {}

# Rate-limit cache: after receiving a 403 from a domain, skip further
# requests to that domain for a window.
_RATE_LIMIT_CACHE_TTL: float = 300.0  # seconds (5 minutes)
_rate_limited_domains: dict[str, float] = {}  # domain -> expiry time


def _is_cache_valid(expiry: float) -> bool:
    """Check if a cache entry with the given expiry time is still valid."""
    return time.monotonic() < expiry


def _reset_timestamp_caches() -> None:
    """Clear TTL and rate-limit caches. **Test-only API.**

    Production code MUST NOT call this. Tests should call it in a
    fixture to prevent cache state from leaking between cases.
    """
    global _resolver
    _timestamp_cache.clear()
    _rate_limited_domains.clear()
    _resolver = None


# ── Source label constants ──────────────────────────────────────────
SOURCE_GITHUB_RELEASES = "github_releases"
SOURCE_GITHUB_TAGS = "github_tags"
SOURCE_LIBRARIES_IO = "libraries_io"
SOURCE_NONE = "unresolved"

# Semantic failure-category source labels — used when resolution fails so
# that downstream consumers (cache writer, display layer, trust mapping)
# can distinguish *why* the timestamp is missing.
SOURCE_FAILED_ALL = "all_sources_failed"
SOURCE_FAILED_NO_GITHUB = "no_github_url"
SOURCE_FAILED_RATE_LIMITED = "rate_limited"
SOURCE_FAILED_NOT_FOUND = "not_found"
SOURCE_FAILED_TIMEOUT = "timeout"
SOURCE_FAILED_NETWORK = "network_error"

# Map resolution_status → source_label for the all-tiers-failed path.
_STATUS_TO_SOURCE_LABEL: dict[str, str] = {
    "all_sources_failed": SOURCE_FAILED_ALL,
    "no_github_url": SOURCE_FAILED_NO_GITHUB,
    "rate_limited": SOURCE_FAILED_RATE_LIMITED,
    "not_found": SOURCE_FAILED_NOT_FOUND,
    "timeout": SOURCE_FAILED_TIMEOUT,
    "network_error": SOURCE_FAILED_NETWORK,
    "server_error": SOURCE_FAILED_NETWORK,
}


# ── Resolution result ───────────────────────────────────────────────
@dataclass
class ResolutionResult:
    """Structured result from timestamp resolution with per-tier failure info.

    Preserves the full resolution pipeline state so that downstream consumers
    (cache writer, display layer, cooldown check) can make informed decisions.

    Attributes:
        publish_time: Resolved datetime, or ``None`` when resolution failed.
        source_label: The tier that succeeded (e.g., ``"github_tags"``) or a
            failure category (e.g., ``"rate_limited"``).
        resolution_status: Machine-readable status — one of ``"resolved"``,
            ``"all_sources_failed"``, ``"rate_limited"``, ``"timeout"``,
            ``"network_error"``, ``"not_found"``, ``"no_github_url"``, or
            ``"unknown_error"``.
        last_error: Human-readable error detail from the last ``_fetch_json``
            call, or ``None`` on success.
        tiers_attempted: Ordered list of tier names that were tried (e.g.,
            ``["libraries_io", "github_releases", "github_tags"]``).
    """

    publish_time: datetime | None
    source_label: str
    resolution_status: str
    last_error: str | None
    tiers_attempted: list[str] = field(default_factory=list)


# ── GitHub API constants ────────────────────────────────────────────
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RELEASES_URL = f"{GITHUB_API_BASE}/repos"
GITHUB_REQUESTS_DELAY = 0.25  # seconds between requests
MAX_TAG_PAGES = 5  # max pages to paginate (100 per page = 500 tags)
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30

# ── Libraries.io constants ──────────────────────────────────────────
LIBRARIES_IO_BASE = "https://libraries.io/api"

# Platforms that Libraries.io supports
LIBRARIES_IO_PLATFORM_MAP: dict[str, str] = {
    "pypi": "pypi",
    "npm": "npm",
    "rubygems": "rubygems",
    "cargo": "cargo",
    "homebrew": "homebrew",
    "conda": "conda",
    # packagist → NOT supported (Libraries.io returns 404)
    # apt/debian → NOT supported
    # yum/dnf → NOT supported
}


class TimestampResolver:
    """Centralized timestamp resolver with a 3-tier fallback chain.

    Tier 1: Libraries.io — per-version, no API key required, 6 platforms.
    Tier 2: GitHub Releases API — single endpoint, fast, ~40% success.
    Tier 3: GitHub Tags → Commits API — paginated tag list, near-100%
            success for any repo with tags.

    Per-session error types (e.g., ``"rate_limited"``) are tracked via
    ``_session_errors: set[str]`` and exposed through ``get_session_errors()``
    for user-facing degradation warnings in the dispatcher.

    Args:
        github_token: Optional GitHub PAT to raise rate limit from
            60 to 5,000 req/hr. Falls back to PKGD_GITHUB_TOKEN env var.
        libraries_io_key: Optional Libraries.io API key. Without this,
            Tier 3 is skipped entirely.
    """

    def __init__(
        self,
        github_token: str | None = None,
        libraries_io_key: str | None = None,
    ) -> None:
        self._github_token = github_token or os.environ.get("PKGD_GITHUB_TOKEN")
        self._libraries_io_key = libraries_io_key or os.environ.get("PKGD_LIBRARIES_IO_KEY")
        self._session_errors: set[str] = set()
        self._last_failure_reason: str | None = None

    async def resolve(
        self,
        package: str,
        version: str,
        github_url: str | None,
        session: aiohttp.ClientSession,
        is_latest: bool = False,
        ecosystem: str | None = None,
    ) -> ResolutionResult:
        """Resolve a publish timestamp for *package* at *version*.

        Args:
            package: Package name.
            version: Exact version string.
            github_url: Full GitHub repository URL (e.g.,
                'https://github.com/psf/requests'), or None if unknown.
            session: Shared aiohttp ClientSession.
            is_latest: Reserved for future use (Libraries.io now performs
                per-version matching and does not gate on this flag).
            ecosystem: Internal ecosystem name (e.g., 'pypi', 'homebrew').
                Required for Tier 1 (Libraries.io platform lookup).

        Returns:
            A :class:`ResolutionResult` containing the publish time, source
            label, resolution status, last error, and list of tiers attempted.
        """
        self._last_failure_reason = None
        tiers_attempted: list[str] = []

        # Tier 1: Libraries.io — per-version, no API key needed, 6 platforms
        if ecosystem:
            platform = LIBRARIES_IO_PLATFORM_MAP.get(ecosystem)
            if platform:
                tiers_attempted.append(SOURCE_LIBRARIES_IO)
                dt = await self._try_libraries_io(platform, package, version, session)
                if dt:
                    return ResolutionResult(
                        publish_time=dt,
                        source_label=SOURCE_LIBRARIES_IO,
                        resolution_status="resolved",
                        last_error=None,
                        tiers_attempted=tiers_attempted,
                    )

        # Tier 2: GitHub Releases API
        if github_url:
            tiers_attempted.append(SOURCE_GITHUB_RELEASES)
            dt = await self._try_github_release(github_url, version, session, ecosystem=ecosystem)
            if dt:
                return ResolutionResult(
                    publish_time=dt,
                    source_label=SOURCE_GITHUB_RELEASES,
                    resolution_status="resolved",
                    last_error=None,
                    tiers_attempted=tiers_attempted,
                )

            # Tier 3: GitHub Tags → Commits API
            tiers_attempted.append(SOURCE_GITHUB_TAGS)
            dt = await self._try_github_tags_commits(github_url, version, session, ecosystem=ecosystem)
            if dt:
                return ResolutionResult(
                    publish_time=dt,
                    source_label=SOURCE_GITHUB_TAGS,
                    resolution_status="resolved",
                    last_error=None,
                    tiers_attempted=tiers_attempted,
                )

        # All tiers failed — derive resolution_status from session errors and
        # the last failure reason captured by the tier methods.
        resolution_status = self._derive_resolution_status(github_url)
        source_label = _STATUS_TO_SOURCE_LABEL.get(resolution_status, SOURCE_NONE)

        logger.debug(
            "Resolver status=all_failed ecosystem=%s pkg=%s ver=%s resolution_status=%s",
            ecosystem,
            package,
            version,
            resolution_status,
        )
        return ResolutionResult(
            publish_time=None,
            source_label=source_label,
            resolution_status=resolution_status,
            last_error=self._last_failure_reason,
            tiers_attempted=tiers_attempted,
        )

    def get_session_errors(self) -> set[str]:
        """Return error codes collected during this resolution session.

        Returns a copy of the internal set so callers cannot mutate it.
        Currently populated error codes:
        - ``"rate_limited"``: GitHub API returned 403 (unauthenticated rate
          limit hit, 60 req/hr exceeded)
        """
        return self._session_errors.copy()

    def _derive_resolution_status(self, github_url: str | None) -> str:
        """Derive ``resolution_status`` from session errors and last failure.

        Priority order:
        1. ``"no_github_url"`` — no repository URL was available
        2. ``"rate_limited"`` — rate limit was hit during the session
        3. Last ``_fetch_json`` failure reason (``"not_found"``,
           ``"timeout"``, ``"network_error"``, ``"server_error"``)
        4. ``"all_sources_failed"`` — fallback

        Args:
            github_url: The GitHub URL provided to the resolver, or ``None``.

        Returns:
            A valid ``resolution_status`` string.
        """
        if github_url is None:
            return "no_github_url"
        if "rate_limited" in self._session_errors:
            return "rate_limited"
        if self._last_failure_reason in (
            "not_found",
            "timeout",
            "network_error",
            "server_error",
        ):
            return self._last_failure_reason
        return "all_sources_failed"

    # ── Tier 2: GitHub Releases API ─────────────────────────────────

    async def _try_github_release(
        self,
        github_url: str,
        version: str,
        session: aiohttp.ClientSession,
        ecosystem: str | None = None,
    ) -> datetime | None:
        """Try to get release date from GitHub Releases API.

        GET /repos/{owner}/{repo}/releases/tags/{tag}
        Tries 3 tag formats: version, v{version}, version.lstrip('v').
        """
        _eco = ecosystem or "unknown"
        logger.debug(
            "Tier=github_releases status=attempt github_url=%s ver=%s",
            github_url,
            version,
        )

        parsed = self._parse_repo_url(github_url)
        if not parsed:
            return None
        owner, repo = parsed

        tags_to_try = [version]
        if not version.startswith("v"):
            tags_to_try.append(f"v{version}")
        stripped = version.lstrip("v")
        if stripped != version:
            tags_to_try.append(stripped)
        tags_to_try = list(dict.fromkeys(tags_to_try))  # deduplicate

        headers = self._github_headers()

        for tag in tags_to_try:
            url = f"{GITHUB_RELEASES_URL}/{owner}/{repo}/releases/tags/{tag}"
            data, reason = await self._fetch_json(url, session, headers, manager=ecosystem)
            if not isinstance(data, dict):
                if reason is not None:
                    self._last_failure_reason = reason
                continue
            published_at = data.get("published_at")
            if published_at:
                logger.debug(
                    "Tier=github_releases status=success github_url=%s ver=%s tag=%s",
                    github_url,
                    version,
                    tag,
                )
                return self._parse_github_datetime(published_at)

        logger.debug(
            "Tier=github_releases status=failure_not_found github_url=%s ver=%s (all tag formats exhausted: %s)",
            github_url,
            version,
            tags_to_try,
        )
        return None

    # ── Tier 3: GitHub Tags → Commits API ───────────────────────────

    async def _try_github_tags_commits(
        self,
        github_url: str,
        version: str,
        session: aiohttp.ClientSession,
        ecosystem: str | None = None,
    ) -> datetime | None:
        """Try to get release date from GitHub Tags API → commit date.

        GET /repos/{owner}/{repo}/tags?per_page=100 (paginated up to 500)
        → find matching tag → GET /repos/{owner}/{repo}/commits/{sha}
        → read commit.committer.date
        """
        _eco = ecosystem or "unknown"
        logger.debug(
            "Tier=github_tags status=attempt github_url=%s ver=%s",
            github_url,
            version,
        )

        parsed = self._parse_repo_url(github_url)
        if not parsed:
            return None
        owner, repo = parsed

        headers = self._github_headers()
        normalized_version = self._normalize_version(version)

        base_url = f"{GITHUB_RELEASES_URL}/{owner}/{repo}/tags"
        for page in range(1, MAX_TAG_PAGES + 1):
            url = f"{base_url}?per_page=100&page={page}"
            data, reason = await self._fetch_json(url, session, headers, manager=ecosystem)
            if data is None:
                if reason is not None:
                    self._last_failure_reason = reason
                logger.debug(
                    "Tier=github_tags status=failure_%s github_url=%s page=%d",
                    reason,
                    github_url,
                    page,
                )
                break

            tags = data if isinstance(data, list) else data.get("tags", []) if isinstance(data, dict) else []

            for tag_entry in tags:
                tag_name = tag_entry.get("name", "")
                if not tag_name:
                    continue
                if self._match_tag_to_version(tag_name, normalized_version):
                    commit = tag_entry.get("commit", {})
                    commit_sha = commit.get("sha") if isinstance(commit, dict) else None
                    if commit_sha:
                        commit_dt = await self._get_commit_date(
                            owner,
                            repo,
                            commit_sha,
                            session,
                            headers,
                            ecosystem=_eco,
                        )
                        if commit_dt:
                            logger.debug(
                                "Tier=github_tags status=success github_url=%s ver=%s tag=%s",
                                github_url,
                                version,
                                tag_name,
                            )
                            return commit_dt

            # Stop if this is the last page (fewer than 100 results)
            if isinstance(data, list) and len(data) < 100:
                break

        logger.debug(
            "Tier=github_tags status=failure_not_found github_url=%s ver=%s (searched %d pages)",
            github_url,
            version,
            MAX_TAG_PAGES,
        )
        return None

    async def _get_commit_date(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        ecosystem: str | None = None,
    ) -> datetime | None:
        """Get commit date from GitHub Commits API."""
        url = f"{GITHUB_RELEASES_URL}/{owner}/{repo}/commits/{commit_sha}"
        data, reason = await self._fetch_json(url, session, headers, manager=ecosystem)
        if data is None:
            logger.debug(
                "Tier=github_tags status=failure_%s commit_sha=%s/%s@%s",
                reason,
                owner,
                repo,
                commit_sha,
            )
            return None
        commit = data.get("commit", {}) if isinstance(data, dict) else {}
        committer = commit.get("committer", {}) if isinstance(commit, dict) else {}
        date_str = committer.get("date")
        if date_str:
            return self._parse_github_datetime(date_str)
        return None

    # ── Tier 1: Libraries.io API ────────────────────────────────────

    async def _try_libraries_io(
        self,
        platform: str,
        package: str,
        version: str,
        session: aiohttp.ClientSession,
    ) -> datetime | None:
        """Try to get publish date for a specific version from Libraries.io.

        GET /api/{platform}/{name}
        Parses versions[*].published_at for the matching version number.
        API key is optional (for higher rate limits) but not required.
        """
        logger.debug(
            "Tier=libraries_io status=attempt ecosystem=%s pkg=%s ver=%s",
            platform,
            package,
            version,
        )

        url = f"{LIBRARIES_IO_BASE}/{platform}/{package}"
        if self._libraries_io_key:
            url += f"?api_key={self._libraries_io_key}"
        data, reason = await self._fetch_json(url, session, headers={}, manager=platform)
        if data is None:
            if reason is not None:
                self._last_failure_reason = reason
            logger.debug(
                "Tier=libraries_io status=failure_%s ecosystem=%s pkg=%s ver=%s",
                reason,
                platform,
                package,
                version,
            )
            return None
        versions = data.get("versions", []) if isinstance(data, dict) else []
        for entry in versions:
            if entry.get("number") == version:
                ts = entry.get("published_at")
                if ts:
                    logger.debug(
                        "Tier=libraries_io status=success ecosystem=%s pkg=%s ver=%s",
                        platform,
                        package,
                        version,
                    )
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        logger.debug(
            "Tier=libraries_io status=failure_not_found ecosystem=%s pkg=%s ver=%s",
            platform,
            package,
            version,
        )
        return None

    # ── Helpers ─────────────────────────────────────────────────────

    def _parse_repo_url(self, repo_url: str) -> tuple[str, str] | None:
        """Extract (owner, repo) from a GitHub URL.

        Handles: https://github.com/owner/repo, https://github.com/owner/repo.git,
        git@github.com:owner/repo.git, http://www.github.com/owner/repo.
        """
        from urllib.parse import urlparse

        parsed = urlparse(repo_url)
        if parsed.netloc not in ("github.com", "www.github.com"):
            # Check for git@github.com:user/repo.git format
            match = re.match(r"git@github\.com:([^/]+)/([^/.]+?)(?:\.git)?$", repo_url)
            if match:
                return (match.group(1), match.group(2))
            return None

        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            return None
        owner, repo = path_parts[0], path_parts[1]
        if repo.endswith(".git"):
            repo = repo[:-4]
        if not owner or not repo:
            return None
        return (owner, repo)

    def _normalize_version(self, version: str) -> str:
        """Normalize version: strip v prefix."""
        v = version.strip()
        if v.lower().startswith("v"):
            v = v[1:]
        return v

    def _match_tag_to_version(self, tag_name: str, target_version: str) -> bool:
        """Check if a tag matches the target version.

        Handles: exact match, v-prefix differences, trailing .0 differences
        (e.g., 'v2.31.0' matches '2.31', '2.31.0' matches '2.31').
        """
        normalized_tag = self._normalize_version(tag_name)
        normalized_target = self._normalize_version(target_version)

        if normalized_tag == normalized_target:
            return True

        # Handle trailing .0 differences
        tag_trimmed = normalized_tag.rstrip("0").rstrip(".")
        target_trimmed = normalized_target.rstrip("0").rstrip(".")
        return tag_trimmed == target_trimmed

    def _github_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "pkg-defender/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    async def _fetch_json(
        self,
        url: str,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        manager: str | None = None,
    ) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
        """Fetch JSON from URL with timeout, retry, and rate-limit handling.

        Checks the module-level rate-limit cache before making a request:
        if the URL's domain has returned 403 recently, short-circuits and
        returns ``(None, "rate_limited")`` immediately.

        Returns a tuple of ``(data, failure_reason)``. On success,
        ``failure_reason`` is ``None``. On failure, ``failure_reason`` is
        a string like ``"not_found"``, ``"rate_limited"``,
        ``"network_error"``, ``"timeout"``, ``"server_error"``,
         or ``"unknown_error"``.
        """
        # Check rate-limit cache before making a request
        domain = urlparse(url).hostname or ""
        rl_expiry = _rate_limited_domains.get(domain)
        if rl_expiry is not None and _is_cache_valid(rl_expiry):
            logger.debug(
                "Rate-limit cache hit for %s — short-circuiting request to %s",
                domain,
                url,
            )
            return (None, "rate_limited")

        try:
            result = await fetch_json(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                max_retries=MAX_RETRIES,
                session=session,
                on_404="return_none",
                manager=manager,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 403:
                logger.warning(
                    "GitHub API rate limited (403) on %s. Configure a GitHub token via "
                    "pkgd.toml [feeds] ghsa_token or PKGD_GITHUB_TOKEN env var for "
                    "5,000 req/hr rate limit.",
                    url,
                )
                self._session_errors.add("rate_limited")
                # Cache the rate-limited domain so subsequent requests skip immediately
                _rate_limited_domains[domain] = time.monotonic() + _RATE_LIMIT_CACHE_TTL
                return (None, "rate_limited")
            return (None, "server_error")
        except TimeoutError:
            return (None, "timeout")
        except aiohttp.ClientError:
            return (None, "network_error")
        except Exception:
            logger.exception("Unexpected error fetching %s", url)
            return (None, "unknown_error")
        else:
            if result.status == 404:
                return (None, "not_found")
            return (result.data, None)

    def _parse_github_datetime(self, date_string: str) -> datetime | None:
        """Parse ISO 8601 datetime to UTC-aware datetime."""
        try:
            if not date_string:
                return None
            # Handle 'Z' suffix (GitHub's format)
            cleaned = date_string.replace("Z", "+00:00")
            # Parse with timezone - fromisoformat handles +00:00
            dt = datetime.fromisoformat(cleaned)
            # Convert to UTC
            return dt.astimezone(UTC)
        except (ValueError, TypeError):
            return None


# Module-level singleton
_resolver: TimestampResolver | None = None


async def resolve_timestamp(
    package: str,
    version: str,
    github_url: str | None,
    ecosystem: str,
    session: aiohttp.ClientSession | None = None,
    is_latest: bool = False,
) -> ResolutionResult:
    """Resolve a publish timestamp using the shared :class:`TimestampResolver`.

    Results are cached by ``(package, version)`` for
    :data:`_TIMESTAMP_CACHE_TTL` seconds to avoid redundant API calls.

    Creates a session if none is provided, delegates to the resolver, and
    handles exceptions gracefully. This is the primary entrypoint for
    registry adapters that need timestamp resolution.

    Args:
        package: Package name.
        version: Exact version string.
        github_url: GitHub repository URL, or ``None`` if unknown.
        ecosystem: Ecosystem identifier (e.g. ``"pypi"``, ``"npm"``).
        session: Optional ``aiohttp.ClientSession`` for connection pooling.
        is_latest: Whether this is the latest version.

    Returns:
        A :class:`ResolutionResult` with structured resolution information.
        On exception, returns a failure result with status ``"unknown_error"``.
    """
    # Check TTL cache before making any external requests
    cache_key = (package, version)
    cached = _timestamp_cache.get(cache_key)
    if cached is not None and _is_cache_valid(cached[1]):
        logger.debug(
            "Cache hit for %s %s in ecosystem=%s",
            package,
            version,
            ecosystem,
        )
        return cached[0]

    own_session = session is None
    s = session or aiohttp.ClientSession()
    try:
        resolver = get_resolver()
        result = await resolver.resolve(
            package=package,
            version=version,
            github_url=github_url,
            session=s,
            is_latest=is_latest,
            ecosystem=ecosystem,
        )
        # Store result in cache with TTL
        expiry = time.monotonic() + _TIMESTAMP_CACHE_TTL
        _timestamp_cache[cache_key] = (result, expiry)
        return result
    except Exception as exc:
        logger.debug(
            "%s: TimestampResolver failed for %s %s",
            ecosystem,
            package,
            version,
        )
        return ResolutionResult(
            publish_time=None,
            source_label="unresolved",
            resolution_status="unknown_error",
            last_error=str(exc),
            tiers_attempted=[],
        )
    finally:
        if own_session:
            await s.close()


def get_resolver() -> TimestampResolver:
    """Get or create the shared TimestampResolver singleton.

    Token resolution order:
    1. PKGD_GITHUB_TOKEN environment variable (highest priority)
    2. config.feeds.ghsa_token from pkgd.toml (fallback)
    3. None (unauthenticated — 60 req/hr limit)
    """
    global _resolver
    if _resolver is None:
        github_token = os.environ.get("PKGD_GITHUB_TOKEN")
        if not github_token:
            from pkg_defender.config import load_config

            config = load_config()
            github_token = config.feeds.ghsa_token or None
        _resolver = TimestampResolver(
            github_token=github_token,
            libraries_io_key=os.environ.get("PKGD_LIBRARIES_IO_KEY"),
        )
    return _resolver
