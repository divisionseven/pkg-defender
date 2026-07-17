# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""GitHub Security Advisory (GHSA) feed source."""

from __future__ import annotations

import contextlib
import logging
import random
from asyncio import sleep as _asyncio_sleep
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import aiohttp

from pkg_defender.config import get_http_timeout, get_max_retries
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger = logging.getLogger(__name__)

GHSA_REST_URL = "https://api.github.com/advisories"
REQUEST_TIMEOUT: int | None = None  # None = use config default


# GHSA ecosystem names → internal ecosystem identifiers
# Note: REST API uses different ecosystem names than GraphQL
ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pip": "pypi",
    "rubygems": "rubygems",
    "cargo": "cargo",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "composer": "composer",
    "pub": "pub",
    "swift": "swift",
}

# Internal ecosystem name → GitHub REST API ecosystem filter value.
# Used by fetch() to translate caller-provided internal names into the
# names GitHub accepts as filter values (e.g., "pypi" → "pip").
# Internal ecosystems that GitHub does not support (e.g., "homebrew",
# "apt", "yum", "dnf", "conda") are intentionally absent so the caller
# can detect and skip them. The forward map (above) is NOT symmetric —
# GitHub's response enum uses "rust" not "cargo", so the reverse map
# must be written from GitHub's filter enum, not derived by inversion.
INTERNAL_TO_GITHUB_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "pip",
    "rubygems": "rubygems",
    "cargo": "rust",
    "composer": "composer",
}

# GHSA severity → internal severity (MODERATE maps to MEDIUM)
SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unknown": "UNKNOWN",
}


def _get_severity(severity: str | None) -> str:
    """Map REST API severity string to internal severity.

    The REST API returns lowercase severity strings.
    """
    if severity is None:
        return "UNKNOWN"
    return SEVERITY_MAP.get(severity.lower(), "UNKNOWN")


# REST API does not require authentication (60 requests/hour rate limit)


def _parse_advisory(
    advisory: dict[str, Any],
    ecosystems: list[str] | None = None,
) -> list[ThreatRecord]:
    """Parse a single GHSA advisory from REST API into ThreatRecord(s).

    One advisory can affect multiple packages across multiple ecosystems,
    so this returns a list of ThreatRecords — one per affected package.

    Args:
        advisory: A single advisory item from the GHSA REST API.
        ecosystems: Optional filter — only include records matching these ecosystems.

    Returns:
        List of ThreatRecord objects (one per affected package).
    """
    ghsa_id: str = advisory.get("ghsa_id", "UNKNOWN")
    summary: str = advisory.get("summary", "")
    severity = _get_severity(advisory.get("severity"))
    permalink: str = advisory.get("html_url", "")

    # Timestamps - REST uses snake_case
    now = datetime.now(UTC)
    first_seen = now
    published_at = advisory.get("published_at")
    if published_at:
        with contextlib.suppress(ValueError, TypeError):
            first_seen = datetime.fromisoformat(published_at.replace("Z", "+00:00"))

    last_seen = now
    updated_at = advisory.get("updated_at")
    if updated_at:
        with contextlib.suppress(ValueError, TypeError):
            last_seen = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))

    records: list[ThreatRecord] = []
    # REST uses direct array, not nested under "nodes"
    vuln_nodes = advisory.get("vulnerabilities", []) or []

    for vuln in vuln_nodes:
        pkg_info = vuln.get("package", {}) or {}
        pkg_name: str = pkg_info.get("name") or ""
        if not pkg_name:
            continue
        ghsa_ecosystem: str = pkg_info.get("ecosystem", "")

        # Map GHSA ecosystem to internal name
        internal_eco = ECOSYSTEM_MAP.get(ghsa_ecosystem)
        if internal_eco is None:
            logger.debug("Skipping unknown GHSA ecosystem %r for %s", ghsa_ecosystem, ghsa_id)
            continue

        # Apply ecosystem filter
        if ecosystems is not None and internal_eco not in ecosystems:
            continue

        # Extract version range
        affected_ranges: list[str] = []
        version_range = vuln.get("vulnerable_version_range", "")
        if version_range:
            affected_ranges.append(version_range)

        # Extract patched version info
        patched = vuln.get("first_patched_version")
        if patched and isinstance(patched, str) and patched:
            affected_ranges.append(f"<{patched}")

        record = ThreatRecord(
            id=f"ghsa:{ghsa_id}:{pkg_name}",
            ecosystem=internal_eco,
            package_name=pkg_name,
            affected_versions=[],
            affected_ranges=affected_ranges,
            severity=severity,
            confidence=0.85,  # High quality but not as structured as OSV
            source="ghsa",
            source_id=ghsa_id,
            summary=summary,
            detail_url=permalink,
            first_seen=first_seen,
            last_seen=last_seen,
            hit_count=1,
            cvss_score=None,
            published_at=first_seen,
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )
        records.append(record)

    return records


class GHSAFeed(FeedSource):
    """GitHub Security Advisory feed source.

    Uses the GitHub REST API to fetch security advisories in bulk.
    Supports cursor-based pagination and incremental sync via ``updated``
    query parameter. No authentication required (60 requests/hour rate limit).

    Auth: None required (uses unauthenticated rate limit).
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "ghsa"

    @property
    def supports_incremental(self) -> bool:
        """GHSA supports incremental sync via updated filter."""
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if GHSA feed is configured.

        GHSA doesn't strictly require a token but having one increases rate limit.
        For simplicity, we always return True as it's a public API.

        Args:
            config: The current configuration object.

        Returns:
            True — GHSA is a public API.
        """
        return True

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch security advisories from GHSA.

        Uses REST API with cursor-based pagination. Advisories are filtered
        by ``updated >= since``.

        Args:
            since: Only fetch advisories updated after this time.
                Defaults to 24 hours ago if None.
            ecosystems: Filter to specific ecosystems (e.g. ``["npm", "pypi"]``).
            session: Shared aiohttp session (created if None).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult containing records and fetch metadata.
        """
        # REST API doesn't require authentication
        if since is None:
            since = datetime.now(UTC) - timedelta(hours=24)

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                )
            )

        assert session is not None  # for type checker

        try:
            records: list[ThreatRecord] = []
            # Build query params
            params: dict[str, str] = {
                "per_page": "100",
                "sort": "updated",
                "direction": "desc",
            }
            # Use ISO date format for the updated filter
            params["updated"] = f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}"

            # Add ecosystem filter if specified — translate internal names
            # to GitHub-accepted filter values (e.g., "pypi" → "pip").
            # Internal ecosystems that GitHub does not support (e.g.,
            # "homebrew", "apt", "yum", "dnf", "conda") are filtered out
            # so the request doesn't 422 on an unknown ecosystem value.
            if ecosystems:
                mapped = [INTERNAL_TO_GITHUB_ECOSYSTEM.get(eco) for eco in ecosystems]
                github_ecosystems = [m for m in mapped if m is not None]
                if not github_ecosystems:
                    logger.debug(
                        "GHSA: no ecosystems supported by GitHub (input: %s) — fetching all advisories",
                        ecosystems,
                    )
                else:
                    # REST API accepts comma-separated ecosystems
                    params["ecosystem"] = ",".join(github_ecosystems)

            while True:
                advisories, next_cursor = await _rest_fetch_with_link(params, session, config)

                for advisory in advisories:
                    records.extend(_parse_advisory(advisory, ecosystems))

                if next_cursor is None:
                    break

                # Use the cursor for next page
                params = params.copy()
                params["after"] = next_cursor

            return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)
        finally:
            if own_session:
                await session.close()

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Point query — not supported by GHSA (bulk-only API).

        GHSA does not provide a point query API. Callers should use
        ``fetch()`` and look up results from the local DB.

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult containing records and fetch metadata.
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)


async def _rest_fetch_with_link(
    params: dict[str, str],
    session: aiohttp.ClientSession,
    config: PKGDConfig | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch advisories from the GitHub REST API with Link header parsing.

    Args:
        params: Query parameters for the request.
        session: aiohttp session to use.
        config: Configuration object for authentication.

    Returns:
        Tuple of (list of advisory dicts, next cursor or None).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Add authentication token if configured
    if config and config.feeds.ghsa_token:
        headers["Authorization"] = f"Bearer {config.feeds.ghsa_token}"

    _max_retries = get_max_retries(config)
    last_exc: Exception | None = None
    for attempt in range(_max_retries):
        try:
            resp = await session.get(
                GHSA_REST_URL,
                params=params,
                headers=headers,
            )

            # Handle rate limiting — retryable
            if resp.status == 429:
                last_exc = aiohttp.ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=429,
                    message="Rate limited",
                )
                if attempt < _max_retries - 1:
                    # Check for Retry-After header
                    retry_after = resp.headers.get("Retry-After", "60")
                    try:
                        wait = int(retry_after)
                    except ValueError:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "GHSA API rate limited; retry %d/%d in %ds",
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await _asyncio_sleep(wait)
                    continue
                raise last_exc

            resp.raise_for_status()
            data: list[dict[str, Any]] = await resp.json()
            next_cursor = _parse_link_header(resp)
            return data, next_cursor

        except aiohttp.ClientResponseError as exc:
            if exc.status in (500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    wait = 2**attempt + random.uniform(0, 1)  # 1-1.99s, 2-2.99s, 4-4.99s
                    logger.warning(
                        "GHSA API returned %d; retry %d/%d in %ds",
                        exc.status,
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await _asyncio_sleep(wait)
                    continue
                else:
                    raise
            raise

        except (aiohttp.ClientError, TimeoutError) as exc:
            last_exc = exc
            if attempt < _max_retries - 1:
                wait = 2**attempt + random.uniform(0, 1)
                logger.warning(
                    "GHSA API request failed: %s; retry %d/%d in %ds",
                    repr(exc),
                    attempt + 1,
                    _max_retries,
                    wait,
                )
                await _asyncio_sleep(wait)
                continue
            else:
                raise

    if last_exc:
        raise last_exc
    raise RuntimeError("Failed to fetch GHSA after retries")


def _parse_link_header(response: aiohttp.ClientResponse) -> str | None:
    """Extract the 'after' cursor from the Link header.

    Args:
        response: The HTTP response object.

    Returns:
        The cursor string for the next page, or None if no more pages.
    """
    link_header = response.headers.get("Link")
    if not link_header:
        return None

    # Parse Link header: <url>; rel="next", <url>; rel="last", etc.
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            # Extract URL from <url>
            url_match = part.split(";")[0].strip()
            if url_match.startswith("<") and url_match.endswith(">"):
                url = url_match[1:-1]
                # Parse 'after' param from URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                after_list = params.get("after")
                if after_list:
                    return after_list[0]
    return None
