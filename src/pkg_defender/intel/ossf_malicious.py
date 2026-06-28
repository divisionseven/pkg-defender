"""OpenSSF Malicious Packages feed source — fetches known malicious packages.

Two-phase fetch pipeline:
1. GitHub Tree API enumerates the full ``osv/malicious/`` tree.
2. Batch raw-content fetches parse individual OSV 1.5.0 / 1.7.4 JSON files.

Never raises to the caller — all error paths return ``FeedFetchResult``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp

from pkg_defender.config import get_http_timeout, get_max_retries
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# GitHub API endpoints
GITHUB_TREE_URL = "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/ossf/malicious-packages/main"

# OSV path patterns
OSV_PATH_PREFIX = "osv/malicious/"
WITHDRAWN_PATH_PREFIX = "osv/withdrawn/"

# Concurrency
DEFAULT_CONCURRENCY = 10
UNAUTHENTICATED_CONCURRENCY = 2
BATCH_SIZE = 50

# Retryable HTTP statuses (project convention)
RETRYABLE_STATUSES = (429, 500, 502, 503, 504)

# OSV ecosystem → internal ecosystem
OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "Go": "go",
    "crates.io": "cargo",
    "Maven": "maven",
    "Git": "unknown",
    "PyPI": "pypi",
    "NuGet": "nuget",
    "RubyGems": "rubygems",
    "Packagist": "packagist",
    "Vscode": "vscode",
}

# Case-insensitive lookup for path-based fallback (directory names are lowercase)
_OSV_ECOSYSTEM_LOOKUP: dict[str, str] = {k.lower(): v for k, v in OSV_ECOSYSTEM_MAP.items()}

# Internal ecosystem → OSV path prefix
ECOSYSTEM_PATH_MAP: dict[str, str] = {
    "npm": "npm",
    "go": "go",
    "cargo": "crates.io",
    "maven": "maven",
    "pypi": "pypi",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "packagist": "packagist",
    "vscode": "vscode",
    "git": "git",
}

# Fallback URL when no references in the OSV record
_FALLBACK_DETAIL_URL = "https://github.com/ossf/malicious-packages"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_github_headers(config: PKGDConfig | None = None) -> dict[str, str]:
    """Build GitHub API headers, optionally including an auth token.

    Args:
        config: Optional configuration containing ``feeds.ghsa_token``.

    Returns:
        Headers dictionary for GitHub API requests.
    """
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if config and config.feeds.ghsa_token:
        headers["Authorization"] = f"Bearer {config.feeds.ghsa_token}"
    return headers


def _determine_ecosystem_from_path(file_path: str) -> str | None:
    """Extract the internal ecosystem name from an OSV file path.

    The path format is ``osv/malicious/{Ecosystem}/{package}/{file}.json``.

    Uses case-insensitive lookup because directory names in the repository
    are lowercase (``go/``, ``maven/``, ``git/``) while OSV ecosystem keys
    use canonical casing (``"Go"``, ``"Maven"``, ``"Git"``).

    Args:
        file_path: The path within the repository.

    Returns:
        The mapped internal ecosystem name, or ``None`` if unrecognised.
    """
    parts = file_path.split("/")
    if len(parts) < 3:
        return None
    raw_ecosystem = parts[2]  # e.g. "npm", "go", "crates.io"
    return _OSV_ECOSYSTEM_LOOKUP.get(raw_ecosystem.lower())


def _determine_package_from_path(file_path: str) -> str | None:
    """Extract the package name from an OSV file path.

    The path format is ``osv/malicious/{Ecosystem}/{package}/{file}.json``.

    Args:
        file_path: The path within the repository.

    Returns:
        The package name, or ``None`` if the path is malformed.
    """
    parts = file_path.split("/")
    if len(parts) < 4:
        return None
    return parts[3]  # e.g. "evil-pkg"


def _parse_ranges(ranges: list[dict[str, Any]]) -> list[str]:
    """Convert OSV range objects to semver range strings.

    Handles SEMVER, ECOSYSTEM, and GIT range types.  Each range object is
    converted to a string like ``>=0 <1.2.3`` or ``>=1.0.0``.

    Note:
        This implementation captures only the last introduced/fixed pair per
        range object.  OSV events can have multiple pairs (e.g. introduced=0,
        fixed=1.0.0, introduced=2.0.0, fixed=2.1.0), but we only use the most
        recent pair.  This is acceptable because the OSSF malicious-packages
        repo uses simple single-pair ranges in practice.  If multi-range
        support is needed later, refactor to accumulate pairs.

    Args:
        ranges: List of OSV range dicts with ``type`` and ``events``.

    Returns:
        List of range strings (e.g. ``[">=0 <1.2.3"]``).
    """
    result: list[str] = []
    for r in ranges:
        events = r.get("events", [])
        if not events:
            continue

        introduced: str | None = None
        fixed: str | None = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]

        if introduced is not None and fixed is not None:
            result.append(f">={introduced} <{fixed}")
        elif introduced is not None:
            result.append(f">={introduced}")
        elif fixed is not None:
            result.append(f"<{fixed}")

    return result


def _parse_osv_record(
    osv_data: dict[str, Any],
    file_path: str = "",
) -> list[ThreatRecord]:
    """Parse a single OSV JSON dict into ``ThreatRecord`` objects.

    Handles schema versions 1.5.0 and 1.7.4, edge cases (git ecosystem,
    empty affected, null fields), and returns a list because one OSV record
    can theoretically affect multiple packages.

    Args:
        osv_data: The parsed OSV JSON dict.
        file_path: The repository path of the JSON file (used as fallback
            for package/ecosystem when ``affected`` is incomplete).

    Returns:
        List of ``ThreatRecord`` objects (usually one).
    """
    osv_id = osv_data.get("id", "")
    affected_list = osv_data.get("affected", [])

    if not affected_list:
        logger.warning("OSSF Malicious: record %s has empty or missing affected array, skipping", osv_id)
        return []

    records: list[ThreatRecord] = []
    now = datetime.now(UTC)

    for affected in affected_list:
        package_obj = affected.get("package")
        ecosystem_raw: str | None = None
        package_name: str | None = None

        if package_obj:
            ecosystem_raw = package_obj.get("ecosystem")
            package_name = package_obj.get("name")

        # Fallback: derive from file path
        ecosystem_raw_from_path = _determine_ecosystem_from_path(file_path) if not ecosystem_raw else None

        if not package_name:
            package_name = _determine_package_from_path(file_path)

        # Map ecosystem
        if ecosystem_raw:
            ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem_raw, "unknown")
        elif ecosystem_raw_from_path:
            ecosystem = ecosystem_raw_from_path
        else:
            ecosystem = "unknown"

        if not package_name:
            package_name = osv_id or "unknown"

        assert package_name is not None

        # Summary fallback
        summary = osv_data.get("summary") or f"Malicious code in {package_name} ({ecosystem})"

        # Dates
        first_seen = now
        published_at = now
        if osv_data.get("published"):
            with contextlib.suppress(ValueError, TypeError):
                first_seen = datetime.fromisoformat(osv_data["published"].replace("Z", "+00:00"))
                published_at = first_seen

        last_seen = now

        # Versions
        affected_versions: list[str] = affected.get("versions", []) or []

        # Ranges
        ranges_raw = affected.get("ranges", []) or []
        affected_ranges = _parse_ranges(ranges_raw)

        # References
        references = osv_data.get("references", []) or []
        detail_url = references[0].get("url", _FALLBACK_DETAIL_URL) if references else _FALLBACK_DETAIL_URL

        record_id = f"ossf_malicious:{ecosystem}:{package_name}"

        records.append(
            ThreatRecord(
                id=record_id,
                ecosystem=ecosystem,
                package_name=package_name,
                affected_versions=affected_versions,
                affected_ranges=affected_ranges,
                severity="CRITICAL",
                confidence=1.0,
                source="ossf_malicious",
                source_id=osv_id,
                summary=summary,
                detail_url=detail_url,
                first_seen=first_seen,
                last_seen=last_seen,
                hit_count=1,
                cvss_score=None,
                published_at=published_at,
                ingested_at=now,
                is_malicious=True,
                is_unverified=False,
            )
        )

    return records


# ---------------------------------------------------------------------------
# Tree SHA caching helpers
# ---------------------------------------------------------------------------


def _get_stored_tree_sha(db_path: Path) -> str | None:
    """Read the stored OSSF tree SHA from ``db_metadata``.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        The stored tree SHA, or ``None`` if no entry exists.
    """
    from pkg_defender.db.schema import get_connection, get_metadata

    conn = get_connection(db_path)
    try:
        return get_metadata(conn, "ossf_malicious_tree_sha")
    finally:
        conn.close()


def _store_tree_sha(db_path: Path, tree_sha: str) -> None:
    """Persist the OSSF tree SHA to ``db_metadata``.

    Args:
        db_path: Path to the SQLite database.
        tree_sha: The tree SHA to persist.
    """
    from pkg_defender.db.schema import get_connection, set_metadata

    conn = get_connection(db_path)
    try:
        set_metadata(conn, "ossf_malicious_tree_sha", tree_sha)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Feed source
# ---------------------------------------------------------------------------


class OSSFMaliciousFeed(FeedSource):
    """OpenSSF Malicious Packages feed source.

    Fetches the OpenSSF malicious packages dataset from the
    ``ossf/malicious-packages`` GitHub repository.  Returns ThreatRecord
    entries with ``is_malicious=True`` for all confirmed malicious packages.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "ossf_malicious"

    @property
    def supports_incremental(self) -> bool:
        """OSSF malicious dataset is a full dump, not incremental."""
        return False

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if OSSF malicious feed is configured.

        This is a public dataset, so it is always available.

        Args:
            config: The current configuration object.

        Returns:
            True — always available.
        """
        return True

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
        db_path: Path | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> FeedFetchResult:
        """Fetch malicious packages from the OpenSSF repository.

        Two-phase pipeline: enumerate the GitHub tree, then batch-fetch and
        parse individual OSV JSON files.  Returns ThreatRecord entries with
        ``is_malicious=True`` for all confirmed malicious packages.

        When ``db_path`` is provided, the feed caches the GitHub tree SHA
        between syncs.  If the tree SHA is unchanged, Phase 2 (file fetches)
        is skipped entirely — the existing database records are current.

        Args:
            since: Ignored — dataset is a full dump.
            ecosystems: Filter to specific ecosystems (e.g. ``["npm", "go"]``).
            session: Shared aiohttp session (created if ``None``).
            config: Configuration object (injected by aggregator).
            db_path: Optional database path for tree SHA caching.
            progress_callback: Optional callback invoked as
                ``(current_file, total_files)`` during batch fetch.

        Returns:
            FeedFetchResult containing ThreatRecord objects with ``is_malicious=True``.
        """
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=get_http_timeout(config)))

        assert session is not None  # for type checker

        try:
            headers = _get_github_headers(config)
            is_authenticated = "Authorization" in headers

            if not is_authenticated:
                logger.warning(
                    "OSSF Malicious: unauthenticated rate limit (60/hr) will make full sync slow; "
                    "consider setting a GitHub token"
                )

            # --- Phase 1: Enumerate tree ---
            tree_result = await self._enumerate_tree(session, headers, config)
            if tree_result is None:
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

            tree_items, tree_truncated, tree_sha = tree_result

            # Filter to osv/malicious/ paths, excluding withdrawn
            osv_paths = [
                item["path"]
                for item in tree_items
                if item["path"].startswith(OSV_PATH_PREFIX)
                and not item["path"].startswith(WITHDRAWN_PATH_PREFIX)
                and item["path"].endswith(".json")
            ]

            # Apply ecosystem filter at the path level
            if ecosystems:
                prefixes = {
                    f"osv/malicious/{ECOSYSTEM_PATH_MAP[eco]}/" for eco in ecosystems if eco in ECOSYSTEM_PATH_MAP
                }
                if prefixes:
                    osv_paths = [p for p in osv_paths if any(p.startswith(prefix) for prefix in prefixes)]
                else:
                    # None of the requested ecosystems are covered
                    osv_paths = []

            if not osv_paths:
                return FeedFetchResult(
                    records=[],
                    feed_metadata={"tree_truncated": tree_truncated},
                    status=FetchStatus.PARTIAL if tree_truncated else FetchStatus.SUCCESS,
                )

            # --- Tree SHA cache check (skip Phase 2 if unchanged) ---
            if db_path is not None and tree_sha is not None and not tree_truncated:
                stored_sha = await asyncio.to_thread(_get_stored_tree_sha, db_path)
                if stored_sha == tree_sha:
                    logger.info(
                        "OSSF Malicious: tree SHA unchanged (%s), skipping %d file fetches",
                        tree_sha[:12],
                        len(osv_paths),
                    )
                    return FeedFetchResult(
                        records=[],
                        feed_metadata={
                            "tree_sha": tree_sha,
                            "tree_sha_hit": True,
                            "tree_truncated": False,
                        },
                        status=FetchStatus.SUCCESS,
                    )

            # --- Phase 2: Batch fetch + parse ---
            concurrency = DEFAULT_CONCURRENCY if is_authenticated else UNAUTHENTICATED_CONCURRENCY
            batch_sleep = 0.1 if is_authenticated else 0.2

            records, fail_count, skip_count = await self._batch_fetch(
                session,
                headers,
                osv_paths,
                config,
                concurrency,
                batch_sleep,
                progress_callback=progress_callback,
            )

            # Determine status
            success_count = len(records)
            if tree_truncated or (fail_count > 0 and success_count > 0):
                status = FetchStatus.PARTIAL
            elif fail_count > 0 and success_count == 0:
                status = FetchStatus.FAILED
            else:
                status = FetchStatus.SUCCESS

            # Store tree SHA after successful Phase 2 completion
            if db_path is not None and tree_sha is not None:
                await asyncio.to_thread(_store_tree_sha, db_path, tree_sha)

            return FeedFetchResult(
                records=records,
                feed_metadata={
                    "fail_count": fail_count,
                    "skip_count": skip_count,
                    "tree_truncated": tree_truncated,
                },
                status=status,
            )
        finally:
            if own_session:
                await session.close()

    async def _enumerate_tree(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        config: PKGDConfig | None,
    ) -> tuple[list[dict[str, Any]], bool, str | None] | None:
        """Enumerate the GitHub tree with retry logic.

        Args:
            session: The aiohttp session.
            headers: Request headers (including auth).
            config: Configuration for retries/timeout.

        Returns:
            Tuple of (tree items, truncated, tree_sha) on success, or ``None``
            on failure.  The ``tree_sha`` is the top-level ``sha`` field from
            the GitHub Tree API response and uniquely identifies the current
            state of the repository tree.  When ``truncated`` is ``True`` the
            returned list contains only a subset of the full tree — callers
            should expect incomplete data.
        """
        max_retries = get_max_retries(config)

        for attempt in range(max_retries):
            try:
                resp = await session.get(GITHUB_TREE_URL, headers=headers)
                status = resp.status

                if status == 200:
                    data: dict[str, Any] = await resp.json()
                    truncated = bool(data.get("truncated"))
                    if truncated:
                        tree_count = len(data.get("tree", []))
                        logger.warning(
                            "OSSF Malicious: GitHub tree response is truncated "
                            "(%d entries returned); data is incomplete",
                            tree_count,
                        )
                    tree: list[dict[str, Any]] = data.get("tree", [])
                    tree_sha: str | None = data.get("sha")
                    return tree, truncated, tree_sha

                if status == 404:
                    logger.error("OSSF Malicious: GitHub tree 404 — repo may have been renamed or deleted")
                    return None

                if status in RETRYABLE_STATUSES:
                    retry_after = resp.headers.get("Retry-After")
                    wait = int(retry_after) if retry_after else min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious API GET %s returned %d; retry %d/%d in %ds",
                        GITHUB_TREE_URL,
                        status,
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                # Non-retryable error (e.g. 403)
                logger.error("OSSF Malicious: GitHub tree returned non-retryable status %d", status)
                return None

            except (aiohttp.ClientError, TimeoutError) as exc:
                if attempt < max_retries - 1:
                    wait = min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious API GET %s failed: %s; retry %d/%d in %ds",
                        GITHUB_TREE_URL,
                        repr(exc),
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "OSSF Malicious: GitHub tree request failed after %d retries: %s",
                        max_retries,
                        repr(exc),
                    )
                    return None

        return None

    async def _batch_fetch(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        osv_paths: list[str],
        config: PKGDConfig | None,
        concurrency: int,
        batch_sleep: float,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> tuple[list[ThreatRecord], int, int]:
        """Batch-fetch OSV files with semaphore-bounded concurrency.

        Args:
            session: The aiohttp session.
            headers: Request headers.
            osv_paths: List of file paths to fetch.
            config: Configuration for retries/timeout.
            concurrency: Max concurrent requests (semaphore size).
            batch_sleep: Sleep duration between batches.
            progress_callback: Optional callback invoked as
                ``(current_file, total_files)`` after each file fetch.

        Returns:
            Tuple of (records, fail_count, skip_count).
        """
        semaphore = asyncio.Semaphore(concurrency)
        max_retries = get_max_retries(config)

        all_records: list[ThreatRecord] = []
        fail_count = 0
        skip_count = 0

        # Process in batches
        for batch_start in range(0, len(osv_paths), BATCH_SIZE):
            batch = osv_paths[batch_start : batch_start + BATCH_SIZE]

            results = await asyncio.gather(
                *[self._fetch_single_file(session, headers, path, config, semaphore, max_retries) for path in batch],
                return_exceptions=False,
            )

            for i, result in enumerate(results):
                if result is None:
                    fail_count += 1
                elif isinstance(result, list):
                    all_records.extend(result)
                else:
                    # Should not happen, but handle gracefully
                    skip_count += 1

                # Report progress per file
                if progress_callback is not None:
                    progress_callback(batch_start + i + 1, len(osv_paths))

            # Yield control between batches
            if batch_start + BATCH_SIZE < len(osv_paths):
                await asyncio.sleep(batch_sleep)

        return all_records, fail_count, skip_count

    async def _fetch_single_file(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        file_path: str,
        config: PKGDConfig | None,
        semaphore: asyncio.Semaphore,
        max_retries: int,
    ) -> list[ThreatRecord] | None:
        """Fetch and parse a single OSV JSON file.

        Args:
            session: The aiohttp session.
            headers: Request headers.
            file_path: Path within the repository.
            config: Configuration for retries/timeout.
            semaphore: Concurrency limiter.
            max_retries: Maximum retry attempts.

        Returns:
            List of ThreatRecords on success, or ``None`` on failure.
        """
        url = f"{GITHUB_RAW_BASE}/{file_path}"

        async with semaphore:
            for attempt in range(max_retries):
                try:
                    resp = await session.get(url, headers=headers)
                    status = resp.status

                    if status == 200:
                        try:
                            osv_data: dict[str, Any] = await resp.json(content_type=None)
                        except Exception:
                            logger.warning("OSSF Malicious: JSON parse error for %s, skipping", file_path)
                            return None
                        return _parse_osv_record(osv_data, file_path=file_path)

                    if status == 404:
                        logger.warning("OSSF Malicious: file %s returned 404 (moved/deleted), skipping", file_path)
                        return None

                    if status == 304:
                        # No change (relevant with ETag caching)
                        return []

                    if status in RETRYABLE_STATUSES:
                        retry_after = resp.headers.get("Retry-After")
                        wait = int(retry_after) if retry_after else min(2**attempt + random.uniform(0, 1), 60)
                        logger.warning(
                            "OSSF Malicious API GET %s returned %d; retry %d/%d in %ds",
                            url,
                            status,
                            attempt + 1,
                            max_retries,
                            wait,
                        )
                        await asyncio.sleep(wait)
                        continue

                    # Non-retryable
                    logger.warning(
                        "OSSF Malicious: file %s returned non-retryable status %d, skipping",
                        file_path,
                        status,
                    )
                    return None

                except (aiohttp.ClientError, TimeoutError) as exc:
                    if attempt < max_retries - 1:
                        wait = min(2**attempt + random.uniform(0, 1), 60)
                        logger.warning(
                            "OSSF Malicious API GET %s failed: %s; retry %d/%d in %ds",
                            url,
                            repr(exc),
                            attempt + 1,
                            max_retries,
                            wait,
                        )
                        await asyncio.sleep(wait)
                    else:
                        logger.warning(
                            "OSSF Malicious: file %s failed after %d retries: %s",
                            file_path,
                            max_retries,
                            repr(exc),
                        )
                        return None

        return None

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Point query — not supported by this feed (bulk-only).

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with FAILED status and empty records — use ``fetch()`` instead.
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
