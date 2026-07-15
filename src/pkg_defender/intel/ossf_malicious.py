# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""OpenSSF Malicious Packages feed source — fetches known malicious packages.

Single-phase fetch pipeline:

1. Fetch the latest commit SHA for ``main`` (one cheap API call) to check
   whether anything has changed since the last sync.
2. If changed, download the full repository as a gzip tarball from
   GitHub's codeload service and stream-extract only the
   ``osv/malicious/**/*.json`` files, parsing each into ThreatRecords.

This intentionally avoids the GitHub Git Trees API. The Trees API
truncates its response once it exceeds ~7MB / 100k entries, which the
``ossf/malicious-packages`` repo has grown past — any tree-based
enumeration silently returns incomplete data. It also replaces tens of
thousands of individual raw-file HTTP requests with a single streamed
archive download, which is both dramatically faster and immune to
per-file rate limiting.

Never raises to the caller — all error paths return ``FeedFetchResult``.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import random
import tarfile
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

# GitHub API — used only for the cheap "has anything changed" check.
GITHUB_COMMIT_URL = "https://api.github.com/repos/ossf/malicious-packages/commits/main"

# Codeload — single-request tarball of the full repo at a given ref.
CODELOAD_TARBALL_URL = "https://codeload.github.com/ossf/malicious-packages/tar.gz/{ref}"

# OSV path patterns (relative to the repo root, i.e. with the archive's
# top-level "<repo>-<sha>/" directory already stripped off).
OSV_PATH_PREFIX = "osv/malicious/"
WITHDRAWN_PATH_PREFIX = "osv/withdrawn/"

# Retryable HTTP statuses (project convention)
RETRYABLE_STATUSES = (429, 500, 502, 503, 504)

# How often to invoke progress_callback while streaming the archive.
# NOTE: the total file count isn't known until the archive is fully read
# (unlike the old Tree API response), so progress is reported as
# (processed_so_far, processed_so_far) — a heartbeat, not a fraction.
PROGRESS_REPORT_INTERVAL = 500

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
        Headers dictionary for GitHub API / codeload requests.
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

    Handles SEMVER, ECOSYSTEM, and GIT range types. Each range object is
    converted to a string like ``>=0 <1.2.3`` or ``>=1.0.0``.

    Note:
        This implementation captures only the last introduced/fixed pair per
        range object. OSV events can have multiple pairs (e.g. introduced=0,
        fixed=1.0.0, introduced=2.0.0, fixed=2.1.0), but we only use the most
        recent pair. This is acceptable because the OSSF malicious-packages
        repo uses simple single-pair ranges in practice. If multi-range
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
        file_path: The repository-relative path of the JSON file (used as
            fallback for package/ecosystem when ``affected`` is incomplete).

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
# Commit SHA caching helpers
# ---------------------------------------------------------------------------


def _get_stored_commit_sha(db_path: Path) -> str | None:
    """Read the stored OSSF commit SHA from ``db_metadata``.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        The stored commit SHA, or ``None`` if no entry exists.
    """
    from pkg_defender.db.schema import get_connection, get_metadata

    conn = get_connection(db_path)
    try:
        return get_metadata(conn, "ossf_malicious_commit_sha")
    finally:
        conn.close()


def _store_commit_sha(db_path: Path, commit_sha: str) -> None:
    """Persist the OSSF commit SHA to ``db_metadata``.

    Args:
        db_path: Path to the SQLite database.
        commit_sha: The commit SHA to persist.
    """
    from pkg_defender.db.schema import get_connection, set_metadata

    conn = get_connection(db_path)
    try:
        set_metadata(conn, "ossf_malicious_commit_sha", commit_sha)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Feed source
# ---------------------------------------------------------------------------


class OSSFMaliciousFeed(FeedSource):
    """OpenSSF Malicious Packages feed source.

    Fetches the OpenSSF malicious packages dataset from the
    ``ossf/malicious-packages`` GitHub repository via a single archive
    download. Returns ThreatRecord entries with ``is_malicious=True`` for
    all confirmed malicious packages.
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

        Checks the latest commit SHA for ``main`` first; if it matches the
        cached value, Phase 2 (the archive download) is skipped entirely —
        the existing database records are current. Otherwise downloads the
        full repo as a tarball and stream-extracts the OSV JSON files.

        Args:
            since: Ignored — dataset is a full dump.
            ecosystems: Filter to specific ecosystems (e.g. ``["npm", "go"]``).
            session: Shared aiohttp session (created if ``None``).
            config: Configuration object (injected by aggregator).
            db_path: Optional database path for commit SHA caching.
            progress_callback: Optional callback invoked periodically during
                extraction as ``(processed, processed)`` — the total file
                count isn't known until the archive has been fully read.

        Returns:
            FeedFetchResult containing ThreatRecord objects with ``is_malicious=True``.
        """
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=get_http_timeout(config)))
        assert session is not None  # for type checker

        try:
            headers = _get_github_headers(config)

            # --- Phase 1: cheap "has anything changed?" check ---
            commit_sha = await self._get_latest_commit_sha(session, headers, config)
            if commit_sha is None:
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

            if db_path is not None:
                stored_sha = await asyncio.to_thread(_get_stored_commit_sha, db_path)
                if stored_sha == commit_sha:
                    logger.info(
                        "OSSF Malicious: commit SHA unchanged (%s), skipping archive download",
                        commit_sha[:12],
                    )
                    return FeedFetchResult(
                        records=[],
                        feed_metadata={"commit_sha": commit_sha, "commit_sha_hit": True},
                        status=FetchStatus.SUCCESS,
                    )

            # --- Phase 2: download + stream-extract archive ---
            records, fail_count = await self._download_and_extract(
                session, headers, commit_sha, config, ecosystems, progress_callback=progress_callback
            )

            if fail_count > 0 and not records:
                status = FetchStatus.FAILED
            elif fail_count > 0:
                status = FetchStatus.PARTIAL
            else:
                status = FetchStatus.SUCCESS

            if db_path is not None and status != FetchStatus.FAILED:
                await asyncio.to_thread(_store_commit_sha, db_path, commit_sha)

            return FeedFetchResult(
                records=records,
                feed_metadata={"commit_sha": commit_sha, "fail_count": fail_count},
                status=status,
            )
        finally:
            if own_session:
                await session.close()

    async def _get_latest_commit_sha(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        config: PKGDConfig | None,
    ) -> str | None:
        """Fetch the latest commit SHA for ``main`` with retry logic.

        Args:
            session: The aiohttp session.
            headers: Request headers (including auth).
            config: Configuration for retries/timeout.

        Returns:
            The commit SHA on success, or ``None`` on failure.
        """
        max_retries = get_max_retries(config)
        for attempt in range(max_retries):
            try:
                resp = await session.get(GITHUB_COMMIT_URL, headers=headers)
                status = resp.status
                if status == 200:
                    data: dict[str, Any] = await resp.json()
                    sha = data.get("sha")
                    if not sha:
                        logger.error("OSSF Malicious: commit lookup returned no sha")
                        return None
                    return str(sha)
                if status == 404:
                    logger.error("OSSF Malicious: commit lookup 404 — repo may have been renamed or deleted")
                    return None
                if status in RETRYABLE_STATUSES:
                    retry_after = resp.headers.get("Retry-After")
                    wait = int(retry_after) if retry_after else min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious API GET %s returned %d; retry %d/%d in %ds",
                        GITHUB_COMMIT_URL,
                        status,
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                # Non-retryable error (e.g. 403)
                logger.error("OSSF Malicious: commit lookup returned non-retryable status %d", status)
                return None
            except (aiohttp.ClientError, TimeoutError) as exc:
                if attempt < max_retries - 1:
                    wait = min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious API GET %s failed: %s; retry %d/%d in %ds",
                        GITHUB_COMMIT_URL,
                        repr(exc),
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "OSSF Malicious: commit lookup failed after %d retries: %s",
                        max_retries,
                        repr(exc),
                    )
                    return None
        return None

    async def _download_and_extract(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        commit_sha: str,
        config: PKGDConfig | None,
        ecosystems: list[str] | None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> tuple[list[ThreatRecord], int]:
        """Download the repo tarball and hand off to extraction.

        Args:
            session: The aiohttp session.
            headers: Request headers (including auth).
            commit_sha: The commit SHA to download (pinned so the tarball
                content matches the commit SHA we're about to cache).
            config: Configuration for retries/timeout.
            ecosystems: Filter to specific ecosystems, or ``None`` for all.
            progress_callback: See :meth:`fetch`.

        Returns:
            Tuple of (records, fail_count). ``fail_count`` of 1 with no
            records indicates the download itself failed; higher fail
            counts alongside records indicate individual files within the
            archive that failed to parse.
        """
        url = CODELOAD_TARBALL_URL.format(ref=commit_sha)
        max_retries = get_max_retries(config)

        archive_bytes: bytes | None = None
        for attempt in range(max_retries):
            try:
                resp = await session.get(url, headers=headers)
                status = resp.status
                if status == 200:
                    archive_bytes = await resp.read()
                    break
                if status in RETRYABLE_STATUSES:
                    retry_after = resp.headers.get("Retry-After")
                    wait = int(retry_after) if retry_after else min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious archive GET %s returned %d; retry %d/%d in %ds",
                        url,
                        status,
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.error("OSSF Malicious: archive download returned non-retryable status %d", status)
                return [], 1
            except (aiohttp.ClientError, TimeoutError) as exc:
                if attempt < max_retries - 1:
                    wait = min(2**attempt + random.uniform(0, 1), 60)
                    logger.warning(
                        "OSSF Malicious archive GET %s failed: %s; retry %d/%d in %ds",
                        url,
                        repr(exc),
                        attempt + 1,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "OSSF Malicious: archive download failed after %d retries: %s",
                        max_retries,
                        repr(exc),
                    )
                    return [], 1

        if archive_bytes is None:
            return [], 1

        # Extraction/parsing is CPU-bound and synchronous — run off the event loop
        # so it doesn't block other concurrent feed fetches.
        return await asyncio.to_thread(self._extract_and_parse, archive_bytes, ecosystems, progress_callback)

    def _extract_and_parse(
        self,
        archive_bytes: bytes,
        ecosystems: list[str] | None,
        progress_callback: Callable[[int, int], None] | None,
    ) -> tuple[list[ThreatRecord], int]:
        """Stream-extract and parse OSV JSON files from a tarball.

        Runs in a worker thread (via ``asyncio.to_thread``) since both
        gzip decompression and JSON parsing are CPU-bound.

        Args:
            archive_bytes: The raw tarball bytes.
            ecosystems: Filter to specific ecosystems, or ``None`` for all.
            progress_callback: See :meth:`fetch`.

        Returns:
            Tuple of (records, fail_count).
        """
        prefixes: set[str] | None = None
        if ecosystems:
            prefixes = {ECOSYSTEM_PATH_MAP[eco] for eco in ecosystems if eco in ECOSYSTEM_PATH_MAP}
            if not prefixes:
                # None of the requested ecosystems are covered by this feed.
                return [], 0

        records: list[ThreatRecord] = []
        fail_count = 0
        processed = 0

        # mode="r:*" auto-detects compression rather than assuming gzip —
        # defensive against any transport-level re-encoding.
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue

                # Archive entries look like "malicious-packages-<sha>/osv/malicious/npm/pkg/MAL-....json".
                # Strip the top-level directory generically rather than assuming its exact name.
                parts = member.name.split("/", 1)
                if len(parts) != 2:
                    continue
                rel_path = parts[1]

                if not rel_path.startswith(OSV_PATH_PREFIX) or rel_path.startswith(WITHDRAWN_PATH_PREFIX):
                    continue
                if not rel_path.endswith(".json"):
                    continue

                if prefixes is not None:
                    path_parts = rel_path.split("/")
                    if len(path_parts) < 3 or path_parts[2] not in prefixes:
                        continue

                extracted = tar.extractfile(member)
                if extracted is None:
                    fail_count += 1
                    continue

                try:
                    osv_data = json.load(extracted)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.warning("OSSF Malicious: JSON parse error for %s, skipping", rel_path)
                    fail_count += 1
                    continue

                records.extend(_parse_osv_record(osv_data, file_path=rel_path))
                processed += 1

                if progress_callback is not None and processed % PROGRESS_REPORT_INTERVAL == 0:
                    progress_callback(processed, processed)

        return records, fail_count

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
