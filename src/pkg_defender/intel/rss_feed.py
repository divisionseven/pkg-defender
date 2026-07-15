# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""RSS feed source — monitors security blogs for supply chain threats."""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import aiohttp
import feedparser

from pkg_defender._http import calc_retry_wait
from pkg_defender.config import get_http_timeout, get_max_retries, load_config
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.intel.extract import extract_packages
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

REQUEST_TIMEOUT: int | None = None  # None = use config default


# Feeds that block aiohttp TLS fingerprint - use urllib directly
URLLIB_ONLY_URLS = [
    "openssf.org",
    # Add others as needed
]

logger = logging.getLogger(__name__)


def _convert_published(entry: Any) -> datetime | None:
    """Convert a feedparser entry published field to a timezone-aware datetime.

    Args:
        entry: A feedparser entry object.

    Returns:
        A timezone-aware datetime, or None if the date cannot be parsed
        or is absent.
    """
    published = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if published is None:
        return None
    try:
        if isinstance(published, time.struct_time):
            return datetime(*published[:6], tzinfo=UTC)
        if isinstance(published, datetime):
            return published if published.tzinfo else published.replace(tzinfo=UTC)
        return None
    except (TypeError, ValueError, OverflowError):
        return None


def _urllib_fetch(url: str) -> dict[str, Any]:
    """Fetch a URL with urllib and parse as RSS (synchronous, for use in threads).

    Uses the system default SSL context which passes CDN TLS fingerprint
    checks that block aiohttp's TLS Client Hello.

    Args:
        url: The RSS feed URL to fetch.

    Returns:
        A feedparser dict.

    Raises:
        ValueError: If the URL scheme is not ``http`` or ``https``.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"Unsupported URL scheme in {url!r} (only http/https allowed)")

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "pkg-defender/1.0"})  # noqa: S310  # validated above
    with urllib.request.urlopen(  # noqa: S310  # validated above
        req,
        timeout=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(),
        context=ctx,
    ) as resp:
        body = resp.read()
    result: dict[str, Any] = feedparser.parse(body)
    return result


async def _fetch_rss_urllib(url: str) -> dict[str, Any]:
    """Fetch an RSS feed via urllib in a thread (async-compatible fallback).

    Args:
        url: The RSS feed URL to fetch.

    Returns:
        A feedparser dict.

    Raises:
        Exception: On fetch failure (propagated from the thread).
    """
    return await asyncio.to_thread(_urllib_fetch, url)


async def _fetch_rss(
    url: str,
    session: aiohttp.ClientSession,
) -> dict[str, Any]:
    """Fetch and parse an RSS feed URL with retry logic.

    Args:
        url: The RSS feed URL to fetch.
        session: An aiohttp session to use for the request.

    Returns:
        A feedparser dict (result of ``feedparser.parse()`` on the response body).

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: After all retries are exhausted on transient errors.
    """
    # Skip aiohttp for feeds that block its TLS fingerprint
    if any(domain in url for domain in URLLIB_ONLY_URLS):
        return await _fetch_rss_urllib(url)

    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await session.get(url)
            resp.raise_for_status()
            body = await resp.read()
            result: dict[str, Any] = await asyncio.to_thread(feedparser.parse, body)
            return result
        except aiohttp.ClientResponseError as exc:
            if exc.status == 403:
                # TLS fingerprint blocked by CDN (e.g. OpenSSF Varnish JA3/JA4
                # check). Fall back to urllib which uses system OpenSSL.
                logger.warning(
                    "RSS GET %s returned 403 (TLS fingerprint); falling back to urllib",
                    url,
                )
                return await _fetch_rss_urllib(url)
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "RSS GET %s returned %s; retry %s/%s in %.2fs",
                        url,
                        exc.status,
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                else:
                    raise
            raise
        except (aiohttp.ClientError, TimeoutError) as exc:
            last_exc = exc
            if attempt < _max_retries - 1:
                wait = 2**attempt + random.uniform(0, 1)
                logger.warning(
                    "RSS GET %s failed: %s; retry %s/%s in %.2fs",
                    url,
                    exc,
                    attempt + 1,
                    _max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError(f"Failed to fetch {url} after {_max_retries} retries")


class RSSFeed(FeedSource):
    """RSS feed source — monitors security blogs and news feeds.

    Parses configured RSS feeds for supply-chain-related articles.
    Entries are filtered by age and keyword relevance before being
    converted to ThreatRecords.  This feed is informational only
    (severity ``LOW``) and never triggers install blocking.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "rss"

    @property
    def supports_incremental(self) -> bool:
        """RSS has no cursor; filtering is by time window only."""
        return False

    @property
    def is_experimental(self) -> bool:
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if RSS feed has configured URLs.

        Args:
            config: The current configuration object.

        Returns:
            True if rss_urls is non-empty.
        """
        return bool(config.feeds.rss_urls)

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch threat records from configured RSS feeds.

        For each configured URL the feed is fetched, parsed, and entries
        are filtered by:
        1. Publication date within ``rss_max_age_hours``
        2. Title or summary containing at least one configured keyword

        Matching entries have package names extracted via
        :func:`~pkg_defender.intel.extract.extract_packages`.

        Args:
            since: Optional additional time filter — entries older than this
                are skipped even if within ``max_age_hours``.
            ecosystems: Unused (RSS entries rarely declare an ecosystem).
            session: Shared aiohttp session (created if ``None``).
                config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult containing ThreatRecord objects and fetch metadata.
        """
        if config is None:
            config = load_config()
        urls = config.feeds.rss_urls
        keywords = [kw.lower() for kw in config.feeds.rss_keywords]
        max_age_hours = config.feeds.rss_max_age_hours
        cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)

        # Effective start: the later of ``since`` and the age-based cutoff
        effective_start = cutoff
        if since is not None and since > effective_start:
            effective_start = since

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                ),
            )

        assert session is not None  # for type checker

        try:
            records: list[ThreatRecord] = []
            now = datetime.now(UTC)
            result_metadata: dict[str, Any] = {}

            for url in urls:
                try:
                    feed = await _fetch_rss(url, session)
                except Exception:
                    logger.warning("Failed to fetch RSS feed: %s", url)
                    continue

                feed_record_count = 0

                for entry in feed.get("entries", []):
                    title = getattr(entry, "title", "") or ""
                    summary = getattr(entry, "summary", "") or getattr(entry, "description", "") or ""
                    link = getattr(entry, "link", "") or ""
                    entry_id = getattr(entry, "id", "") or link

                    # --- Time filter ---
                    published = _convert_published(entry)
                    if published is None:
                        continue  # skip entries with no parseable date
                    if published < effective_start:
                        continue

                    # --- Keyword filter ---
                    text_lower = (title + " " + summary).lower()
                    if not any(kw in text_lower for kw in keywords):
                        continue

                    feed_record_count += 1

                    # --- Package extraction ---
                    extracted = extract_packages(title + " " + summary)

                    if extracted:
                        for pkg in extracted:
                            records.append(
                                ThreatRecord(
                                    id=f"rss:{entry_id}:{pkg.package}",
                                    ecosystem=pkg.ecosystem,
                                    package_name=pkg.package,
                                    affected_versions=[],
                                    affected_ranges=[],
                                    severity="LOW",
                                    confidence=0.5,
                                    source="rss",
                                    source_id=entry_id,
                                    summary=title,
                                    detail_url=link,
                                    first_seen=published,
                                    last_seen=now,
                                    hit_count=1,
                                    cvss_score=None,
                                    published_at=published,
                                    ingested_at=now,
                                    is_malicious=False,
                                    is_unverified=True,  # Tier 3 - RSS is unverified
                                )
                            )
                    else:
                        # Fallback: use source URL domain as identifier
                        # when no packages were extracted from the feed entry
                        domain = urlparse(url).netloc or "unknown"
                        records.append(
                            ThreatRecord(
                                id=f"rss:{entry_id}:{domain}",
                                ecosystem="unknown",
                                package_name=domain,
                                affected_versions=[],
                                affected_ranges=[],
                                severity="LOW",
                                confidence=0.5,
                                source="rss",
                                source_id=entry_id,
                                summary=title,
                                detail_url=link,
                                first_seen=published,
                                last_seen=now,
                                hit_count=1,
                                cvss_score=None,
                                published_at=published,
                                ingested_at=now,
                                is_malicious=False,
                                is_unverified=True,  # Tier 3 - RSS is unverified
                            )
                        )

                # Log if feed returned 0 entries after filtering
                if feed_record_count == 0:
                    warning_msg = (
                        f"RSS feed {url} returned 0 entries after filtering. "
                        "Tip: Adjust RSS filters with: "
                        'pkgd config set feeds.rss_keywords "your, keywords"'
                    )
                    logger.warning(warning_msg)
                    # Store warning so sync summary can display it after progress bar exits
                    result_metadata["warning"] = warning_msg

            return FeedFetchResult(records=records, feed_metadata=result_metadata, status=FetchStatus.SUCCESS)

        except Exception:
            logger.warning("Failed to fetch RSS feeds")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
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
        """Point query — not supported by RSS (bulk-only).

        RSS feeds do not provide a per-package lookup API.  Callers should
        use ``fetch()`` and look up results from the local database.

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with FAILED status and empty records — use fetch() instead.
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
