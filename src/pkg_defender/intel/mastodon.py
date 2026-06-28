"""Mastodon social feed source — monitors infosec.exchange for security posts."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

import aiohttp

from pkg_defender._http import calc_retry_wait
from pkg_defender.config import get_http_timeout, get_max_retries, load_config
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.intel.extract import extract_packages
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT: int | None = None  # None = use config default


async def _mastodon_get(
    url: str,
    session: aiohttp.ClientSession,
) -> dict[str, Any] | list[Any]:
    """Execute a GET request to the Mastodon API with retry on transient errors.

    Retries on 429, 500, 502, 503, 504 with exponential backoff (1s, 2s, 4s).

    Args:
        url: Full URL to GET.
        session: aiohttp session to use.

    Returns:
        Parsed JSON response as a dict or list.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: After all retries exhausted on transient errors.
    """
    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await session.get(url)
            resp.raise_for_status()
            return cast(dict[str, Any] | list[Any], await resp.json())

        except aiohttp.ClientResponseError as exc:
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "Mastodon API GET %s returned %d; retry %d/%d in %ds",
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
                    "Mastodon API GET %s failed: %s; retry %d/%d in %ds",
                    url,
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
    raise RuntimeError(f"Failed to fetch {url} after {_max_retries} retries")


class MastodonFeed(FeedSource):
    """Mastodon social feed source — monitors for security-related posts.

    Primarily targets infosec.exchange but supports any configured instance.
    Fetches posts by hashtag from the public timeline API.

    Social feeds are informational only (board mandate: never block installs
    based on social sources alone). Severity is set to LOW for all entries.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "mastodon"

    @property
    def supports_incremental(self) -> bool:
        """Mastodon supports incremental sync via min_id cursor."""
        return True

    @property
    def is_experimental(self) -> bool:
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if Mastodon feed is enabled.

        Only checks the enabled flag (no token validation yet).

        Args:
            config: The current configuration object.

        Returns:
            True if mastodon_enabled is set.
        """
        return config.feeds.mastodon_enabled

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch security-related posts from Mastodon public timeline.

        Queries each configured hashtag on the configured instance. Uses
        ``min_id`` parameter for incremental sync (only returns posts newer
        than the last seen ID). Extracts package names from post content
        using the shared extractor.

        Args:
            since: Only fetch posts after this time. Defaults to
                ``config.feeds.mastodon_max_age_hours`` ago.
            ecosystems: Ignored — social feeds discover packages from
                unstructured text without prior ecosystem knowledge.
            session: Shared aiohttp session (created if None).
            config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult containing ThreatRecord objects and fetch metadata.
        """
        if config is None:
            config = load_config()
        instance = config.feeds.mastodon_instance
        hashtags = config.feeds.mastodon_hashtags
        max_age = config.feeds.mastodon_max_age_hours

        if since is None:
            since = datetime.now(UTC) - timedelta(hours=max_age)

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                ),
            )

        assert session is not None  # for type checker

        records: list[ThreatRecord] = []
        max_post_id: int = 0

        try:
            for hashtag in hashtags:
                url = f"https://{instance}/api/v1/timelines/tag/{hashtag}?limit=40"

                try:
                    data = await _mastodon_get(url, session)
                except Exception:
                    logger.warning(
                        "Failed to fetch Mastodon hashtag #%s — skipping",
                        hashtag,
                    )
                    continue

                if not isinstance(data, list):
                    continue

                for post in data:
                    # Age filtering
                    created_at = post.get("created_at", "")
                    if created_at:
                        try:
                            post_time = datetime.fromisoformat(
                                created_at.replace("Z", "+00:00"),
                            )
                            if post_time < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    # Track max post ID for incremental cursor
                    try:
                        post_id_int = int(post["id"])
                        max_post_id = max(max_post_id, post_id_int)
                    except (KeyError, ValueError, TypeError):
                        pass

                    # Extract package names from post content
                    content = post.get("content", "")
                    extracted = extract_packages(content)

                    post_url = post.get("url", "")
                    post_id = str(post.get("id", "unknown"))

                    for pkg in extracted:
                        # Signal-only mode: store package + signal, never full content
                        # is_unverified=True because Mastodon is a Tier 3 community source
                        record = ThreatRecord(
                            id=f"mastodon:{hashtag}:{post_id}:{pkg.package}",
                            ecosystem=pkg.ecosystem,
                            package_name=pkg.package,
                            affected_versions=[],
                            affected_ranges=[],
                            severity="LOW",
                            confidence=0.4,  # SOURCE_CONFIDENCE["mastodon"]
                            source="mastodon",
                            source_id=post_id,
                            summary=f"Mentioned in #{hashtag} post",
                            detail_url=post_url,
                            first_seen=datetime.now(UTC),
                            last_seen=datetime.now(UTC),
                            hit_count=1,
                            cvss_score=None,
                            published_at=datetime.now(UTC),
                            ingested_at=datetime.now(UTC),
                            is_malicious=False,
                            is_unverified=True,  # Tier 3 source - unverified
                        )
                        records.append(record)

            return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)

        except Exception:
            logger.warning("Failed to fetch Mastodon posts")
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
        """Point query — not supported by Mastodon (bulk-only).

        Mastodon does not provide a point query API. Callers should use
        ``fetch()`` and look up results from the local DB.

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with empty records (bulk-only feed).
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
