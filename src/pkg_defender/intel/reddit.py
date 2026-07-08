"""Reddit feed source — monitors subreddits for supply chain security posts."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus

import aiohttp

from pkg_defender import __version__
from pkg_defender._http import calc_retry_wait
from pkg_defender.config import get_http_timeout, get_max_retries, load_config
from pkg_defender.display import is_verbose_mode
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.intel.extract import extract_packages
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger = logging.getLogger(__name__)

PULLPUSH_SEARCH_URL = "https://api.pullpush.io/reddit/search/submission/"
REQUEST_TIMEOUT: int | None = None  # None = use config default
USER_AGENT = f"pkg-defender/{__version__} (supply chain monitor)"


# Engagement scoring thresholds
_HIGH_UPVOTE_THRESHOLD = 200
_HIGH_COMMENT_THRESHOLD = 50
_CONFIDENCE_MULTIPLIER = 1.2

# Base confidence for Reddit (social but moderated communities)
BASE_CONFIDENCE = 0.45


async def _reddit_get(
    url: str,
    session: aiohttp.ClientSession,
) -> dict[str, Any]:
    """Execute a GET request to the PullPush API with retries.

    Uses exponential backoff (1s/2s/4s) on transient errors (429, 5xx).
    PullPush has more permissive rate limits than Reddit's public API.

    Args:
        url: Full URL to fetch.
        session: Shared aiohttp session.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: After all retries exhausted on transient errors.
    """
    headers = {"User-Agent": USER_AGENT}
    last_exc: Exception | None = None
    _max_retries = get_max_retries()

    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await session.get(url, headers=headers)
            resp.raise_for_status()
            data: dict[str, Any] = await resp.json()
            return data

        except aiohttp.ClientResponseError as exc:
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "Reddit API GET %s returned %d; retry %d/%d in %ds",
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
                verbose = is_verbose_mode()
                # Handle status attribute access properly
                error_detail: str
                if verbose:
                    error_detail = repr(exc)
                elif isinstance(exc, aiohttp.ClientResponseError):
                    error_detail = f"HTTP {exc.status}"
                else:
                    error_detail = str(exc)
                logger.warning(
                    "Reddit API GET %s failed: %s; retry %d/%d in %ds",
                    url,
                    error_detail,
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


_REDDIT_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"


async def _get_oauth_token(
    session: aiohttp.ClientSession,
    client_id: str,
    client_secret: str,
    config: PKGDConfig,
) -> str:
    """Get OAuth access token for Reddit API.

    Uses Reddit's client_credentials flow for script/installed apps.

    Args:
        session: Shared aiohttp session.
        client_id: Reddit OAuth client_id.
        client_secret: Reddit OAuth client_secret.
        config: Configuration object.

    Returns:
        Access token string.
    """
    auth = aiohttp.BasicAuth(client_id, client_secret)
    headers = {"User-Agent": USER_AGENT}
    data = {"grant_type": "client_credentials"}

    timeout_secs = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            async with asyncio.timeout(timeout_secs):
                resp = await session.post(
                    _REDDIT_TOKEN_URL,
                    json=data,
                    headers=headers,
                    auth=auth,
                )
            resp.raise_for_status()
            result: dict[str, Any] = await resp.json()
            access_token: str = result["access_token"]
            return access_token

        except aiohttp.ClientResponseError as exc:
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "Reddit OAuth POST returned %d; retry %d/%d in %ds",
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

        except (TimeoutError, aiohttp.ClientError) as exc:
            last_exc = exc
            if attempt < _max_retries - 1:
                wait = 2**attempt + random.uniform(0, 1)
                logger.warning(
                    "Reddit OAuth POST failed: %s; retry %d/%d in %ds",
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
    raise RuntimeError("Failed to get Reddit OAuth token after retries")


async def _reddit_get_oauth(
    url: str,
    session: aiohttp.ClientSession,
    client_id: str,
    client_secret: str,
    config: PKGDConfig,
) -> dict[str, Any]:
    """Execute authenticated GET request to Reddit API.

    Args:
        url: Full URL to fetch.
        session: Shared aiohttp session.
        client_id: Reddit OAuth client_id.
        client_secret: Reddit OAuth client_secret.
        config: Configuration object.

    Returns:
        Parsed JSON response as a dict.
    """
    # Get token using client_credentials flow
    token = await _get_oauth_token(session, client_id, client_secret, config)

    headers = {
        "User-Agent": USER_AGENT,
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    timeout_secs = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            async with asyncio.timeout(timeout_secs):
                resp = await session.get(url, headers=headers)
            resp.raise_for_status()
            data: dict[str, Any] = await resp.json()
            return data

        except aiohttp.ClientResponseError as exc:
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "Reddit OAuth GET %s returned %d; retry %d/%d in %ds",
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

        except (TimeoutError, aiohttp.ClientError) as exc:
            last_exc = exc
            if attempt < _max_retries - 1:
                wait = 2**attempt + random.uniform(0, 1)
                logger.warning(
                    "Reddit OAuth GET %s failed: %s; retry %d/%d in %ds",
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


def _compute_engagement_confidence(post: dict[str, Any]) -> float:
    """Compute confidence score boosted by post engagement metrics.

    Posts with high upvote ratios or many comments get a confidence
    multiplier, reflecting that community engagement increases signal
    quality for moderated subreddits.

    Args:
        post: A Reddit post data dict (``data`` field from API).

    Returns:
        Confidence value between ``BASE_CONFIDENCE`` and
        ``BASE_CONFIDENCE * _CONFIDENCE_MULTIPLIER``.
    """
    upvotes = post.get("ups", 0) or 0
    num_comments = post.get("num_comments", 0) or 0

    if upvotes >= _HIGH_UPVOTE_THRESHOLD or num_comments >= _HIGH_COMMENT_THRESHOLD:
        return BASE_CONFIDENCE * _CONFIDENCE_MULTIPLIER

    return BASE_CONFIDENCE


def _post_to_threat_records(
    post: dict[str, Any],
    subreddit: str,
    max_age_hours: int,
) -> list[ThreatRecord]:
    """Convert a Reddit post into ThreatRecord(s) via package extraction.

    Extracts package names from the post title and selftext. Each unique
    extracted package becomes a ThreatRecord. Posts older than
    ``max_age_hours`` are skipped.

    Signal-only mode: stores package name + count as summary, never stores
    full post content (Tier 3 source per solutions doc Section 3).

    Args:
        post: A Reddit post ``data`` dict.
        subreddit: Source subreddit name (for logging).
        max_age_hours: Maximum post age in hours.

    Returns:
        List of ThreatRecord objects (empty if no packages extracted or
        post is too old).
    """
    created_utc = post.get("created_utc", 0)
    post_time = datetime.fromtimestamp(created_utc, tz=UTC)
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=max_age_hours)

    if post_time < cutoff:
        return []

    title = post.get("title", "")
    selftext = post.get("selftext", "")
    combined_text = f"{title} {selftext}"

    extracted = extract_packages(combined_text)
    if not extracted:
        return []

    confidence = _compute_engagement_confidence(post)
    post_id = post.get("id", "")
    permalink = post.get("permalink", "")
    detail_url = f"https://www.reddit.com{permalink}" if permalink else None
    upvote_count = post.get("ups", 0)
    comment_count = post.get("num_comments", 0)

    # Signal-only mode: don't store full content, just package + signal
    # is_unverified=True because Reddit is a Tier 3 community source
    records: list[ThreatRecord] = []
    for pkg in extracted:
        record = ThreatRecord(
            id=f"reddit:{post_id}:{pkg.package}",
            ecosystem=pkg.ecosystem,
            package_name=pkg.package,
            affected_versions=[],
            affected_ranges=[],
            severity="LOW",
            confidence=confidence,
            source="reddit",
            source_id=post_id,
            summary=f"Mentioned in r/{subreddit}: {upvote_count} upvotes, {comment_count} comments",
            detail_url=detail_url,
            first_seen=post_time,
            last_seen=post_time,
            hit_count=1,
            cvss_score=None,
            published_at=post_time,
            ingested_at=now,
            is_malicious=False,
            is_unverified=True,  # Tier 3 source - unverified
        )
        records.append(record)

    return records


class RedditFeed(FeedSource):
    """Reddit feed source — monitors subreddits for supply chain signals.

    Uses the PullPush API (successor to Pushshift) to search configured
    subreddits for security-related keywords. Extracts package names from
    post titles and bodies via ``extract_packages()``.

    Supports incremental sync via ``created_utc`` cursor filtering.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "reddit"

    @property
    def supports_incremental(self) -> bool:
        """Reddit supports incremental sync via created_utc cursor."""
        return True

    @property
    def is_experimental(self) -> bool:
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if Reddit feed is configured.

        Reddit requires BOTH:
        1. reddit_enabled=True (explicit opt-in, BYOK)
        2. OAuth credentials (client_id AND client_secret)

        Args:
            config: The current configuration object.

        Returns:
            True only if reddit_enabled AND credentials are configured.
        """
        if not config.feeds.reddit_enabled:
            return False
        client_id = config.feeds.reddit_client_id
        client_secret = config.feeds.reddit_client_secret
        return bool(client_id and client_secret)

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch threat records from Reddit.

        Iterates over configured subreddits × keywords, calling the Reddit
        search API for each combination. Posts are filtered by age and
        engagement-scored confidence.

        Args:
            since: Only fetch posts created after this time. Used as
                the ``created_utc`` cursor for incremental sync.
                Defaults to ``reddit_max_age_hours`` ago.
            ecosystems: Filter extracted packages to these ecosystems.
                If None, all ecosystems are included.
            session: Shared aiohttp session (created if None).
                config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult containing ThreatRecord objects and fetch metadata.
        """
        if config is None:
            config = load_config()
        subreddits = config.feeds.reddit_subreddits
        keywords = config.feeds.reddit_keywords
        max_age_hours = config.feeds.reddit_max_age_hours

        # Check if credentials are configured (BYOK - use official Reddit API)
        use_oauth = self.is_configured(config)
        client_id = config.feeds.reddit_client_id
        client_secret = config.feeds.reddit_client_secret

        if use_oauth:
            logger.info("Reddit credentials configured — using official Reddit API with OAuth")
        else:
            logger.info("No Reddit credentials — using PullPush fallback API")

        if since is None:
            since = datetime.now(UTC) - timedelta(hours=max_age_hours)

        # Convert since to Unix timestamp for created_utc filtering
        since_ts = since.timestamp()

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                ),
            )

        assert session is not None  # for type checker

        records: list[ThreatRecord] = []
        seen_post_ids: set[str] = set()
        semaphore = asyncio.Semaphore(10)  # Limit concurrent API calls

        async def fetch_subreddit_keyword(subreddit: str, keyword: str) -> list[ThreatRecord]:
            """Fetch posts for a single subreddit/keyword combination."""
            # Build URL based on auth mode
            if use_oauth:
                # Official Reddit API uses different endpoint structure
                url = (
                    "https://oauth.reddit.com/search/"
                    f"?q={quote_plus(keyword)}"
                    f"&subreddit={quote_plus(subreddit)}"
                    f"&sort=new"
                    f"&limit=100"
                )
            else:
                # PullPush fallback
                url = (
                    f"{PULLPUSH_SEARCH_URL}"
                    f"?q={quote_plus(keyword)}"
                    f"&subreddit={quote_plus(subreddit)}"
                    f"&sort=desc"
                    f"&sort_type=created_utc"
                    f"&size=100"
                )

            async with semaphore:
                try:
                    if use_oauth:
                        data = await _reddit_get_oauth(url, session, client_id, client_secret, config)
                        # Reddit API returns: data.data.children[].data
                        posts = data.get("data", {}).get("children", [])
                        posts = [child.get("data", {}) for child in posts]
                    else:
                        data = await _reddit_get(url, session)
                        # PullPush returns: data.data[]
                        posts = data.get("data", [])
                except Exception as exc:
                    verbose = is_verbose_mode()
                    error_detail = repr(exc) if verbose else str(exc)
                    logger.warning(
                        "Failed to fetch r/%s search for %r; skipping: %s",
                        subreddit,
                        keyword,
                        error_detail,
                    )
                    return []

            local_records: list[ThreatRecord] = []

            for post in posts:
                post_id = post.get("id", "")

                # Deduplicate across keyword searches
                if post_id in seen_post_ids:
                    continue
                seen_post_ids.add(post_id)

                # Skip posts older than cursor
                # PullPush API returns created_utc as a string (e.g., "1746783820.0")
                created_utc = float(post.get("created_utc", 0))
                if created_utc < since_ts:
                    continue

                post_records = _post_to_threat_records(
                    post,
                    subreddit,
                    max_age_hours,
                )

                # Apply ecosystem filter
                if ecosystems is not None:
                    post_records = [r for r in post_records if r.ecosystem in ecosystems]

                local_records.extend(post_records)

            return local_records

        try:
            # Build all tasks for concurrent execution
            tasks: list[asyncio.Task[list[ThreatRecord]]] = []
            for subreddit in subreddits:
                for keyword in keywords:
                    task = asyncio.create_task(fetch_subreddit_keyword(subreddit, keyword))
                    tasks.append(task)

            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks)

            # Flatten results
            for result in results:
                records.extend(result)

            # Small delay to be nice to the API
            await asyncio.sleep(0.1)

            return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)

        except Exception as exc:
            verbose = is_verbose_mode()
            error_detail = repr(exc) if verbose else str(exc)
            logger.error("Failed to fetch Reddit feed: %s", error_detail)
            logger.debug("Failed to fetch Reddit feed — full traceback:", exc_info=True)
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
        """Point query — not supported by Reddit (bulk-only).

        Reddit is a social feed with no per-package API. Callers should
        use ``fetch()`` and look up results from the local DB.

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
