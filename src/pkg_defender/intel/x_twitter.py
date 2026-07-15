# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""X/Twitter intelligence feed — BYOK social signal monitor."""

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

X_SEARCH_URL = "https://api.twitter.com/2/tweets/search/recent"
REQUEST_TIMEOUT: int | None = None  # None = use config default


# Source confidence for X/Twitter (from scorer.py SOURCE_CONFIDENCE)
BASE_CONFIDENCE = 0.5
TRUSTED_ACCOUNT_MULTIPLIER = 1.5


def _build_search_query(keywords: list[str]) -> str:
    """Build a compound Twitter search query from keywords.

    Combines keywords with OR, appends retweet exclusion and English
    language filter.

    Args:
        keywords: List of keyword strings to search for.

    Returns:
        Formatted Twitter API search query string.
    """
    keyword_part = " OR ".join(f'"{kw}"' for kw in keywords)
    return f"({keyword_part}) -is:retweet lang:en"


def _parse_tweet(
    tweet: dict[str, Any],
    includes_users: dict[str, dict[str, Any]],
    trusted_accounts: list[str],
    keywords: list[str],
    max_age_hours: int,
) -> ThreatRecord | None:
    """Parse a single tweet into a ThreatRecord.

    Extracts package names from tweet text, determines severity and
    confidence based on whether the author is a trusted account.

    Args:
        tweet: A single tweet object from the Twitter API v2 response.
        includes_users: Lookup dict of user objects keyed by user ID.
        trusted_accounts: List of trusted author IDs for confidence boosting.
        keywords: Keywords used for the search (for summary context).
        max_age_hours: Maximum age in hours for tweets to include.

    Returns:
        A ThreatRecord if packages were extracted, or None if the tweet
        is too old or contains no extractable package names.
    """
    text = tweet.get("text", "")
    tweet_id = tweet.get("id", "unknown")
    author_id = tweet.get("author_id", "")
    created_at_str = tweet.get("created_at", "")

    # Parse timestamp and apply max age filter
    now = datetime.now(UTC)
    created_at = now
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            created_at = now

    cutoff = now - timedelta(hours=max_age_hours)
    if created_at < cutoff:
        return None

    # Extract package names from tweet text
    extracted = extract_packages(text)
    if not extracted:
        return None

    # Determine confidence — boost for trusted accounts
    is_trusted = author_id in trusted_accounts
    confidence = BASE_CONFIDENCE * TRUSTED_ACCOUNT_MULTIPLIER if is_trusted else BASE_CONFIDENCE
    severity = "LOW"

    # Build author info for summary
    author_username = "unknown"
    if author_id in includes_users:
        author_username = includes_users[author_id].get("username", "unknown")

    # Use first extracted package for the primary record
    primary = extracted[0]
    ecosystem = primary.ecosystem if primary.ecosystem != "unknown" else "unknown"

    summary = f"X/Twitter mention by @{author_username}: {text[:200]}"
    detail_url = f"https://twitter.com/i/web/status/{tweet_id}"

    return ThreatRecord(
        id=f"x_twitter:{tweet_id}",
        ecosystem=ecosystem,
        package_name=primary.package,
        affected_versions=[],
        affected_ranges=[],
        severity=severity,
        confidence=confidence,
        source="x_twitter",
        source_id=tweet_id,
        summary=summary,
        detail_url=detail_url,
        first_seen=created_at,
        last_seen=created_at,
        hit_count=1,
        cvss_score=None,
        published_at=created_at,
        ingested_at=datetime.now(UTC),
        is_malicious=False,
        is_unverified=True,  # Tier 3 - social source
    )


async def _api_get(
    url: str,
    params: dict[str, Any],
    bearer_token: str,
    session: aiohttp.ClientSession,
) -> dict[str, Any]:
    """Execute an authenticated GET request to the X/Twitter API.

    Retries on transient errors (429, 500, 502, 503, 504) with exponential
    backoff. Fails immediately on 401/403 (auth errors — not retryable).

    Args:
        url: API endpoint URL.
        params: Query parameters.
        bearer_token: Bearer token for authentication.
        session: aiohttp session to use.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors (401, 403).
        aiohttp.ClientError: After all retries exhausted on transient errors.
    """
    headers = {"Authorization": f"Bearer {bearer_token}"}

    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    for attempt in range(_max_retries):
        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await session.get(url, params=params, headers=headers)

            # Auth errors — not retryable
            if resp.status in (401, 403):
                resp.raise_for_status()  # raises ClientResponseError

            resp.raise_for_status()
            return cast(dict[str, Any], await resp.json())

        except aiohttp.ClientResponseError as exc:
            if exc.status in (429, 500, 502, 503, 504):
                last_exc = exc
                if attempt < _max_retries - 1:
                    if resp is not None:
                        wait = calc_retry_wait(attempt, exc.status, resp)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "X/Twitter API returned %d; retry %d/%d in %ds",
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
                    "X/Twitter API request failed: %s; retry %d/%d in %ds",
                    repr(exc),
                    attempt + 1,
                    _max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                continue
            else:
                raise

    if last_exc:
        raise last_exc
    raise RuntimeError("Failed to query X/Twitter API after retries")


class XTwitterFeed(FeedSource):
    """X/Twitter intelligence feed — BYOK social signal monitor.

    Monitors X/Twitter for security-related posts mentioning supply chain
    attacks. Requires a bearer token from the X/Twitter API (BYOK).
    Disabled by default — gracefully returns empty results if no token
    is configured.

    This feed is bulk-only (no point query). It fetches recent tweets
    matching configured keywords and extracts package names from tweet text.

    Auth: Bearer token from ``PKGD_FEEDS_X_TWITTER_TOKEN`` env var or config.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "x_twitter"

    @property
    def supports_incremental(self) -> bool:
        """X/Twitter does not support incremental sync (no cursor)."""
        return False

    @property
    def is_experimental(self) -> bool:
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if X/Twitter feed has a bearer token configured.

        Args:
            config: The current configuration object.

        Returns:
            True if x_twitter_bearer_token is set.
        """
        return bool(config.feeds.x_twitter_bearer_token.strip())

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch recent tweets matching configured keywords.

        If no bearer token is configured, logs an info message and returns
        a failed FeedFetchResult (graceful disable — NOT an error).

        On 401/403 responses, logs a message about requiring a paid API key
        and returns a failed FeedFetchResult.

        Args:
            since: Unused — X/Twitter feed uses max_age_hours from config.
            ecosystems: Optional filter — only include records matching these
                ecosystems.
            session: Shared aiohttp session (created if None).
             config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult with records and status.
        """
        if config is None:
            config = load_config()

        bearer_token = config.feeds.x_twitter_bearer_token
        if not bearer_token:
            logger.info("X/Twitter feed disabled: no bearer token configured")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        keywords = config.feeds.x_twitter_keywords
        trusted_accounts = config.feeds.x_twitter_trusted_accounts
        max_age_hours = config.feeds.x_twitter_max_age_hours

        if not keywords:
            logger.info("X/Twitter feed disabled: no keywords configured")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        query = _build_search_query(keywords)

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                ),
            )

        assert session is not None  # for type checker

        try:
            params: dict[str, Any] = {
                "query": query,
                "max_results": 100,
                "tweet.fields": "author_id,created_at,text",
                "expansions": "author_id",
                "user.fields": "username",
            }

            data = await _api_get(X_SEARCH_URL, params, bearer_token, session)

            # Build user lookup from includes
            includes_users: dict[str, dict[str, Any]] = {}
            for user in data.get("includes", {}).get("users", []):
                user_id = user.get("id", "")
                if user_id:
                    includes_users[user_id] = user

            records: list[ThreatRecord] = []
            for tweet in data.get("data", []):
                record = _parse_tweet(
                    tweet,
                    includes_users,
                    trusted_accounts,
                    keywords,
                    max_age_hours,
                )
                if record is None:
                    continue

                # Apply ecosystem filter
                if ecosystems is not None and record.ecosystem not in ecosystems:
                    continue

                records.append(record)

            return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)

        except aiohttp.ClientResponseError as exc:
            if exc.status in (401, 403):
                logger.info(
                    "X/Twitter feed requires a paid API key (HTTP %d)",
                    exc.status,
                )
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
            logger.warning("X/Twitter API error")
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
        except Exception:
            logger.warning("Failed to fetch X/Twitter feed")
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
        """Point query — not supported by X/Twitter (bulk-only).

        X/Twitter does not provide a point query API. Callers should use
        ``fetch()`` and look up results from the local DB.

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            Always a failed FeedFetchResult with empty records.
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
