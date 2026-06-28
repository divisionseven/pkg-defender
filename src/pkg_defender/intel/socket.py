"""Socket.dev feed source — real-time supply chain risk scoring."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp

from pkg_defender._http import calc_retry_wait
from pkg_defender.config import get_http_timeout, get_max_retries, load_config
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

SOCKET_API_BASE = "https://api.socket.dev/v0"
REQUEST_TIMEOUT: int | None = None  # None = use config default

logger = logging.getLogger(__name__)


def _get_api_key() -> str | None:
    """Read the Socket.dev API key from config file.

    Returns:
        The API key string with whitespace stripped, or ``None`` if not
        configured or contains only whitespace.
    """
    try:
        config = load_config()
        if config.feeds.socket_api_key:
            key = config.feeds.socket_api_key.strip()
            if key:
                return key
    except Exception:
        logger.debug("socket: config load for API key failed")
        pass

    return None


def _score_to_severity(supply_chain_risk: float, malware: float) -> str:
    """Map combined Socket.dev risk scores to a severity string.

    Args:
        supply_chain_risk: Supply chain risk score (0.0–1.0).
        malware: Malware score (0.0–1.0).

    Returns:
        One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, or ``UNKNOWN``.
    """
    if malware >= 0.8:
        return "CRITICAL"
    if malware >= 0.5 or supply_chain_risk >= 0.9:
        return "HIGH"
    if supply_chain_risk >= 0.7:
        return "MEDIUM"
    return "UNKNOWN"


async def _socket_fetch(
    endpoint: str,
    api_key: str | None = None,
    session: aiohttp.ClientSession | None = None,
) -> dict[str, Any]:
    """Internal HTTP GET helper with 5-second timeout and exponential-backoff retry.

    Args:
        endpoint: Absolute path appended to ``SOCKET_API_BASE``.
        api_key: Optional Socket.dev API key for higher rate limits.
        session: Optional existing aiohttp session; one is created if ``None``.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: After all retries exhausted on transient errors.
    """
    url = f"{SOCKET_API_BASE}{endpoint}"
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout())
    own_session = session is None

    if own_session:
        session = aiohttp.ClientSession(timeout=timeout)

    assert session is not None

    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"api {api_key}"

    try:
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
                            "Socket API GET %s returned %d; retry %d/%d in %ds",
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
                        "Socket API GET %s failed: %s; retry %d/%d in %ds",
                        url,
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
        raise RuntimeError(f"Failed to fetch {url} after {_max_retries} retries")
    finally:
        if own_session:
            await session.close()


class SocketFeed(FeedSource):
    """Socket.dev intelligence feed — per-package supply chain risk scoring.

    Socket.dev provides real-time scores for supply chain risk and malware,
    but only supports point queries. Bulk data feeds are not available on
    any tier — they require an Enterprise subscription. The free/public
    tier is limited to npm packages only.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "socket"

    @property
    def supports_incremental(self) -> bool:
        """Whether this feed supports incremental sync.

        Socket.dev is point-query only — no bulk fetch endpoint exists
        on any tier (Enterprise-only feature).
        """
        return False

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if Socket.dev feed is properly configured.

        Args:
            config: The PKGDConfig instance.

        Returns:
            True if both socket_enabled is True and socket_api_key is set.
        """
        return config.feeds.socket_enabled and bool(config.feeds.socket_api_key.strip())

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Bulk fetch is not supported by Socket.dev.

        Returns a ``FeedFetchResult`` with an empty records list.  Callers
        should use ``check_package`` for point queries.
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Check a single npm package@version against Socket.dev scores.

        Args:
            package: Package name.
            version: Package version.
            ecosystem: Ecosystem identifier (only ``"npm"`` is supported).
            session: Optional existing aiohttp session.
             config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            A ``FeedFetchResult`` containing a ``ThreatRecord`` if risk scores
            exceed thresholds, or an empty records list otherwise.
        """
        if ecosystem != "npm":
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        if config is None:
            config = load_config()
        api_key = config.feeds.socket_api_key
        endpoint = f"/npm/{package}/{version}/score"
        own_session = session is None

        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout(config)
                )
            )

        try:
            data = await _socket_fetch(endpoint, api_key=api_key, session=session)
        finally:
            if own_session and session is not None:
                await session.close()

        # --- Parse scores ---
        supply_chain_risk = 0.0
        malware = 0.0
        score_obj = data.get("score", {})
        if isinstance(score_obj, dict):
            supply_chain_risk = float(score_obj.get("supplyChainRisk", 0.0))
            malware = float(score_obj.get("malware", 0.0))

        # Check thresholds
        if supply_chain_risk < 0.7 and malware < 0.5:
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        severity = _score_to_severity(supply_chain_risk, malware)
        now = datetime.now(UTC)

        # Build summary from issues array if present
        issues: list[dict[str, Any]] = data.get("issues", [])
        issue_titles: list[str] = []
        for issue in issues:
            title = issue.get("title", "")
            if title:
                issue_titles.append(title)
        summary = f"Socket.dev: supplyChainRisk={supply_chain_risk:.2f}, malware={malware:.2f}"
        if issue_titles:
            summary += f" — {'; '.join(issue_titles[:5])}"

        record = ThreatRecord(
            id=f"socket:{package}:{version}",
            ecosystem=ecosystem,
            package_name=package,
            affected_versions=[version],
            affected_ranges=[],
            severity=severity,
            confidence=0.95,
            source="socket",
            source_id=f"{package}@{version}",
            summary=summary,
            detail_url=f"https://socket.dev/{ecosystem}/package/{package}",
            first_seen=now,
            last_seen=now,
            hit_count=1,
            cvss_score=None,
            published_at=now,
            ingested_at=now,
            is_malicious=False,
            is_unverified=False,
        )
        return FeedFetchResult(records=[record], feed_metadata={}, status=FetchStatus.SUCCESS)
