# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Bodhi REST client for RPM update publish-time lookup.

Preferred source for Fedora/EPEL packages. Returns ``date_pushed`` when
populated (canonical "last push event" — to testing or stable), falling
back to ``date_submitted`` (first submission to Bodhi).

Anubis solver policy (per Resolved Design Decision Q6, Constraint C1):
    This client uses plain ``aiohttp`` with the shared
    :func:`pkg_defender._http.fetch_json` retry/backoff. It MUST be
    able to function with **zero doc access** — Anubis may block
    ``webfetch`` of ``bodhi.fedoraproject.org`` (YUM-001 §7.1), so this
    client is designed for programmatic API access only.

    No HTML parsing. No :class:`html.parser.HTMLParser` calls. No
    :mod:`bs4` / :mod:`lxml` / :mod:`html.parser` imports. Bodhi's
    REST API is JSON-only — the test suite enforces this constraint
    via :func:`test_bodhi_client_works_without_doc_access` (patches
    :class:`html.parser.HTMLParser` to raise on construction).

    The Anubis PoW solver at ``/tmp/anubis_pass3.py`` is NOT invoked
    (deferred — see future-issue tracker note, label
    ``deferred/future-work`` + ``component:anubis``).

    # TODO(integration): integrate anubis-solver when publicly packaged.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import aiohttp

from pkg_defender._http import fetch_json

# Manager name for SSRF domain check -- Bodhi is part of the yum/dnf cascade.
_BODHI_MANAGER: str = "yum"

logger = logging.getLogger(__name__)

# Public base URL of the Bodhi REST API.
BODHI_BASE_URL: str = "https://bodhi.fedoraproject.org"

# 6 hours, matches ``.github/workflows/snapshot.yml`` cadence
# (``"0 */6 * * *"``). Per Resolved Design Decision Q4: same operational
# heartbeat as the threat-intel snapshot — no over-fetching, no stale
# data longer than 6 hours.
BODHI_CACHE_TTL_SECONDS: int = 21600

# Source string used by the cascade when this client produces a result.
SOURCE_BODHI: str = "bodhi"

# Page size for Bodhi paginated queries. 100 is the Bodhi default
# ``rows_per_page`` ceiling — fetching 100 versions per call covers
# any realistic package history in a single page.
_BODHI_PAGE_SIZE: int = 100

# Maximum pages to walk before giving up (defensive guard against
# misbehaving / paginating-forever servers). 50 pages × 100 = 5,000
# updates — far more than any real package will have.
_BODHI_MAX_PAGES: int = 50

# Module-level cache. Keyed by ``(package, nvr)`` to avoid cross-package
# pollution. Value is ``(datetime | None, cached_at_epoch)`` — the second
# element is the wall-clock time the entry was stored, for TTL checks.
_cache: dict[tuple[str, str], tuple[datetime | None, float]] = {}


def _reset_cache_for_tests() -> None:
    """Clear the module-level Bodhi cache. **Test-only API.**

    Production code MUST NOT call this. Tests should call it in a fixture
    to prevent cache state from leaking between cases (the cache is
    shared across all :class:`BodhiClient` instances).
    """
    _cache.clear()


def _parse_bodhi_date(date_str: str) -> datetime | None:
    """Parse a Bodhi date string and return a UTC-aware datetime.

    Bodhi's date format is ``"YYYY-MM-DD HH:MM:SS"`` — **not** ISO 8601
    (the ``T`` separator is missing). Per BC-2, we use
    :func:`datetime.strptime` and force ``tzinfo=UTC`` rather than
    :func:`datetime.fromisoformat` (which would raise on the missing
    ``T``).

    Args:
        date_str: Bodhi-formatted date string.

    Returns:
        UTC-aware :class:`datetime`, or ``None`` if the string is empty
        / malformed.
    """
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _check_cache(package: str, nvr: str) -> tuple[datetime | None, str] | None:
    """Return a cached result if present and fresh; else ``None``.

    Args:
        package: Package name.
        nvr: NVR string.

    Returns:
        The cached ``(datetime | None, "bodhi")`` tuple if the entry
        is still within :data:`BODHI_CACHE_TTL_SECONDS`, else ``None``.
    """
    entry = _cache.get((package, nvr))
    if entry is None:
        return None
    _cached_value, cached_at = entry
    if (time.time() - cached_at) > BODHI_CACHE_TTL_SECONDS:
        return None
    return (_cached_value, SOURCE_BODHI)


def _store_cache(package: str, nvr: str, result: datetime | None) -> None:
    """Store a result in the module-level cache.

    Args:
        package: Package name.
        nvr: NVR string.
        result: Parsed datetime or ``None``.
    """
    _cache[(package, nvr)] = (result, time.time())


def _match_nvr(build_nvr: str, queried_nvr: str) -> bool:
    """Check if a Bodhi build's NVR matches the queried NVR.

    Matching strategy (per BC-3):
        1. Exact match (preferred).
        2. Version-prefix fallback — if exact match fails, compare the
           version segment (everything between name and release) of
           each NVR. Handles Bodhi entries that include an extra
           ``.fc45`` suffix or similar.

    Args:
        build_nvr: NVR string from the Bodhi build entry, e.g.
            ``"curl-8.21.0~rc1-1.fc45"``.
        queried_nvr: The NVR we're looking for.

    Returns:
        ``True`` if either matching strategy succeeds.
    """
    if build_nvr == queried_nvr:
        return True

    # Fallback: version-prefix match.
    def _version_segment(nvr: str) -> str:
        parts = nvr.split("-")
        if len(parts) < 3:
            return ""
        # Version is everything between the name (parts[0]) and the
        # release (parts[-1]). Joining with "-" handles versions that
        # themselves contain "-" (rare but legal).
        return "-".join(parts[1:-1])

    return _version_segment(build_nvr) == _version_segment(queried_nvr)


def _extract_match(
    updates: list[dict[str, Any]],
    nvr: str,
) -> datetime | None:
    """Walk a list of Bodhi updates and return a matched datetime.

    Args:
        updates: ``updates`` list from the Bodhi response.
        nvr: The NVR we're looking for.

    Returns:
        UTC-aware :class:`datetime` of the first matching build's
        ``date_pushed`` (preferred) or ``date_submitted`` (fallback).
        Returns ``None`` if no match found.
    """
    for update in updates:
        builds = update.get("builds") or []
        for build in builds:
            build_nvr = build.get("nvr", "")
            if not _match_nvr(build_nvr, nvr):
                continue
            # Per BC-1: prefer ``date_pushed`` (canonical "last push
            # event"). Fall back to ``date_submitted`` if pushed is
            # null/empty (e.g. update is still in candidate state).
            date_pushed = update.get("date_pushed") or ""
            date_submitted = update.get("date_submitted") or ""
            date_str = date_pushed if date_pushed else date_submitted
            parsed = _parse_bodhi_date(date_str)
            if parsed is not None:
                return parsed
            # Both dates null/empty for this update — log and continue
            # to other builds (in case a sibling build has a date).
            logger.warning(
                "Bodhi update for nvr=%s has both date_pushed and date_submitted null",
                nvr,
            )
            return None
    return None


class BodhiClient:
    """Async Bodhi REST API client for RPM update publish-time lookup.

    See module docstring for design rationale. Always returns
    ``(datetime | None, "bodhi")`` from :meth:`get_publish_time` — never
    raises at the public API surface.
    """

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        """Initialize the client.

        Args:
            session: Optional ``aiohttp.ClientSession`` for connection
                pooling. If ``None``, a transient session is created
                per request (the caller is not responsible for closing
                it).
        """
        self._session: aiohttp.ClientSession | None = session

    async def get_publish_time(
        self,
        package: str,
        nvr: str,
    ) -> tuple[datetime | None, str]:
        """Return ``(publish_time, source)`` for *package* at *nvr*.

        Algorithm (per BC-1, BC-2, BC-3):
            1. Check the module-level cache — return immediately on hit.
            2. Paginate ``/updates/?packages=<package>&rows_per_page=100``
               until the response's ``total`` field is exhausted (or
               ``_BODHI_MAX_PAGES`` is reached).
            3. For each update, iterate ``builds``; on the first NVR
               match, prefer ``date_pushed`` (per BC-1) and parse with
               :func:`datetime.strptime` + ``tzinfo=UTC`` (per BC-2).
            4. On match, store in cache and return ``(datetime, "bodhi")``.
            5. On no match, store ``None`` in cache and return
               ``(None, "bodhi")``.

        Returns:
            ``(datetime | None, "bodhi")``. Never raises.

        Note:
            The cache stores *negative* results (``None``) too — a
            confirmed "no match" is cheaper to re-query than a fresh
            walk through 100 builds.
        """
        cached = _check_cache(package, nvr)
        if cached is not None:
            return cached

        try:
            result = await self._walk_updates(package, nvr)
        except aiohttp.ClientError as exc:
            logger.debug("Bodhi client error for %s/%s: %s", package, nvr, exc)
            return (None, SOURCE_BODHI)
        except (OSError, ValueError) as exc:
            logger.debug("Bodhi transport error for %s/%s: %s", package, nvr, exc)
            return (None, SOURCE_BODHI)
        _store_cache(package, nvr, result)
        return (result, SOURCE_BODHI)

    async def _walk_updates(
        self,
        package: str,
        nvr: str,
    ) -> datetime | None:
        """Walk Bodhi paginated updates and return the matched datetime.

        Returns ``None`` on any error (logged at debug). Pagination
        uses the ``page`` query parameter; we stop when ``page * page_size``
        reaches the response's ``total`` field.
        """
        page = 1
        seen = 0
        try:
            while page <= _BODHI_MAX_PAGES:
                url = f"{BODHI_BASE_URL}/updates/?packages={package}&rows_per_page={_BODHI_PAGE_SIZE}&page={page}"
                fetch_result = await fetch_json(
                    url,
                    session=self._session,
                    on_404="return_none",
                    manager=_BODHI_MANAGER,
                )
                if not fetch_result.success or fetch_result.data is None:
                    # 4xx returned ``None`` with success=True (return_none
                    # mode) or some other non-retryable failure. Either
                    # way, give up gracefully.
                    return None
                payload = fetch_result.data
                if not isinstance(payload, dict):
                    return None
                updates: list[dict[str, Any]] = payload.get("updates") or []
                total = int(payload.get("total") or 0)
                match = _extract_match(updates, nvr)
                if match is not None:
                    return match
                seen += len(updates)
                # Stop when we've seen everything Bodhi reported.
                if total and seen >= total:
                    return None
                if not updates:
                    # No more data — server has run out.
                    return None
                page += 1
            return None
        except aiohttp.ClientError as exc:
            logger.debug("Bodhi client error for %s/%s: %s", package, nvr, exc)
            return None
        except (OSError, ValueError) as exc:
            # OSError: socket / DNS issues
            # ValueError: malformed JSON, unexpected response shape
            logger.debug("Bodhi transport error for %s/%s: %s", package, nvr, exc)
            return None

    async def close(self) -> None:
        """Close the underlying ``aiohttp`` session if owned by this client.

        Callers that pass their own session are responsible for closing
        it themselves. This method is a no-op when no session was
        injected at construction.
        """
        if self._session is not None:
            await self._session.close()
            self._session = None
