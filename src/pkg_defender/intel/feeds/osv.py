"""OSV.dev feed source — fetches vulnerability data from the OSV API and data dumps."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import tempfile
import zipfile
from asyncio import sleep as _asyncio_sleep
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp

if TYPE_CHECKING:
    from pkg_defender.config.settings import DatabaseConfig

from pkg_defender._http import calc_retry_wait
from pkg_defender.config import PKGDConfig, get_db_path, get_http_timeout, get_max_retries
from pkg_defender.db.schema import get_connection, get_metadata, set_metadata
from pkg_defender.intel.base import EcosystemResult, FeedFetchResult, FetchStatus
from pkg_defender.intel.feeds._osv_parser import (
    _extract_severity_and_cvss,
    _parse_osv_vuln,
    cvss_to_severity,
)
from pkg_defender.models import ThreatRecord

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"
OSV_DUMP_BASE = "https://storage.googleapis.com/osv-vulnerabilities"
REQUEST_TIMEOUT: int | None = None  # None = use config default


# Internal ecosystem → OSV dump ecosystem name
DUMP_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "apt": "Debian",
    "yum": "Linux",
    "dnf": "Linux",
}

# Internal ecosystem → OSV API ecosystem name
ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "apt": "Debian",
    "yum": "Linux",
    "dnf": "Linux",
}


def _map_ecosystem(ecosystem: str) -> str:
    """Map internal ecosystem name to OSV ecosystem string.

    Args:
        ecosystem: Internal ecosystem identifier (e.g. ``"npm"``, ``"pypi"``).

    Returns:
        The OSV-compatible ecosystem string.

    Raises:
        ValueError: If the ecosystem is not in the mapping.
    """
    mapped = ECOSYSTEM_MAP.get(ecosystem)
    if mapped is None:
        raise ValueError(f"Unknown ecosystem {ecosystem!r}; supported: {list(ECOSYSTEM_MAP.keys())}")
    return mapped


def _map_severity(vuln: dict[str, Any]) -> str:
    """Extract severity from an OSV vulnerability dict.

    Args:
        vuln: Raw OSV vulnerability object.

    Returns:
        Severity string: ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, or ``UNKNOWN``.
    """
    cvss_score = _extract_severity_and_cvss(vuln)
    return cvss_to_severity(cvss_score)


def _cvss_to_severity(score: float) -> str:
    """Map a CVSS base score to a severity string.

    Args:
        score: CVSS base score (0.0-10.0).

    Returns:
        Severity string.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


async def _osv_fetch(
    url: str,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
    session: aiohttp.ClientSession | None = None,
) -> dict[str, Any]:
    """Internal HTTP helper with 5-second timeout and exponential-backoff retry.

    Args:
        url: Fully-qualified URL to request.
        method: HTTP method (``"GET"`` or ``"POST"``).
        json_body: Optional JSON body for POST requests.
        params: Optional query parameters for GET requests.
        session: Optional existing aiohttp session; one is created if None.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors.
        aiohttp.ClientError: After all retries exhausted on transient errors.
    """
    _timeout = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout()
    timeout = aiohttp.ClientTimeout(total=_timeout)
    own_session = session is None

    if own_session:
        session = aiohttp.ClientSession(timeout=timeout)

    assert session is not None  # for type checker

    last_exc: Exception | None = None
    _max_retries = get_max_retries()
    try:
        for attempt in range(_max_retries):
            resp: aiohttp.ClientResponse | None = None
            try:
                if method.upper() == "POST":
                    resp = await session.post(url, json=json_body)
                else:
                    resp = await session.get(url, params=params)

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
                            "OSV API %s %s returned %d; retry %d/%d in %ds",
                            method,
                            url,
                            exc.status,
                            attempt + 1,
                            _max_retries,
                            wait,
                        )
                        await _asyncio_sleep(wait)
                        continue
                    raise
                raise  # Non-retryable statuses (4xx except 429) raise immediately

            except (aiohttp.ClientError, TimeoutError) as exc:
                last_exc = exc
                if attempt < _max_retries - 1:
                    wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "OSV API %s %s failed: %s; retry %d/%d in %ds",
                        method,
                        url,
                        repr(exc),
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await _asyncio_sleep(wait)
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError(f"Failed to fetch {url} after {_max_retries} retries")
    finally:
        if own_session:
            await session.close()


async def check_package(
    ecosystem: str,
    package: str,
    version: str,
    session: aiohttp.ClientSession | None = None,
) -> list[ThreatRecord]:
    """Check a single package@version against the OSV database.

    POSTs to ``/query`` with the package name, ecosystem, and version.

    Args:
        ecosystem: Internal ecosystem identifier (e.g. ``"npm"``).
        package: Package name.
        version: Exact version string.
        session: Optional existing aiohttp session.

    Returns:
        List of ThreatRecord objects for any known vulnerabilities.
    """
    osv_ecosystem = _map_ecosystem(ecosystem)
    url = f"{OSV_API_BASE}/query"
    body: dict[str, Any] = {
        "package": {"name": package, "ecosystem": osv_ecosystem},
        "version": version,
    }

    own_session = session is None
    if own_session:
        _timeout = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout()
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_timeout),
        )

    try:
        data = await _osv_fetch(url, method="POST", json_body=body, session=session)
        vulns = data.get("vulns", [])
        return [_parse_osv_vuln(v, ecosystem=ecosystem, package=package) for v in vulns]
    finally:
        if own_session and session is not None:
            await session.close()


async def get_vuln(
    vuln_id: str,
    session: aiohttp.ClientSession | None = None,
) -> ThreatRecord | None:
    """Fetch a single vulnerability by its OSV ID.

    Args:
        vuln_id: The OSV vulnerability ID (e.g. ``"GHSA-xxxx-xxxx-xxxx"``).
        session: Optional existing aiohttp session.

    Returns:
        A ThreatRecord if found, or None if the vuln ID returns 404.
    """
    url = f"{OSV_API_BASE}/vulns/{vuln_id}"

    own_session = session is None
    if own_session:
        _timeout = REQUEST_TIMEOUT if REQUEST_TIMEOUT is not None else get_http_timeout()
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=_timeout),
        )

    try:
        data = await _osv_fetch(url, method="GET", session=session)
        eco = _extract_first_ecosystem(data)
        pkg = _extract_first_package(data)
        return _parse_osv_vuln(data, ecosystem=eco, package=pkg)
    except aiohttp.ClientResponseError as exc:
        if exc.status == 404:
            return None
        raise
    finally:
        if own_session and session is not None:
            await session.close()


def _extract_first_ecosystem(vuln: dict[str, Any]) -> str:
    """Extract the first ecosystem from a vuln affected list, reverse-mapped."""
    for affected_entry in vuln.get("affected", []):
        pkg_info = affected_entry.get("package", {})
        osv_eco = pkg_info.get("ecosystem", "")
        # Reverse map: "npm" → "npm", "PyPI" → "pypi"
        for internal, external in ECOSYSTEM_MAP.items():
            if external == osv_eco:
                return internal
    return "npm"  # safe default


def _extract_first_package(vuln: dict[str, Any]) -> str | None:
    """Extract the first package name from a vuln's affected list."""
    for affected_entry in vuln.get("affected", []):
        pkg_info = affected_entry.get("package", {})
        name: str | None = pkg_info.get("name") if isinstance(pkg_info.get("name"), str) else None
        if name:
            return name
    return None


# ============ Bulk dump download functions ============


def _read_osv_etag(db_path: Path, db_config: DatabaseConfig | None, meta_key: str) -> str | None:
    """Read ETag from metadata store. Runs in thread pool."""
    conn = get_connection(db_path, config=db_config)
    try:
        return get_metadata(conn, meta_key)
    finally:
        conn.close()


def _write_osv_etag(db_path: Path, db_config: DatabaseConfig | None, meta_key: str, etag: str) -> None:
    """Write ETag to metadata store. Runs in thread pool."""
    conn = get_connection(db_path, config=db_config)
    try:
        set_metadata(conn, meta_key, etag)
    finally:
        conn.close()


async def download_ecosystem_dump(
    ecosystem: str,
    session: aiohttp.ClientSession | None = None,
    config: PKGDConfig | None = None,
    progress_callback: Callable[[int, int | None], None] | None = None,
) -> list[dict[str, Any]]:
    """Download and parse the OSV vulnerability dump for an ecosystem.

    Downloads the bulk data dump from OSV (e.g., npm/all.zip),
    extracts each individual vulnerability JSON file, and returns a list
    of vulnerability records.

    When ``config`` is provided, uses ETag-based conditional requests to
    skip the download if the dump hasn't changed since the last sync.

    Args:
        ecosystem: Internal ecosystem identifier (e.g. ``"npm"``, ``"pypi"``).
        session: Optional existing aiohttp session.
        config: Optional config for ETag persistence. When ``None``, no
            ETag logic runs (full download every time).

    Returns:
        List of vulnerability dicts from the dump.

    Raises:
        ValueError: If the ecosystem is not supported for dumps.
        aiohttp.ClientError: On network failures.
    """
    osv_eco = DUMP_ECOSYSTEM_MAP.get(ecosystem)
    if osv_eco is None:
        raise ValueError(f"Unsupported ecosystem for dump: {ecosystem}. Supported: {list(DUMP_ECOSYSTEM_MAP.keys())}")

    url = f"{OSV_DUMP_BASE}/{osv_eco}/all.zip"
    logger.info("Downloading OSV dump for %s from %s", ecosystem, url)

    # --- ETag: read cached value from metadata store ---
    stored_etag: str | None = None
    db_path: Path | None = None
    if config is not None:
        try:
            db_path = get_db_path(config)
            stored_etag = await asyncio.to_thread(_read_osv_etag, db_path, config.database, f"osv_etag:{osv_eco}")
        except Exception as exc:
            logger.warning("Failed to read ETag for %s: %s", ecosystem, exc)

    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300))

    assert session is not None  # for type checker

    try:
        last_exc: Exception | None = None
        _max_retries = get_max_retries()
        for attempt in range(_max_retries):
            resp: aiohttp.ClientResponse | None = None
            try:
                kwargs: dict[str, Any] = {}
                if stored_etag is not None:
                    kwargs["headers"] = {"If-None-Match": stored_etag}

                resp = await session.get(url, **kwargs)

                # 304 Not Modified — dump unchanged, skip processing
                if resp.status == 304:
                    logger.info("OSV %s dump unchanged (304), skipping", ecosystem)
                    return []

                resp.raise_for_status()

                # Stream HTTP response to a tempfile, then read zip from disk.
                # This avoids holding the full ~195 MB zip in memory.
                tmp_path: str | None = None
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                        tmp_path = tmp.name
                        async for chunk, _ in resp.content.iter_chunks():
                            if chunk:
                                tmp.write(chunk)
                                if progress_callback:
                                    progress_callback(len(chunk), resp.content_length)

                    # Extract JSON files from zip on disk (offload to thread)
                    def _extract_vulns_from_zip(zip_path: str) -> list[dict[str, Any]]:
                        extracted: list[dict[str, Any]] = []
                        with zipfile.ZipFile(zip_path) as zf:
                            for name in zf.namelist():
                                if name.endswith(".json"):
                                    try:
                                        with zf.open(name) as f:
                                            vuln = json.load(f)
                                            if isinstance(vuln, dict):
                                                extracted.append(vuln)
                                            elif isinstance(vuln, list):
                                                extracted.extend(vuln)
                                    except (json.JSONDecodeError, KeyError) as e:
                                        logger.debug("Skipping malformed OSV file %s: %s", name, e)
                                        continue
                        return extracted

                    vulns = await asyncio.to_thread(_extract_vulns_from_zip, tmp_path)

                    # Store ETag for future conditional requests
                    try:
                        new_etag = resp.headers.get("ETag")
                        if config is not None and new_etag and db_path is not None:
                            await asyncio.to_thread(
                                _write_osv_etag, db_path, config.database, f"osv_etag:{osv_eco}", new_etag
                            )
                    except Exception as exc:
                        logger.warning("Failed to store ETag for %s: %s", ecosystem, exc)

                    return vulns

                finally:
                    if tmp_path is not None:
                        with contextlib.suppress(OSError):
                            os.unlink(tmp_path)

            except (aiohttp.ClientError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
                # 404 is permanent — fail fast, never retry
                if isinstance(exc, aiohttp.ClientResponseError) and exc.status == 404:
                    raise
                last_exc = exc
                if attempt < _max_retries - 1:
                    # Check Retry-After header for 429 (rate limit) responses.
                    # Guard with isinstance check: 'resp' is only assigned when
                    # the exception is a ClientResponseError (from raise_for_status),
                    # not for network errors where session.get() itself fails.
                    if isinstance(exc, aiohttp.ClientResponseError) and exc.status == 429:
                        if resp is not None:
                            wait = calc_retry_wait(attempt, exc.status, resp)
                        else:
                            wait = 2**attempt + random.uniform(0, 1)
                    else:
                        wait = 2**attempt + random.uniform(0, 1)
                    logger.warning(
                        "OSV dump download failed: %s; retry %d/%d in %ds",
                        repr(exc),
                        attempt + 1,
                        _max_retries,
                        wait,
                    )
                    await _asyncio_sleep(wait)
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("Failed to download OSV dump after retries")

    finally:
        if own_session:
            await session.close()


async def fetch_from_dump(
    ecosystems: list[str] | None = None,
    session: aiohttp.ClientSession | None = None,
    config: PKGDConfig | None = None,
    progress_callback: Callable[[int, int | None], None] | None = None,
) -> FeedFetchResult:
    """Fetch vulnerabilities from OSV bulk data dumps.

    Downloads the full dump for each ecosystem and parses all vulnerabilities.
    This is more comprehensive than the query API but slower and uses more memory.

    When ``config`` is provided, ETag-based conditional requests skip unchanged
    dumps.

    Args:
        ecosystems: Optional list of ecosystems to fetch. If None, fetches all.
        session: Optional existing aiohttp session.
        config: Optional config for ETag persistence.

    Returns:
        FeedFetchResult containing records and ecosystem metadata.
    """
    if ecosystems is None:
        ecosystems = list(DUMP_ECOSYSTEM_MAP.keys())

    # Filter out ecosystems not supported by OSV bulk dumps.
    # Unsupported ecosystems (e.g., "homebrew") have no dump available;
    # attempting download would fail and leave last_sync as NULL,
    # causing an infinite re-sync loop on first run.
    supported_ecosystems = [eco for eco in ecosystems if eco in DUMP_ECOSYSTEM_MAP]
    skipped = set(ecosystems) - set(supported_ecosystems)
    if skipped:
        logger.info(
            "Skipping OSV sync for unsupported ecosystem(s): %s",
            ", ".join(sorted(skipped)),
        )

    results: list[ThreatRecord] = []
    ecosystem_results: list[EcosystemResult] = []

    # Group ecosystems by dump key to avoid redundant downloads
    # when multiple ecosystems (e.g., "yum" and "dnf") map to the same
    # OSV dump namespace (e.g., "Linux").
    dump_groups: dict[str, list[str]] = {}
    for eco in supported_ecosystems:
        dump_key = DUMP_ECOSYSTEM_MAP[eco]  # Safe — filtered above
        if dump_key not in dump_groups:
            dump_groups[dump_key] = []
        dump_groups[dump_key].append(eco)

    for dump_key, ecos in dump_groups.items():
        first_eco = ecos[0]
        eco_url = f"{OSV_DUMP_BASE}/{dump_key}/all.zip"
        try:
            vulns = await download_ecosystem_dump(
                first_eco,
                session=session,
                config=config,
                progress_callback=progress_callback,
            )
            logger.info("Parsed %d vulnerabilities from OSV dump for %s", len(vulns), ", ".join(ecos))

            # Produce records for ALL ecosystems sharing this dump key
            for target_eco in ecos:
                count = 0
                for vuln in vulns:
                    try:
                        record = _parse_osv_vuln(vuln, ecosystem=target_eco)
                        results.append(record)
                        count += 1
                    except Exception as e:
                        logger.debug("Failed to parse OSV vuln %s: %s", vuln.get("id"), e)
                        continue

                ecosystem_results.append(
                    EcosystemResult(
                        ecosystem=target_eco,
                        count=count,
                        url=eco_url,
                        status="success",
                        error=None,
                    )
                )

        except Exception as e:
            # Build error message that never empty
            error_msg = str(e)
            if not error_msg:
                # Try args, fallback to class name
                error_msg = e.args[0] if e.args else type(e).__name__
            logger.warning("Failed to download OSV dump for %s: %s", dump_key, error_msg)
            for target_eco in ecos:
                ecosystem_results.append(
                    EcosystemResult(
                        ecosystem=target_eco,
                        count=0,
                        url=eco_url,
                        status="failed",
                        error=error_msg,
                    )
                )
            continue

    # Determine overall fetch status from ecosystem results
    if ecosystem_results:
        any_failed = any(r.status == "failed" for r in ecosystem_results)
        any_succeeded = any(r.status == "success" for r in ecosystem_results)
        if any_failed and any_succeeded:
            overall_status = FetchStatus.PARTIAL
        elif any_failed:
            overall_status = FetchStatus.FAILED
        else:
            overall_status = FetchStatus.SUCCESS
    else:
        overall_status = FetchStatus.SUCCESS

    return FeedFetchResult(
        records=results,
        feed_metadata={"ecosystem_results": [asdict(e) for e in ecosystem_results]},
        status=overall_status,
    )
