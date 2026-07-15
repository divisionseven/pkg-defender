# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""YUM/DNF repodata client for per-package ``<time file>`` lookup.

Universal source across all 11 verified RPM distros (YUM-001 §6.1). Returns
a *proxied* timestamp — accurate to minutes for fresh packages, accurate
to weeks/months for frozen-snapshot repos (Oracle 9 ``latest``, openEuler
22.03 LTS). NOT a "verified" claim (no cryptographic attestation of when
the file was added); the cascade renders this as ``(PROXIED — NOT
RELIABLE)`` in the UI.

**Per Resolved Design Decision Q5:** the constructor accepts an optional
``repo_urls`` parameter to follow the ``PYPI_REGISTRY_URL`` module-level
constant pattern. When ``None``, falls back to the module-level
``_DEFAULT_REPODATA_URLS`` (11 URLs).

**Per Resolved Design Decision Q9:** the 11 default URLs are validated
with a live HEAD request **on first use, lazily** (NOT at module import
time — module imports should be side-effect-free per Python convention;
this also keeps tests fast and supports offline CI). URLs returning
non-200 emit ``logger.warning(...)`` and are skipped. The validation
result is cached in a module-level ``_validated_default_urls`` variable
so subsequent calls are cheap. Set ``PKGD_SKIP_URL_VALIDATION=1`` env
var to skip the HEAD validation entirely.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import logging
import lzma
import os
import tempfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp
import defusedxml.ElementTree as ET

from pkg_defender.core.registry_domains import is_domain_allowed

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

logger = logging.getLogger(__name__)

# Source string used by the cascade when this client produces a result.
# Public value — keep in sync with the cascade's source-enum.
SOURCE_REPODATA: str = "repodata"

# Environment variable that, when set to ``"1"``, disables lazy HEAD
# validation entirely. Useful for offline / air-gapped CI environments.
_SKIP_VALIDATION_ENV: str = "PKGD_SKIP_URL_VALIDATION"

# Per-URL request timeout (seconds) — kept short because HEAD checks
# must be fast (the cascade can't wait 30s per URL × 11 URLs = 5+ min).
_REPODATA_VALIDATION_TIMEOUT: float = 5.0

# Decompression buffer threshold. primary.xml is stream-decompressed
# from a temp file (196MB+ for Fedora rawhide) to bound memory.
_DECOMPRESS_CHUNK_SIZE: int = 65536

# Module-level state — 11 default RPM distros verified end-to-end in
# YUM-001 §6.1. Order matters: the cascade walks them in this order
# (Fedora rawhide first because Bodhi-anchored data is most reliable;
# frozen-snapshot repos last so we have a fallback when nothing else
# has the package). No Fedora 41 / EPEL 10 URLs (unverified); no AL2023
# (403/404 per YUM-001 §4 / §6.3); no RHEL (paid subscription required).
_DEFAULT_REPODATA_URLS: tuple[str, ...] = (
    # Fedora (Bodhi + Koji + repodata available) — YUM-001 §2.3
    "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os",
    # EPEL (Bodhi + repodata available) — YUM-001 §2.3 (YUM-001 verified EPEL 9 only)
    "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64",
    # RHEL clones (repodata only) — YUM-001 §2.3
    "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os",
    "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os",
    "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os",
    # Oracle 9 — YUM-001 §2.3 (the `latest` path is a FROZEN snapshot
    # from 2022-2023; cascade rejects via `_FROZEN_SNAPSHOT_REPODATA_URLS`)
    "https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64",
    # openEuler (frozen snapshot per YUM-001 §2.3)
    "https://repo.openeuler.org/openEuler-22.03-LTS/OS/x86_64",
    # Mageia — YUM-001 §2.3
    "https://mirrors.kernel.org/mageia/distrib/9/x86_64/media/core/release",
    # openSUSE Tumbleweed — YUM-001 §2.3
    "https://download.opensuse.org/tumbleweed/repo/oss",
    # RPM Fusion free (EL9) — YUM-001 §2.3
    "https://download1.rpmfusion.org/free/el/updates/9/x86_64",
    # Amazon Linux 2 — YUM-001 §6.5 (AL2 needs the hash directory)
    "https://cdn.amazonlinux.com/2/core/2.0/x86_64/793d6c328e20f10fdc29a8f88d8488406da73e29f40b3912f49fbe03947df76a",
)

# Cached result of ``_ensure_validated()``. ``None`` means "not yet
# validated". The list contains URLs that returned 200 on HEAD; URLs
# that returned non-200 are omitted (and logged once during validation).
_validated_default_urls: list[str] | None = None

# Tracks whether we've already emitted the "all default URLs failed"
# error. Prevents log spam if the cascade hits this condition on every
# call (e.g. during a long-running daemon run with all URLs down).
_all_urls_failed_logged: bool = False


def _reset_validation_cache_for_tests() -> None:
    """Clear the module-level validation cache. **Test-only API.**

    Production code MUST NOT call this. Tests should call it in a
    fixture to ensure HEAD-validation state doesn't leak between cases
    (the cache is shared across all :class:`RepodataClient` instances).
    """
    global _validated_default_urls, _all_urls_failed_logged
    _validated_default_urls = None
    _all_urls_failed_logged = False


async def _check_head_url(
    session: aiohttp.ClientSession,
    url: str,
    timeout: aiohttp.ClientTimeout,
) -> str | None:
    """HEAD-check a single repodata URL for accessibility.

    Logs a warning on non-200 or network errors and returns the URL on
    success, or ``None`` on failure.

    Args:
        session: Active ``aiohttp.ClientSession``.
        url: The repodata URL to check.
        timeout: Per-request timeout configuration.

    Returns:
        The URL if HEAD returned 200, or ``None`` if the URL is
        unreachable (non-200, network error, or timeout).
    """
    try:
        async with session.head(url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status == 200:
                return url
            logger.warning(
                "repodata URL validation: %s returned %d, skipping",
                url,
                resp.status,
            )
    except aiohttp.ClientError as exc:
        logger.warning(
            "repodata URL validation: %s raised %s, skipping",
            url,
            exc,
        )
    except TimeoutError:
        logger.warning(
            "repodata URL validation: %s timed out, skipping",
            url,
        )
    return None


async def _ensure_validated(
    session: aiohttp.ClientSession,
) -> list[str]:
    """Lazily validate the 11 default URLs on first use.

    HEAD-checks all URLs in parallel via ``asyncio.gather``. Non-200
    responses are logged at warning level and skipped. The validated
    list is cached for the process lifetime.

    Honors :data:`_SKIP_VALIDATION_ENV` — when set to ``"1"``, skips
    HEAD validation entirely and returns the full list.

    Args:
        session: Active ``aiohttp.ClientSession`` for the HEAD requests.

    Returns:
        Subset of ``_DEFAULT_REPODATA_URLS`` that returned 200 on HEAD.
        Returns the full list when validation is skipped via env var.
        Returns an empty list when all URLs failed (logged at error).
    """
    global _validated_default_urls, _all_urls_failed_logged

    if _validated_default_urls is not None:
        return _validated_default_urls

    if os.environ.get(_SKIP_VALIDATION_ENV) == "1":
        logger.debug(
            "%s=1 — skipping repodata URL validation (using full list)",
            _SKIP_VALIDATION_ENV,
        )
        _validated_default_urls = list(_DEFAULT_REPODATA_URLS)
        return _validated_default_urls

    timeout_cfg = aiohttp.ClientTimeout(total=_REPODATA_VALIDATION_TIMEOUT)
    tasks = [_check_head_url(session, url, timeout_cfg) for url in _DEFAULT_REPODATA_URLS]
    results: list[str | None] = await asyncio.gather(*tasks)
    validated: list[str] = [url for url in results if url is not None]

    if not validated and not _all_urls_failed_logged:
        logger.error(
            "repodata URL validation: all %d default URLs failed HEAD — "
            "repodata cascade will return (None, None) for every call",
            len(_DEFAULT_REPODATA_URLS),
        )
        _all_urls_failed_logged = True
    _validated_default_urls = validated
    return validated


def _split_nvr(nvr: str) -> tuple[str, str, str]:
    """Split an NVR string into ``(name, version, release)``.

    Handles versions that themselves contain ``-`` (rare but legal in
    RPM). The algorithm matches ``rpm``'s own split: split on ``-``,
    first segment is the name, last segment is the release, everything
    in between is the version (joined back with ``-``).

    Args:
        nvr: NVR string, e.g. ``"curl-8.21.0~rc1-1.fc45"``.

    Returns:
        ``(name, version, release)`` triple. If the input has fewer
        than 3 ``-``-separated parts, returns ``(nvr, "", "")`` so the
        caller can skip the match gracefully.
    """
    parts = nvr.split("-")
    if len(parts) < 3:
        return (nvr, "", "")
    name = parts[0]
    release = parts[-1]
    version = "-".join(parts[1:-1])
    return (name, version, release)


def _decompress(data: bytes, href: str) -> bytes:
    """Decompress primary.xml based on the file extension.

    Supports ``.gz`` (gzip), ``.xz`` (lzma), and ``.zst`` (zstandard —
    optional dependency). Returns the original ``data`` unchanged if
    the extension is unrecognized (some repos serve uncompressed
    primary.xml as a fallback).

    Args:
        data: Compressed bytes from the response.
        href: The href from repomd.xml, used to determine compression
            (e.g. ``"repodata/abcd-primary.xml.gz"``).

    Returns:
        Decompressed bytes, ready for XML parsing.
    """
    lower = href.lower()
    if lower.endswith(".gz"):
        return gzip.decompress(data)
    if lower.endswith(".xz"):
        return lzma.decompress(data)
    if lower.endswith(".zst"):
        try:
            import zstandard
        except ImportError:
            logger.warning(
                "zstandard not installed — cannot decompress %s. Install python-zstandard to support .zst primary.xml.",
                href,
            )
            return b""
        return bytes(zstandard.ZstdDecompressor().decompress(data))
    return data


def _decompress_file(src_path: str, href: str) -> str:
    """Stream-decompress a file based on the *href* extension.

    For ``.gz`` (gzip) and ``.xz`` (lzma) extensions, reads the
    compressed file in streaming chunks of :data:`_DECOMPRESS_CHUNK_SIZE`,
    writes decompressed data to a new temporary file, deletes *src_path*,
    and returns the decompressed path.

    For ``.zst`` (zstandard), uses ``copy_stream`` for bounded-memory
    decompression (no intermediate Python bytes object holds the full
    decompressed content).

    For unrecognised extensions (uncompressed fallback), returns
    *src_path* unchanged — no decompression needed.

    Args:
        src_path: Path to the compressed file.
        href: The href from repomd.xml, used to determine compression
            (e.g. ``"repodata/abcd-primary.xml.gz"``).

    Returns:
        Path to the decompressed file. When the input was already
        uncompressed, returns *src_path* unchanged.

    Raises:
        OSError: On file I/O failure (disk full, permission error).
        ImportError: For ``.zst`` when ``zstandard`` is not installed.
    """
    lower = href.lower()

    if not (lower.endswith(".gz") or lower.endswith(".xz") or lower.endswith(".zst")):
        return src_path

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as dst:
        dst_path = dst.name

    try:
        if lower.endswith(".gz"):
            with gzip.open(src_path, "rb") as src, open(dst_path, "wb") as dst_file:
                while True:
                    chunk = src.read(_DECOMPRESS_CHUNK_SIZE)
                    if not chunk:
                        break
                    dst_file.write(chunk)

        elif lower.endswith(".xz"):
            with lzma.open(src_path, "rb") as src, open(dst_path, "wb") as dst_file:
                while True:
                    chunk = src.read(_DECOMPRESS_CHUNK_SIZE)
                    if not chunk:
                        break
                    dst_file.write(chunk)

        elif lower.endswith(".zst"):
            try:
                import zstandard
            except ImportError as exc:
                logger.warning(
                    "zstandard not installed — cannot decompress %s. "
                    "Install python-zstandard to support .zst primary.xml.",
                    src_path,
                )
                raise ImportError("zstandard not installed") from exc

            with open(src_path, "rb") as src, open(dst_path, "wb") as dst_file:
                zstandard.ZstdDecompressor().copy_stream(src, dst_file)

        os.unlink(src_path)
        return dst_path
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(dst_path)
        raise


def _parse_time_attr(time_elem: Element) -> datetime | None:
    """Extract the ``file`` attribute of a ``<time>`` element as datetime.

    Args:
        time_elem: ``<time>`` XML element with a ``file="..."`` attribute
            containing epoch seconds.

    Returns:
        UTC-aware :class:`datetime`, or ``None`` if the attribute is
        missing or unparseable.
    """
    file_attr = time_elem.get("file")
    if not file_attr:
        return None
    try:
        return datetime.fromtimestamp(int(file_attr), tz=UTC)
    except (TypeError, ValueError):
        return None


def _find_primary_href(repomd_bytes: bytes) -> str | None:
    """Parse repomd.xml and return the ``<location href>`` of primary.

    Real createrepo_c output declares ``xmlns="http://linux.duke.edu/metadata/repo"``;
    some minimal tools omit the namespace. This function accepts both by
    matching on the *local* element name (stripped of any ``{ns}`` prefix).

    Args:
        repomd_bytes: Raw repomd.xml bytes (no compression).

    Returns:
        The ``href`` attribute of the ``<location>`` element inside
        ``<data type="primary">``, or ``None`` if the element is
        missing.
    """
    try:
        root = ET.fromstring(repomd_bytes)
    except ET.ParseError:
        return None

    def _local(tag: str) -> str:
        """Strip the ``{namespace}`` prefix from an ElementTree tag."""
        return tag.split("}", 1)[-1] if "}" in tag else tag

    for data_elem in list(root):
        if _local(data_elem.tag) != "data":
            continue
        if data_elem.get("type") != "primary":
            continue
        for child in data_elem:
            if _local(child.tag) == "location":
                return child.get("href")
    return None


def _iter_packages(primary_bytes: bytes) -> Any:
    """Yield each ``<package>`` element from a primary.xml byte stream.

    Uses :func:`xml.etree.ElementTree.iterparse` to bound memory
    regardless of primary.xml size. After yielding each package, the
    element is cleared from the tree to release memory (critical for
    the 196MB Fedora rawhide primary.xml).

    Args:
        primary_bytes: Decompressed primary.xml bytes.

    Yields:
        Each ``<package>`` :class:`xml.etree.ElementTree.Element`.
    """
    context = ET.iterparse(io.BytesIO(primary_bytes), events=("end",))
    for _event, elem in context:
        # ``elem.tag`` may be a fully-qualified name in some XML
        # parsers; strip the namespace prefix for matching.
        tag = elem.tag.split("}", 1)[-1]
        if tag == "package":
            yield elem
            elem.clear()


def _iter_packages_from_file(xml_path: str) -> Any:
    """Yield each ``<package>`` element from a primary.xml file on disk.

    Uses :func:`defusedxml.ElementTree.iterparse` directly on the file
    path to keep memory bounded regardless of primary.xml size. After
    yielding each package, the element is cleared from the tree to
    release memory (critical for the 196MB Fedora rawhide primary.xml).

    Args:
        xml_path: Path to the decompressed primary.xml file on disk.

    Yields:
        Each ``<package>`` :class:`defusedxml.ElementTree.Element`.
    """
    context = ET.iterparse(xml_path, events=("end",))
    for _event, elem in context:
        tag = elem.tag.split("}", 1)[-1]
        if tag == "package":
            yield elem
            elem.clear()


def _match_package(
    packages: Any,
    name: str,
    version: str,
    release: str,
) -> datetime | None:
    """Find a ``<package>`` matching ``(name, version, release)`` and return
    its ``<time file>`` value.

    Streams the ``packages`` iterable (no list materialization) to keep
    memory bounded.

    Args:
        packages: Iterable of ``<package>`` elements (e.g. from
            :func:`_iter_packages`).
        name: Package name (e.g. ``"curl"``).
        version: Version segment of the NVR (e.g. ``"8.21.0~rc1"``).
        release: Release segment of the NVR (e.g. ``"1.fc45"``).

    Returns:
        UTC-aware :class:`datetime` of the first match's ``<time file>``,
        or ``None`` if no package matches.
    """
    for pkg in packages:
        # ``<name>`` is a direct child of ``<package>``
        name_elem = pkg.find("name")
        if name_elem is None or (name_elem.text or "") != name:
            continue
        version_elem = pkg.find("version")
        if version_elem is None or (version_elem.text or "") != version:
            continue
        release_elem = pkg.find("release")
        if release_elem is None or (release_elem.text or "") != release:
            continue
        # Match found — extract the <time file="..."/> attribute.
        time_elem = pkg.find("time")
        if time_elem is None:
            return None
        return _parse_time_attr(time_elem)
    return None


class RepodataClient:
    """Async YUM/DNF repodata client for per-package ``<time file>`` lookup.

    See module docstring for design rationale. The second element of
    :meth:`get_publish_time` is the **matched URL** (not a source
    string) — the cascade translates URL→``"repodata"`` per BC-8 and
    may need the URL for per-URL rejection (openEuler per Q7) and for
    the validator's per-URL source key (so the N>5 clamping heuristic
    buckets per-repo, not all-repodata-together).
    """

    def __init__(
        self,
        repo_urls: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            repo_urls: Per-ecosystem override (Q5). When ``None``,
                falls back to the module-level
                :data:`_DEFAULT_REPODATA_URLS` (lazily validated on
                first use).
            session: Optional ``aiohttp.ClientSession`` for connection
                pooling. If ``None``, a transient session is created
                per request.
        """
        self._explicit_repo_urls: list[str] | None = repo_urls
        self._session: aiohttp.ClientSession | None = session

    async def get_publish_time(
        self,
        package: str,
        nvr: str,
    ) -> tuple[datetime | None, str | None]:
        """Return ``(publish_time, matched_url)`` for *package* at *nvr*.

        Walks each configured URL in order, fetches ``repomd.xml``,
        follows the primary ``<location href>``, decompresses
        primary.xml, stream-parses it for a matching ``<package>``, and
        returns the first match's ``<time file>`` value.

        Args:
            package: Package name (e.g. ``"curl"``).
            nvr: Full NVR (e.g. ``"curl-8.21.0~rc1-1.fc45"``).

        Returns:
            ``(datetime | None, str | None)``. The first element is
            the UTC-aware publish time on match, else ``None``. The
            second element is the URL that produced the match (the
            cascade uses this for per-URL rejection and the
            validator's source key), else ``None`` when no URL
            matched.

        Note:
            Never raises — all network, parse, and decompression
            errors are logged at debug level and cause the cascade to
            walk to the next URL. Returns ``(None, None)`` when no
            URL has the package.
        """
        name, version, release = _split_nvr(nvr)
        if not version or not release:
            logger.debug(
                "repodata: NVR %r has fewer than 3 segments — cannot match",
                nvr,
            )
            return (None, None)

        urls = await self._resolve_urls()
        if not urls:
            return (None, None)

        for url in urls:
            try:
                result = await self._probe_url(url, name, version, release)
            except aiohttp.ClientError as exc:
                logger.debug("repodata: client error on %s: %s", url, exc)
                continue
            except TimeoutError as exc:
                logger.debug("repodata: timeout on %s: %s", url, exc)
                continue
            except (OSError, ValueError) as exc:
                # OSError: socket issues; ValueError: malformed XML
                logger.debug("repodata: parse error on %s: %s", url, exc)
                continue
            if result is not None:
                return (result, url)
        return (None, None)

    async def _resolve_urls(self) -> list[str]:
        """Return the URL list to walk: explicit override or validated default.

        When the caller supplied ``repo_urls=`` to the constructor,
        use it directly (no validation, no caching). Otherwise, run
        the lazy HEAD validation on first call.
        """
        if self._explicit_repo_urls is not None:
            return self._explicit_repo_urls
        if self._session is None:
            async with aiohttp.ClientSession() as tmp_session:
                return await _ensure_validated(tmp_session)
        return await _ensure_validated(self._session)

    async def _probe_url(
        self,
        base_url: str,
        name: str,
        version: str,
        release: str,
    ) -> datetime | None:
        """Fetch repomd.xml + primary.xml from *base_url* and look for
        a matching package.

        Primary.xml is streamed to a temp file and decompressed in
        chunks to bound memory regardless of repodata size.

        Args:
            base_url: Repo base URL (e.g. ``"https://.../os"``).
            name: Package name.
            version: Version segment.
            release: Release segment.

        Returns:
            The matched package's ``<time file>`` as UTC-aware
            datetime, or ``None`` if not found in this repo.
        """
        repomd_url = f"{base_url}/repodata/repomd.xml"
        repomd_bytes = await self._fetch_bytes(repomd_url)
        if repomd_bytes is None:
            return None
        href = _find_primary_href(repomd_bytes)
        if not href:
            return None
        # ``href`` may be absolute (rare) or relative (common).
        if href.startswith("http://") or href.startswith("https://"):
            primary_url = href
        else:
            primary_url = f"{base_url}/{href.lstrip('/')}"

        # Stream primary.xml to temp file, decompress on disk,
        # stream-parse from the decompressed file — never holds
        # the full ~196 MB primary.xml in memory.
        tmp_paths: list[str] = []
        try:
            primary_tmp = await self._stream_to_temp(primary_url)
            if primary_tmp is None:
                return None
            tmp_paths.append(primary_tmp)

            decompressed_path = _decompress_file(primary_tmp, href)
            tmp_paths.append(decompressed_path)

            packages = _iter_packages_from_file(decompressed_path)
            return _match_package(packages, name, version, release)
        finally:
            for p in tmp_paths:
                with contextlib.suppress(OSError):
                    os.unlink(p)

    async def _fetch_bytes(self, url: str) -> bytes | None:
        """Fetch a URL and return its body, or ``None`` on non-200.

        Args:
            url: The URL to fetch.

        Returns:
            Raw response bytes, or ``None`` if the response was
            non-200, a network error occurred, or the URL failed
            the SSRF domain allowlist check.
        """
        # SSRF defense-in-depth: verify URL is in the yum allowlist
        if not is_domain_allowed("yum", url):
            logger.warning(
                "repodata: SSRF domain check failed for %s -- not in yum allowlist",
                url,
            )
            return None

        timeout_cfg = aiohttp.ClientTimeout(total=30)
        if self._session is not None:
            async with self._session.get(url, timeout=timeout_cfg) as resp:
                if resp.status != 200:
                    return None
                return await resp.read()
        async with (
            aiohttp.ClientSession() as tmp_session,
            tmp_session.get(url, timeout=timeout_cfg) as resp,
        ):
            if resp.status != 200:
                return None
            return await resp.read()

    async def _stream_to_temp(self, url: str) -> str | None:
        """Fetch *url* and stream the response body to a temporary file.

        Returns the temp file path (caller must clean up), or ``None``
        on SSRF block, non-200 response, or network error.

        Args:
            url: The URL to fetch.

        Returns:
            Temporary file path on success, ``None`` on failure.
        """
        # SSRF defense-in-depth: verify URL is in the yum allowlist
        if not is_domain_allowed("yum", url):
            logger.warning(
                "repodata: SSRF domain check failed for %s -- not in yum allowlist",
                url,
            )
            return None

        timeout_cfg = aiohttp.ClientTimeout(total=30)

        async def _do_stream(session: aiohttp.ClientSession) -> str | None:
            async with session.get(url, timeout=timeout_cfg) as resp:
                if resp.status != 200:
                    return None
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    try:
                        async for chunk, _ in resp.content.iter_chunks():
                            if chunk:
                                tmp.write(chunk)
                        path = tmp.name
                    except Exception:
                        with contextlib.suppress(OSError):
                            os.unlink(tmp.name)
                        raise
                return path

        if self._session is not None:
            return await _do_stream(self._session)
        async with aiohttp.ClientSession() as tmp_session:
            return await _do_stream(tmp_session)

    async def close(self) -> None:
        """Close the underlying ``aiohttp`` session if owned by this client.

        Callers that pass their own session are responsible for closing
        it themselves. This method is a no-op when no session was
        injected at construction.
        """
        if self._session is not None:
            await self._session.close()
            self._session = None
