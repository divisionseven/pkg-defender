"""Synthetic repodata fixtures for unit tests.

Generates small (3-10 package) createrepo_c-schema repomd.xml + primary.xml
files for the unit test suite. No network, no I/O at module import time —
call :func:`build_synthetic_fixtures` from a fixture or test to materialize
the bytes.

This is a conftest helper, not a real fixture file — it produces in-memory
bytes for use in mocked HTTP responses. The actual ``tests/fixtures/repodata/synthetic/``
directory is reserved for committed real-cached fixtures (per Phase 0
plan §"Fixture directory structure").

Why programmatic instead of on-disk fixtures:
    * Deterministic — no "stale fixture" footgun
    * Cheap to extend — add a package, regenerate
    * Easy to introspect in tests (each test can build its own subset)
"""

from __future__ import annotations

import gzip
import lzma
import xml.etree.ElementTree as ET
from typing import Literal

# Fixed reference epoch: 2024-01-01 12:00:00 UTC = 1704110400.
# All synthetic <time file="..."/> values use this epoch so tests can
# assert against a known datetime.
SYNTHETIC_TIME_EPOCH: int = 1_704_110_400


def _build_primary_xml(packages: list[tuple[str, str, str]]) -> bytes:
    """Build a createrepo_c-schema primary.xml byte string.

    Args:
        packages: List of ``(name, version, release)`` tuples.

    Returns:
        UTF-8 encoded primary.xml bytes.
    """
    root = ET.Element("package")
    # ``<name>`` and ``<version>`` are required for createrepo_c; ``<time>``
    # has a ``file`` attribute (epoch seconds) and optional ``build``.
    packages_elem = ET.SubElement(root, "packages")
    for name, version, release in packages:
        pkg = ET.SubElement(packages_elem, "package", type="rpm")
        ET.SubElement(pkg, "name").text = name
        ET.SubElement(pkg, "version").text = version
        ET.SubElement(pkg, "release").text = release
        ET.SubElement(pkg, "arch").text = "x86_64"
        time_elem = ET.SubElement(pkg, "time")
        time_elem.set("file", str(SYNTHETIC_TIME_EPOCH))
        time_elem.set("build", str(SYNTHETIC_TIME_EPOCH - 3600))
    encoded: bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return encoded


def _build_repomd_xml(primary_href: str) -> bytes:
    """Build a createrepo_c-schema repomd.xml byte string.

    Args:
        primary_href: The ``href`` for the primary ``<data>`` element,
            e.g. ``"repodata/abc-primary.xml.gz"``.

    Returns:
        UTF-8 encoded repomd.xml bytes.
    """
    root = ET.Element("repomd")
    root.set("xmlns", "http://linux.duke.edu/metadata/repo")
    root.set("xmlns:rpm", "http://linux.duke.edu/metadata/rpm")
    data = ET.SubElement(root, "data", type="primary")
    checksum = ET.SubElement(data, "checksum", type="sha256")
    checksum.text = "0" * 64  # dummy 64-char hex
    open_checksum = ET.SubElement(data, "open-checksum", type="sha256")
    open_checksum.text = "0" * 64
    location = ET.SubElement(data, "location")
    location.set("href", primary_href)
    timestamp = ET.SubElement(data, "timestamp")
    timestamp.text = str(SYNTHETIC_TIME_EPOCH)
    size = ET.SubElement(data, "size")
    size.text = "0"
    open_size = ET.SubElement(data, "open-size")
    open_size.text = "0"
    encoded: bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return encoded


def build_synthetic_fixtures(
    packages: list[tuple[str, str, str]] | None = None,
    compression: Literal["gz", "xz", "zst", "none"] = "gz",
    primary_href: str | None = None,
) -> tuple[bytes, bytes]:
    """Build synthetic ``(repomd.xml, primary.xml)`` bytes for tests.

    Args:
        packages: Package list. Defaults to 3 well-known packages
            (curl, wget, httpd) at synthetic NVRs.
        compression: Compression format for primary.xml.
            ``"none"`` returns uncompressed bytes (for tests that
            verify the decompression fallback chain).
        primary_href: Override the primary ``<location href>``. If
            ``None``, derived from the compression format.

    Returns:
        Tuple of ``(repomd_xml_bytes, primary_xml_bytes)`` — both
        ready to return from a mocked HTTP response.
    """
    if packages is None:
        packages = [
            ("curl", "8.21.0", "1.fc45"),
            ("wget", "1.21.4", "2.fc45"),
            ("httpd", "2.4.62", "1.fc45"),
        ]
    if primary_href is None:
        ext = "" if compression == "none" else f".{compression}"
        primary_href = f"repodata/abc123-primary.xml{ext}"
    repomd_bytes = _build_repomd_xml(primary_href)
    primary_raw = _build_primary_xml(packages)
    if compression == "gz":
        primary_bytes = gzip.compress(primary_raw)
    elif compression == "xz":
        primary_bytes = lzma.compress(primary_raw, format=lzma.FORMAT_XZ)
    elif compression == "none":
        primary_bytes = primary_raw
    elif compression == "zst":
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError as exc:
            # Skip zstd fixtures if library is not installed
            raise ImportError("zstandard library not installed; cannot build .zst fixtures") from exc
        cctx = zstandard.ZstdCompressor()
        primary_bytes = cctx.compress(primary_raw)
    else:
        raise ValueError(f"Unknown compression format: {compression}")
    return repomd_bytes, primary_bytes
