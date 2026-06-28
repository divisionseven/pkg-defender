"""Tests for the npm registry adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from pkg_defender.models import VersionInfo
from pkg_defender.registry.npm import (
    NPM_REGISTRY_URL,
    _encode_package_name,
    _fetch_json,
    get_all_versions,
    get_latest_version,
    get_publish_time,
    get_version_info,
)

# ---------------------------------------------------------------------------
# Sample metadata blobs
# ---------------------------------------------------------------------------

SAMPLE_METADATA: dict[str, Any] = {
    "dist-tags": {"latest": "2.1.0"},
    "versions": {
        "1.0.0": {},
        "1.5.0": {},
        "2.0.0": {},
        "2.1.0": {},
    },
    "time": {
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2025-06-15T10:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.5.0": "2021-06-15T10:00:00.000Z",
        "2.0.0": "2023-03-01T08:30:00.000Z",
        "2.1.0": "2025-06-15T10:00:00.000Z",
    },
}

SCOPED_METADATA: dict[str, Any] = {
    "dist-tags": {"latest": "3.0.0"},
    "versions": {"2.0.0": {}, "3.0.0": {}},
    "time": {
        "created": "2021-01-01T00:00:00.000Z",
        "modified": "2025-01-01T00:00:00.000Z",
        "2.0.0": "2022-07-01T00:00:00.000Z",
        "3.0.0": "2025-01-01T00:00:00.000Z",
    },
}

# ---------------------------------------------------------------------------
# _encode_package_name
# ---------------------------------------------------------------------------


class TestEncodePackageName:
    def test_plain_package_unchanged(self) -> None:
        assert _encode_package_name("lodash") == "lodash"

    def test_plain_with_hyphens(self) -> None:
        assert _encode_package_name("express-rate-limit") == "express-rate-limit"

    def test_scoped_package_encoded(self) -> None:
        assert _encode_package_name("@scope/name") == "%40scope%2Fname"

    def test_scoped_with_hyphens(self) -> None:
        assert _encode_package_name("@babel/core") == "%40babel%2Fcore"

    def test_scoped_with_org(self) -> None:
        assert _encode_package_name("@types/node") == "%40types%2Fnode"


# ---------------------------------------------------------------------------
# _fetch_json
# ---------------------------------------------------------------------------


class TestFetchJson:
    async def test_returns_metadata_when_fetch_succeeds(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await _fetch_json(url)
        assert result == SAMPLE_METADATA

    async def test_creates_session_when_none(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload={"ok": True})
            result = await _fetch_json(url, session=None)
        assert result == {"ok": True}

    async def test_uses_provided_session(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            with aioresponses() as m:
                m.get(url, payload={"ok": True})
                result = await _fetch_json(url, session=session)
        assert result == {"ok": True}

    async def test_retries_then_succeeds(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, status=500)
            m.get(url, status=500)
            m.get(url, payload={"recovered": True})
            result = await _fetch_json(url)
        assert result == {"recovered": True}

    async def test_retries_exhausted_raises(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, status=500)
            m.get(url, status=500)
            m.get(url, status=500)
            with pytest.raises(aiohttp.ClientResponseError):
                await _fetch_json(url)

    async def test_timeout_raises(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            with pytest.raises(asyncio.TimeoutError):
                await _fetch_json(url)


# ---------------------------------------------------------------------------
# get_publish_time
# ---------------------------------------------------------------------------


class TestGetPublishTime:
    async def test_returns_datetime_for_known_version(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            publish_time, source = await get_publish_time("lodash", "1.5.0")

        assert publish_time is not None
        assert publish_time == datetime(2021, 6, 15, 10, 0, 0, tzinfo=UTC)
        assert source == "registry_api"

    async def test_returns_none_for_unknown_version(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            publish_time, source = await get_publish_time("lodash", "99.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_returns_none_for_404(self) -> None:
        url = f"{NPM_REGISTRY_URL}/nonexistent-pkg-xyz"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            publish_time, source = await get_publish_time("nonexistent-pkg-xyz", "1.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_handles_scoped_package(self) -> None:
        url = f"{NPM_REGISTRY_URL}/%40types%2Fnode"
        with aioresponses() as m:
            m.get(url, payload=SCOPED_METADATA)
            publish_time, source = await get_publish_time("@types/node", "2.0.0")

        assert publish_time is not None
        assert publish_time == datetime(2022, 7, 1, 0, 0, 0, tzinfo=UTC)
        assert source == "registry_api"

    async def test_skips_created_and_modified_keys(self) -> None:
        """Ensure 'created' and 'modified' don't match a version lookup."""
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            # 'created' is a key in the time dict but not a real version
            publish_time, source = await get_publish_time("lodash", "created")

        assert publish_time is None
        assert source == "no_github_url"


# ---------------------------------------------------------------------------
# get_all_versions
# ---------------------------------------------------------------------------


class TestGetAllVersions:
    async def test_returns_all_versions(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await get_all_versions("lodash")

        assert set(result) == {"1.0.0", "1.5.0", "2.0.0", "2.1.0"}

    async def test_returns_empty_on_404(self) -> None:
        url = f"{NPM_REGISTRY_URL}/nonexistent-pkg-xyz"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            result = await get_all_versions("nonexistent-pkg-xyz")

        assert result == []

    async def test_handles_scoped_package(self) -> None:
        url = f"{NPM_REGISTRY_URL}/%40types%2Fnode"
        with aioresponses() as m:
            m.get(url, payload=SCOPED_METADATA)
            result = await get_all_versions("@types/node")

        assert set(result) == {"2.0.0", "3.0.0"}


# ---------------------------------------------------------------------------
# get_latest_version
# ---------------------------------------------------------------------------


class TestGetLatestVersion:
    async def test_returns_latest(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await get_latest_version("lodash")

        assert result == "2.1.0"

    async def test_returns_none_on_404(self) -> None:
        url = f"{NPM_REGISTRY_URL}/nonexistent-pkg-xyz"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            result = await get_latest_version("nonexistent-pkg-xyz")

        assert result is None

    async def test_handles_scoped_package(self) -> None:
        url = f"{NPM_REGISTRY_URL}/%40types%2Fnode"
        with aioresponses() as m:
            m.get(url, payload=SCOPED_METADATA)
            result = await get_latest_version("@types/node")

        assert result == "3.0.0"


# ---------------------------------------------------------------------------
# get_version_info
# ---------------------------------------------------------------------------


class TestGetVersionInfo:
    async def test_returns_version_info(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await get_version_info("lodash", "2.0.0")

        assert result is not None
        assert result.version == "2.0.0"
        assert result.ecosystem == "npm"
        assert result.package_name == "lodash"
        assert result.publish_time == datetime(2023, 3, 1, 8, 30, 0, tzinfo=UTC)

    async def test_returns_none_for_unknown_version(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await get_version_info("lodash", "99.0.0")

        assert result is None

    async def test_returns_none_on_404(self) -> None:
        url = f"{NPM_REGISTRY_URL}/nonexistent-pkg-xyz"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            result = await get_version_info("nonexistent-pkg-xyz", "1.0.0")

        assert result is None

    async def test_dataclass_fields_populated(self) -> None:
        url = f"{NPM_REGISTRY_URL}/lodash"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_METADATA)
            result = await get_version_info("lodash", "1.0.0")

        assert result is not None
        assert isinstance(result, VersionInfo)
        assert result.version == "1.0.0"
        assert result.ecosystem == "npm"
        assert result.package_name == "lodash"
        assert isinstance(result.publish_time, datetime)


# ---------------------------------------------------------------------------
# Session reuse
# ---------------------------------------------------------------------------


class TestSessionReuse:
    async def test_shared_session_across_calls(self) -> None:
        """Verify a single session can be passed to multiple calls."""
        url = f"{NPM_REGISTRY_URL}/lodash"
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            with aioresponses() as m:
                m.get(url, payload=SAMPLE_METADATA)
                m.get(url, payload=SAMPLE_METADATA)
                v1, _ = await get_publish_time("lodash", "1.0.0", session=session)
                v2 = await get_latest_version("lodash", session=session)

        assert v1 == datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert v2 == "2.1.0"
