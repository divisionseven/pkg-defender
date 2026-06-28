"""Tests for the PyPI registry adapter."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import aiohttp
from aioresponses import aioresponses

from pkg_defender.models import VersionInfo
from pkg_defender.registry.pypi import (
    PYPI_REGISTRY_URL,
    PyPIAdapter,
)

# ---------------------------------------------------------------------------
# Sample PyPI response blobs
# ---------------------------------------------------------------------------

SAMPLE_VERSION_RESPONSE: dict[str, Any] = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
    },
    "urls": [
        {
            "filename": "requests-2.31.0-py3-none-any.whl",
            "upload_time_iso_8601": "2023-05-22T14:00:00.000000Z",
            "size": 62624,
        },
        {
            "filename": "requests-2.31.0.tar.gz",
            "upload_time_iso_8601": "2023-05-22T14:00:05.000000Z",
            "size": 110986,
        },
    ],
}

SAMPLE_ALL_VERSIONS_RESPONSE: dict[str, Any] = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
    },
    "releases": {
        "2.28.0": [
            {
                "filename": "requests-2.28.0-py3-none-any.whl",
                "upload_time_iso_8601": "2022-06-09T09:00:00.000000Z",
            }
        ],
        "2.29.0": [
            {
                "filename": "requests-2.29.0-py3-none-any.whl",
                "upload_time_iso_8601": "2023-04-10T12:00:00.000000Z",
            }
        ],
        "2.31.0": [
            {
                "filename": "requests-2.31.0-py3-none-any.whl",
                "upload_time_iso_8601": "2023-05-22T14:00:00.000000Z",
            }
        ],
    },
}

SAMPLE_LATEST_RESPONSE: dict[str, Any] = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
    },
}

EMPTY_RELEASES_RESPONSE: dict[str, Any] = {
    "info": {"name": "empty-pkg", "version": "0.0.1"},
    "releases": {
        "0.0.1": [],
    },
}

NO_TIMESTAMP_RESPONSE: dict[str, Any] = {
    "info": {"name": "no-ts-pkg", "version": "1.0.0"},
    "releases": {
        "1.0.0": [
            {"filename": "no_ts-1.0.0.tar.gz", "size": 1024},
        ],
    },
}


# ---------------------------------------------------------------------------
# PyPIAdapter — properties
# ---------------------------------------------------------------------------


class TestPyPIAdapterProperties:
    def test_ecosystem(self) -> None:
        adapter = PyPIAdapter()
        assert adapter.ecosystem == "pypi"

    def test_registry_base_url(self) -> None:
        adapter = PyPIAdapter()
        assert adapter.registry_base_url == "https://pypi.org"


# ---------------------------------------------------------------------------
# PyPIAdapter.get_publish_time
# ---------------------------------------------------------------------------


class TestGetPublishTime:
    async def test_returns_datetime_for_known_version(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/2.31.0/json"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_VERSION_RESPONSE)
            publish_time, source = await PyPIAdapter().get_publish_time("requests", "2.31.0")

        assert publish_time is not None
        assert publish_time == datetime.fromisoformat("2023-05-22T14:00:00.000000+00:00")
        assert source == "registry_api"

    async def test_returns_none_for_404(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/nonexistent-pkg-xyz/1.0.0/json"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            publish_time, source = await PyPIAdapter().get_publish_time("nonexistent-pkg-xyz", "1.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_returns_none_when_no_urls(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/empty-pkg/0.0.1/json"
        response: dict[str, Any] = {
            "info": {"name": "empty-pkg", "version": "0.0.1"},
            "urls": [],
        }
        with aioresponses() as m:
            m.get(url, payload=response)
            publish_time, source = await PyPIAdapter().get_publish_time("empty-pkg", "0.0.1")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_returns_none_when_no_upload_time_key(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/no-ts-pkg/1.0.0/json"
        response: dict[str, Any] = {
            "info": {"name": "no-ts-pkg", "version": "1.0.0"},
            "urls": [{"filename": "no_ts-1.0.0.tar.gz", "size": 1024}],
        }
        with aioresponses() as m:
            m.get(url, payload=response)
            publish_time, source = await PyPIAdapter().get_publish_time("no-ts-pkg", "1.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_uses_first_url_for_timestamp(self) -> None:
        """Should use urls[0] (the wheel), not urls[1] (the sdist)."""
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/2.31.0/json"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_VERSION_RESPONSE)
            publish_time, source = await PyPIAdapter().get_publish_time("requests", "2.31.0")

        assert publish_time is not None
        # urls[0] is the wheel at 14:00:00, urls[1] is the sdist at 14:00:05
        assert publish_time.second == 0
        assert source == "registry_api"


# ---------------------------------------------------------------------------
# PyPIAdapter.get_all_versions
# ---------------------------------------------------------------------------


class TestGetAllVersions:
    async def test_returns_all_versions_sorted_desc(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/json"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_ALL_VERSIONS_RESPONSE)
            result = await PyPIAdapter().get_all_versions("requests")

        assert len(result) == 3
        assert result[0].version == "2.31.0"
        # Ensure publish_time is not None before comparison
        assert result[0].publish_time is not None
        assert result[1].publish_time is not None
        assert result[0].publish_time > result[1].publish_time
        assert result[1].version == "2.29.0"
        assert result[2].version == "2.28.0"

    async def test_returns_version_info_objects(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/json"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_ALL_VERSIONS_RESPONSE)
            result = await PyPIAdapter().get_all_versions("requests")

        for vi in result:
            assert isinstance(vi, VersionInfo)
            assert vi.ecosystem == "pypi"
            assert vi.package_name == "requests"

    async def test_returns_empty_on_404(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/nonexistent-pkg-xyz/json"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            result = await PyPIAdapter().get_all_versions("nonexistent-pkg-xyz")

        assert result == []

    async def test_skips_versions_with_no_files(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/empty-pkg/json"
        response: dict[str, Any] = {
            "info": {"name": "empty-pkg", "version": "1.0.0"},
            "releases": {
                "1.0.0": [],
                "2.0.0": [
                    {
                        "filename": "empty_pkg-2.0.0.tar.gz",
                        "upload_time_iso_8601": "2023-06-01T00:00:00Z",
                    }
                ],
            },
        }
        with aioresponses() as m:
            m.get(url, payload=response)
            result = await PyPIAdapter().get_all_versions("empty-pkg")

        assert len(result) == 1
        assert result[0].version == "2.0.0"

    async def test_includes_versions_without_upload_time(self) -> None:
        """Versions without upload_time are included with fallback to datetime.now()."""
        url = f"{PYPI_REGISTRY_URL}/pypi/no-ts-pkg/json"
        response: dict[str, Any] = {
            "info": {"name": "no-ts-pkg", "version": "1.0.0"},
            "releases": {
                "1.0.0": [{"filename": "no_ts-1.0.0.tar.gz", "size": 1024}],
                "2.0.0": [
                    {
                        "filename": "no_ts-2.0.0.tar.gz",
                        "upload_time_iso_8601": "2023-06-01T00:00:00Z",
                    }
                ],
            },
        }
        with aioresponses() as m:
            m.get(url, payload=response)
            result = await PyPIAdapter().get_all_versions("no-ts-pkg")

        # Both versions are included (missing upload_time uses fallback)
        assert len(result) == 2
        # Versions sorted by publish_time descending (1.0.0 has fallback=now, so comes first)
        assert result[0].version == "1.0.0"
        assert result[0].publish_time is not None
        assert result[1].version == "2.0.0"
        assert result[1].publish_time == datetime.fromisoformat("2023-06-01T00:00:00+00:00")

    async def test_empty_releases_dict(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/brand-new/json"
        response: dict[str, Any] = {
            "info": {"name": "brand-new", "version": "0.0.0"},
            "releases": {},
        }
        with aioresponses() as m:
            m.get(url, payload=response)
            result = await PyPIAdapter().get_all_versions("brand-new")

        assert result == []


# ---------------------------------------------------------------------------
# PyPIAdapter.get_latest_version
# ---------------------------------------------------------------------------


class TestGetLatestVersion:
    async def test_returns_latest(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/json"
        with aioresponses() as m:
            m.get(url, payload=SAMPLE_LATEST_RESPONSE)
            result = await PyPIAdapter().get_latest_version("requests")

        assert result == "2.31.0"

    async def test_returns_none_on_404(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/nonexistent-pkg-xyz/json"
        with aioresponses() as m:
            m.get(url, status=404)
            m.get(url, status=404)
            m.get(url, status=404)
            result = await PyPIAdapter().get_latest_version("nonexistent-pkg-xyz")

        assert result is None


# ---------------------------------------------------------------------------
# Timeout behavior
# ---------------------------------------------------------------------------


class TestTimeoutBehavior:
    async def test_timeout_returns_none_for_publish_time(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/slow-pkg/1.0.0/json"
        with aioresponses() as m:
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            publish_time, source = await PyPIAdapter().get_publish_time("slow-pkg", "1.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_timeout_returns_empty_for_all_versions(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/slow-pkg/json"
        with aioresponses() as m:
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            result = await PyPIAdapter().get_all_versions("slow-pkg")

        assert result == []

    async def test_timeout_returns_none_for_latest(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/slow-pkg/json"
        with aioresponses() as m:
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            result = await PyPIAdapter().get_latest_version("slow-pkg")

        assert result is None


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


class TestRetryLogic:
    async def test_retry_succeeds_after_transient_errors(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/flaky-pkg/1.0.0/json"
        success_response: dict[str, Any] = {
            "info": {"name": "flaky-pkg", "version": "1.0.0"},
            "urls": [
                {
                    "filename": "flaky_pkg-1.0.0.tar.gz",
                    "upload_time_iso_8601": "2023-06-01T00:00:00Z",
                }
            ],
        }
        with aioresponses() as m:
            m.get(url, status=500)
            m.get(url, status=500)
            m.get(url, payload=success_response)
            publish_time, source = await PyPIAdapter().get_publish_time("flaky-pkg", "1.0.0")

        assert publish_time is not None
        assert publish_time == datetime.fromisoformat("2023-06-01T00:00:00+00:00")
        assert source == "registry_api"

    async def test_retry_exhausted_returns_none(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/flaky-pkg/1.0.0/json"
        with aioresponses() as m:
            m.get(url, status=502)
            m.get(url, status=502)
            m.get(url, status=502)
            publish_time, source = await PyPIAdapter().get_publish_time("flaky-pkg", "1.0.0")

        assert publish_time is None
        assert source == "no_github_url"

    async def test_adapter_get_publish_time_with_retry(self) -> None:
        """Verify the adapter instance method also retries."""
        adapter = PyPIAdapter()
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/2.31.0/json"
        with aioresponses() as m:
            m.get(url, status=503)
            m.get(url, payload=SAMPLE_VERSION_RESPONSE)
            publish_time, source = await adapter.get_publish_time("requests", "2.31.0")

        assert publish_time is not None
        assert source == "registry_api"


# ---------------------------------------------------------------------------
# Session reuse
# ---------------------------------------------------------------------------


class TestSessionReuse:
    async def test_shared_session_across_calls(self) -> None:
        """Verify a single session can be passed to multiple adapter calls."""
        adapter = PyPIAdapter()
        url_version = f"{PYPI_REGISTRY_URL}/pypi/requests/2.31.0/json"
        url_all = f"{PYPI_REGISTRY_URL}/pypi/requests/json"
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            with aioresponses() as m:
                m.get(url_version, payload=SAMPLE_VERSION_RESPONSE)
                m.get(url_all, payload=SAMPLE_LATEST_RESPONSE)
                v1, _ = await adapter.get_publish_time("requests", "2.31.0", session=session)
                v2 = await adapter.get_latest_version("requests", session=session)

        assert v1 is not None
        assert v2 == "2.31.0"

    async def test_standalone_functions_share_session(self) -> None:
        url = f"{PYPI_REGISTRY_URL}/pypi/requests/2.31.0/json"
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            with aioresponses() as m:
                m.get(url, payload=SAMPLE_VERSION_RESPONSE)
                publish_time, _ = await PyPIAdapter().get_publish_time("requests", "2.31.0", session=session)

        assert publish_time is not None
