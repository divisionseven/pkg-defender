"""Tests for UnifiedRegistryAdapter base class and bridge methods."""

from __future__ import annotations

from datetime import datetime

import aiohttp
import pytest
from pytest_mock import MockerFixture

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import ParsedCommand
from pkg_defender.registry.base import EcosystemCapability


class TestUnifiedRegistryAdapterBase:
    """Tests for UnifiedRegistryAdapter base class methods."""

    def test_import_from_registry(self) -> None:
        """UnifiedRegistryAdapter can be imported from registry package."""
        from pkg_defender.registry import UnifiedRegistryAdapter

        assert UnifiedRegistryAdapter is not None

    def test_split_pkgd_flags(self) -> None:
        """split_pkgd_flags separates pkgd flags from manager args."""
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        # Create a concrete subclass for testing
        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "test"
            manager_name = "test"

            registry_base_url = "https://test.example.com"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return None, ""

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                return None

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="test",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        clean, flags = adapter.split_pkgd_flags(["install", "requests", "--dry-run", "--cooldown", "48", "--explain"])
        assert clean == ["install", "requests"]
        assert flags["dry_run"] is True
        assert flags["cooldown"] == "48"
        assert flags["explain"] is True

    def test_classify_intent_safe(self) -> None:
        """Unknown subcommand returns SAFE_PASSTHROUGH."""
        from pkg_defender.models.command import CommandIntent
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "test"
            manager_name = "test"

            registry_base_url = "https://test.example.com"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return None, ""

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                return None

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="test",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        assert adapter.classify_intent("unknown") == CommandIntent.SAFE_PASSTHROUGH

    def test_tokenize_args(self) -> None:
        """tokenize_args groups value-consuming flags with their values."""
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "test"
            manager_name = "test"
            VALUE_FLAGS = frozenset({"-i", "--index-url"})

            registry_base_url = "https://test.example.com"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return None, ""

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                return None

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="test",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        result = adapter.tokenize_args(["install", "-i", "https://pypi.org/simple", "requests"])
        assert result == ["install", ("-i", "https://pypi.org/simple"), "requests"]


class TestUnifiedRegistryAdapterBridge:
    """Tests for error-wrapping bridge methods."""

    @pytest.mark.asyncio
    async def test_resolve_latest_version_wraps_timeout(self) -> None:
        """Python TimeoutError is converted to PipelineTimeoutError."""
        from pkg_defender.audit.errors import TimeoutError as PipelineTimeoutError
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "pypi"
            manager_name = "pip"

            registry_base_url = "https://pypi.org"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return None, ""

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                raise TimeoutError("timed out")

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="pip",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        with pytest.raises(PipelineTimeoutError) as exc_info:
            await adapter.resolve_latest_version("requests")
        assert "pypi" in exc_info.value.title

    @pytest.mark.asyncio
    async def test_resolve_latest_version_wraps_client_error(self) -> None:
        """aiohttp.ClientError is converted to NetworkError."""
        import aiohttp

        from pkg_defender.audit.errors import NetworkError
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "pypi"
            manager_name = "pip"

            registry_base_url = "https://pypi.org"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return None, ""

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                raise aiohttp.ClientError("connection refused")

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="pip",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        with pytest.raises(NetworkError) as exc_info:
            await adapter.resolve_latest_version("requests")
        assert "pypi" in exc_info.value.title
        assert "requests" in exc_info.value.user_message

    @pytest.mark.asyncio
    async def test_get_release_date_wraps_timeout(self) -> None:
        """Python TimeoutError in get_release_date is converted to PipelineTimeoutError."""
        from pkg_defender.audit.errors import TimeoutError as PipelineTimeoutError
        from pkg_defender.registry.base import UnifiedRegistryAdapter

        class TestAdapter(UnifiedRegistryAdapter):
            ecosystem = "pypi"
            manager_name = "pip"

            registry_base_url = "https://pypi.org"

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return []

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                raise TimeoutError("timed out")

            async def get_all_versions(
                self, package: str, session: aiohttp.ClientSession | None = None
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(self, package: str, session: aiohttp.ClientSession | None = None) -> None:
                return None

            async def get_installed_version(self, package: str) -> None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                from pkg_defender.models.command import CommandIntent, ParsedCommand

                return ParsedCommand(
                    manager="pip",
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        adapter = TestAdapter()
        with pytest.raises(PipelineTimeoutError) as exc_info:
            await adapter.get_release_date("requests", "2.31.0")
        assert "pypi" in exc_info.value.title


class TestHTTPMixinFetchJson:
    """Tests for HTTPMixin._fetch_json bridge."""

    async def test_returns_dict_on_fetch(self, mocker: MockerFixture) -> None:
        """Successful FetchResult is unwrapped to dict."""
        from pkg_defender._http import FetchResult
        from pkg_defender.registry.base import HTTPMixin

        mock_fetch = mocker.patch(
            "pkg_defender._http.fetch_json",
            return_value=FetchResult(
                data={"key": "val"},
                status=200,
                success=True,
            ),
        )

        result = await HTTPMixin._fetch_json("https://example.com/data")

        assert result == {"key": "val"}
        mock_fetch.assert_awaited_once()

    async def test_failed_fetch_raises_runtime_error(self, mocker: MockerFixture) -> None:
        """FetchResult with success=False raises RuntimeError."""
        from pkg_defender._http import FetchResult
        from pkg_defender.registry.base import HTTPMixin

        mock_fetch = mocker.patch(
            "pkg_defender._http.fetch_json",
            return_value=FetchResult(
                data=None,
                error="connection refused",
                success=False,
            ),
        )

        with pytest.raises(RuntimeError, match="Failed to fetch.*connection refused"):
            await HTTPMixin._fetch_json("https://example.com/data")

        mock_fetch.assert_awaited_once()

    async def test_default_timeout_passed_through(self, mocker: MockerFixture) -> None:
        """Default timeout=15 and max_retries=3 are passed to the utility."""
        from pkg_defender._http import FetchResult
        from pkg_defender.registry.base import HTTPMixin

        mock_fetch = mocker.patch(
            "pkg_defender._http.fetch_json",
            return_value=FetchResult(
                data={"ok": True},
                status=200,
                success=True,
            ),
        )

        await HTTPMixin._fetch_json("https://example.com/data")

        mock_fetch.assert_awaited_once_with(
            "https://example.com/data",
            timeout=15,
            max_retries=3,
            session=None,
            on_404="raise",
            manager=None,
        )

    async def test_on_404_always_raise(self, mocker: MockerFixture) -> None:
        """on_404='raise' is always passed regardless of caller kwargs."""
        from pkg_defender._http import FetchResult
        from pkg_defender.registry.base import HTTPMixin

        mock_fetch = mocker.patch(
            "pkg_defender._http.fetch_json",
            return_value=FetchResult(
                data={"ok": True},
                status=200,
                success=True,
            ),
        )

        await HTTPMixin._fetch_json("https://example.com/data", timeout=30, max_retries=5)

        # Verify on_404 is always "raise" even when other params change
        _call_args = mock_fetch.await_args
        assert _call_args is not None
        assert _call_args.kwargs["on_404"] == "raise"
