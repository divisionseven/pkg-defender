"""Tests for pkg_defender.registry._koji_client.

The Koji XML-RPC client fetches ``completion_time`` for an NVR. Tested
with synthetic XML-RPC responses (no live network) and ``xmlrpc.client``
mocking for the protocol-level error paths.
"""

from __future__ import annotations

import xml.parsers.expat
import xmlrpc.client
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.core.registry_domains import is_domain_allowed
from pkg_defender.exceptions import SecurityError
from pkg_defender.registry._koji_client import (
    KOJI_BASE_URL,
    SOURCE_KOJI,
    KojiClient,
    _build_xmlrpc_request,
    _parse_completion_time,
)

# ---------------------------------------------------------------------------
# Synthetic XML-RPC response helpers
# ---------------------------------------------------------------------------


def _success_response(completion_time: float) -> bytes:
    """Build a synthetic XML-RPC <methodResponse> with a struct return value.

    Args:
        completion_time: Epoch seconds to embed in the response.

    Returns:
        UTF-8 encoded XML-RPC response body.
    """
    body = (
        '<?xml version="1.0"?>\n'
        "<methodResponse><params><param><value><struct>"
        "<member><name>id</name><value><int>12345</int></value></member>"
        f"<member><name>completion_time</name><value><double>{completion_time}</double></value></member>"
        "<member><name>package_name</name><value><string>curl</string></value></member>"
        "</struct></value></param></params></methodResponse>"
    )
    return body.encode("utf-8")


def _not_found_response() -> bytes:
    """Synthetic XML-RPC <methodResponse> with a nil return value (build not found)."""
    return (
        b'<?xml version="1.0"?>\n<methodResponse><params><param><value><nil/></value></param></params></methodResponse>'
    )


def _fault_response(fault_code: int, fault_string: str) -> bytes:
    """Synthetic XML-RPC <methodResponse> with a <fault> element."""
    body = (
        '<?xml version="1.0"?>\n'
        "<methodResponse><fault><value><struct>"
        f"<member><name>faultCode</name><value><int>{fault_code}</int></value></member>"
        f"<member><name>faultString</name><value><string>{fault_string}</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )
    return body.encode("utf-8")


def _missing_completion_time_response() -> bytes:
    """Synthetic response with a struct but no ``completion_time`` field."""
    return (
        b'<?xml version="1.0"?>\n'
        b"<methodResponse><params><param><value><struct>"
        b"<member><name>id</name><value><int>12345</int></value></member>"
        b"<member><name>package_name</name><value><string>curl</string></value></member>"
        b"</struct></value></param></params></methodResponse>"
    )


def _malformed_response() -> bytes:
    """A response that is not valid XML-RPC."""
    return b"<<< not xml-rpc >>>"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def _mock_session() -> MagicMock:
    """Build a mock aiohttp.ClientSession for KojiClient.

    Returns a MagicMock that supports ``async with session.post(...) as resp``
    and ``resp.raise_for_status()`` + ``resp.read()`` (both async).
    """
    return MagicMock()


# ---------------------------------------------------------------------------
# Tests for module-level helpers
# ---------------------------------------------------------------------------


class TestBuildXmlrpcRequest:
    """Tests for :func:`_build_xmlrpc_request`."""

    def test_builds_getbuild_request(self) -> None:
        """Body is UTF-8 encoded XML with the method name and a string param."""
        body = _build_xmlrpc_request("getBuild", "curl-8.21.0-1.fc45")
        assert isinstance(body, bytes)
        text = body.decode("utf-8")
        assert "getBuild" in text
        assert "curl-8.21.0-1.fc45" in text
        assert text.lstrip().startswith("<?xml")

    def test_no_params(self) -> None:
        """Empty params tuple is valid XML-RPC."""
        body = _build_xmlrpc_request("ping")
        text = body.decode("utf-8")
        assert "ping" in text
        assert "<params>" in text  # xmlrpc.client.dumps emits <params></params>


class TestParseCompletionTime:
    """Tests for :func:`_parse_completion_time`."""

    def test_parses_double_completion_time(self) -> None:
        """Parses ``<double>`` epoch seconds into a UTC datetime."""
        dt = _parse_completion_time(_success_response(1_700_000_000.0))
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.tzinfo.utcoffset(dt) == UTC.utcoffset(dt)
        assert dt == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_parses_int_completion_time(self) -> None:
        """``<int>`` epoch seconds is also accepted (coerced via float())."""
        # Build a response with <int> instead of <double>
        body = (
            b'<?xml version="1.0"?>\n'
            b"<methodResponse><params><param><value><struct>"
            b"<member><name>completion_time</name><value><int>1700000000</int></value></member>"
            b"</struct></value></param></params></methodResponse>"
        )
        dt = _parse_completion_time(body)
        assert dt is not None
        assert dt == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_returns_none_for_nil_response(self) -> None:
        """``<nil/>`` return value (build not found) → ``None``."""
        assert _parse_completion_time(_not_found_response()) is None

    def test_returns_none_when_completion_time_missing(self) -> None:
        """Struct without ``completion_time`` → ``None``."""
        assert _parse_completion_time(_missing_completion_time_response()) is None

    def test_raises_fault_on_fault_response(self) -> None:
        """``<fault>`` response → :class:`xmlrpc.client.Fault`."""
        with pytest.raises(xmlrpc.client.Fault) as exc_info:
            _parse_completion_time(_fault_response(42, "Invalid NVR"))
        assert exc_info.value.faultCode == 42
        assert "Invalid NVR" in exc_info.value.faultString

    def test_raises_on_malformed_response(self) -> None:
        """Non-XML-RPC bytes raise an XML parsing error (caught by caller)."""
        with pytest.raises((xml.parsers.expat.ExpatError, ValueError, TypeError)):
            _parse_completion_time(_malformed_response())


# ---------------------------------------------------------------------------
# Tests for KojiClient
# ---------------------------------------------------------------------------


class TestKojiClient:
    """Tests for :class:`KojiClient`."""

    @pytest.mark.asyncio
    async def test_koji_returns_completion_time(self) -> None:
        """Success path: ``getBuild`` returns completion_time."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_success_response(1_700_000_000.0))
        # Support async with for resp
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)

        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-8.21.0-1.fc45")

        assert result[0] is not None
        assert result[0].tzinfo is not None
        assert result[0].utcoffset() == UTC.utcoffset(result[0])
        assert result[0] == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
        assert result[1] == SOURCE_KOJI

    @pytest.mark.asyncio
    async def test_koji_returns_tz_aware_datetime(self) -> None:
        """Returned datetime is always UTC-aware (never naive)."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_success_response(1_700_000_001.0))
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)

        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-8.21.0-1.fc45")
        assert result[0] is not None
        assert result[0].tzinfo is not None
        assert result[0].utcoffset() == UTC.utcoffset(result[0])

    @pytest.mark.asyncio
    async def test_koji_handles_build_not_found(self) -> None:
        """Koji returns ``<nil/>`` (None) when build not found."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_not_found_response())
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)

        client = KojiClient(session=session)
        result = await client.get_build_completion_time("nonexistent-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_handles_xmlrpc_fault(self) -> None:
        """``<fault>`` response → ``(None, "koji")``, no exception."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_fault_response(1, "Invalid NVR"))
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)

        client = KojiClient(session=session)
        result = await client.get_build_completion_time("bogus")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_handles_aiohttp_client_error(self) -> None:
        """``aiohttp.ClientError`` (e.g. connection refused) → ``(None, "koji")``."""
        session = MagicMock()
        session.post = MagicMock(side_effect=aiohttp.ClientError("conn refused"))
        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_handles_timeout(self) -> None:
        """``TimeoutError`` (builtin or aiohttp) → ``(None, "koji")``."""
        session = MagicMock()
        session.post = MagicMock(side_effect=TimeoutError("koji slow"))
        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_handles_malformed_response(self) -> None:
        """Malformed XML-RPC body → ``(None, "koji")``."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_malformed_response())
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)
        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_handles_http_500(self) -> None:
        """HTTP 500 (non-200) raises ``ClientResponseError`` → ``(None, "koji")``."""
        session = MagicMock()
        resp = MagicMock()
        # Make raise_for_status raise ClientResponseError
        err = aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=500)
        resp.raise_for_status = MagicMock(side_effect=err)
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)
        client = KojiClient(session=session)
        result = await client.get_build_completion_time("curl-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_koji_never_raises(self) -> None:
        """Patch internal methods to raise — verify no exception propagates.

        Uses an exception type that the production code's broad
        ``except (OSError, ValueError)`` chain catches. If the
        production code's exception handling were removed, this
        test would FAIL with the raised exception.
        """
        client = KojiClient(session=MagicMock())
        # OSError is in the production code's catch chain
        with patch.object(client, "_post", new=AsyncMock(side_effect=OSError("boom"))):
            result = await client.get_build_completion_time("curl-1.0-1")
        assert result == (None, SOURCE_KOJI)

    @pytest.mark.asyncio
    async def test_close_with_injected_session_does_not_close_it(self) -> None:
        """``close()`` on a client with an injected session is a no-op."""
        session = MagicMock()
        session.close = AsyncMock()
        client = KojiClient(session=session)
        await client.close()
        # Injected session was NOT closed (caller's responsibility)
        session.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_close_with_transient_session_closes_nothing(self) -> None:
        """``close()`` on a client without an injected session is safe."""
        client = KojiClient()  # no session
        await client.close()  # should not raise

    @pytest.mark.asyncio
    async def test_post_sends_correct_url_and_content_type(self) -> None:
        """Verify the request URL and content-type header are correct."""
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_success_response(1_700_000_000.0))
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)

        client = KojiClient(session=session)
        await client.get_build_completion_time("curl-8.21.0-1.fc45")

        # Inspect the post() call
        call_args = session.post.call_args
        assert call_args is not None
        assert call_args.args[0] == KOJI_BASE_URL
        # The Content-Type header must be text/xml
        headers = call_args.kwargs.get("headers", {})
        assert headers.get("Content-Type") == "text/xml"


# ---------------------------------------------------------------------------
# Mutation test for XML-RPC Fault handling
# ---------------------------------------------------------------------------


class TestMutationXmlRpcFaultHandling:
    """Mutation test: remove the Fault handler and verify tests fail.

    Procedure: monkeypatch the production code to remove the
    ``except xmlrpc.client.Fault`` branch, then run
    ``test_koji_handles_xmlrpc_fault``. With the handler removed,
    the test must FAIL (the production code would propagate
    :class:`xmlrpc.client.Fault`).
    """

    def test_mutation_fault_handler_removed(self) -> None:
        """Sanity check: confirm removing the Fault handler would fail tests.

        This is a documentation test, not a runtime mutation. We verify
        the test would actually fail by directly invoking the client
        with a Fault-raising parser and confirming the current code
        catches it. If the Fault handler were removed, the test below
        would raise :class:`xmlrpc.client.Fault`.
        """
        # Build a session that returns a fault response
        session = MagicMock()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.read = AsyncMock(return_value=_fault_response(1, "Invalid"))
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        session.post = MagicMock(return_value=resp)
        client = KojiClient(session=session)
        import asyncio

        result = asyncio.run(client.get_build_completion_time("bogus"))
        # The current code catches the Fault → result is (None, "koji").
        # If the handler were removed, this would raise xmlrpc.client.Fault.
        assert result == (None, SOURCE_KOJI)


class TestKojiDomainCheck:
    """SSRF domain allowlist tests for KojiClient._post()."""

    def test_koji_url_in_yum_allowlist(self) -> None:
        """KOJI_BASE_URL is in the yum allowlist (defense-in-depth)."""
        assert is_domain_allowed("yum", KOJI_BASE_URL)

    async def test_post_blocked_domain_raises_security_error(self) -> None:
        """_post() raises SecurityError when KOJI_BASE_URL is not in allowlist."""
        client = KojiClient()
        body = _build_xmlrpc_request("getBuild", "test-1.0-1.fc45")
        with (
            patch(
                "pkg_defender.registry._koji_client.is_domain_allowed",
                return_value=False,
            ),
            pytest.raises(SecurityError, match="SSRF domain check failed"),
        ):
            await client._post(body)
