"""Koji XML-RPC client for RPM build completion-time lookup.

Used as a tiebreaker when Bodhi has no record. ``getBuild(nvr)`` returns a
struct with ``completion_time`` — the wall-clock when the Koji build task
completed (NOT when the RPM was published to a user-facing repo). Accurate
to within ~1-2 minutes of Bodhi's ``date_pushed`` (YUM-001 §3.1).

Design choices:
    * Uses raw ``aiohttp.ClientSession.post`` + manual XML-RPC marshalling
      rather than ``xmlrpc.client.ServerProxy`` so the caller can share a
      single ``aiohttp`` session across the cascade (connection pooling,
      uniform timeout/retry policy).
    * Parses the response with :func:`xmlrpc.client.loads` — the stdlib
      unmarshaller handles ``<fault>`` responses by raising
      :class:`xmlrpc.client.Fault`, so we get correct exception semantics
      without reimplementing the protocol.
    * **Never raises** at the public API surface. All network, parse, and
      protocol errors are logged at debug level and converted to
      ``(None, "koji")``. The cascade handles ``None`` by falling through
      to the next source.
"""

from __future__ import annotations

import logging
import xml.parsers.expat
import xmlrpc.client
from datetime import UTC, datetime
from typing import Any

import aiohttp

from pkg_defender.core.registry_domains import is_domain_allowed
from pkg_defender.exceptions import SecurityError

logger = logging.getLogger(__name__)

# Public URL of the Fedora Koji hub XML-RPC endpoint.
KOJI_BASE_URL: str = "https://koji.fedoraproject.org/kojihub"

# Request timeout (seconds). Kept separate from the shared ``fetch_json``
# default because Koji ``getBuild`` can be slow under load.
KOJI_TIMEOUT_SECONDS: int = 30

# Source string used by the cascade when this client produces a result.
# Public value — keep in sync with the cascade's source-enum.
SOURCE_KOJI: str = "koji"


def _build_xmlrpc_request(method_name: str, *params: Any) -> bytes:
    """Build a raw XML-RPC request body for a single method call.

    Args:
        method_name: The XML-RPC method name (e.g. ``"getBuild"``).
        *params: Positional parameters to serialize. Standard Python
            types (``str``, ``int``, ``float``, ``bool``, ``list``,
            ``dict``, ``None``) are supported by :mod:`xmlrpc.client`.

    Returns:
        UTF-8 encoded XML-RPC request body, ready for HTTP POST.
    """
    return xmlrpc.client.dumps(tuple(params), methodname=method_name).encode("utf-8")


def _parse_completion_time(response_bytes: bytes) -> datetime | None:
    """Parse a ``getBuild`` XML-RPC response and return ``completion_time``.

    Args:
        response_bytes: Raw XML-RPC response body from Koji.

    Returns:
        Parsed ``datetime`` (UTC) for the build completion time, or
        ``None`` if the build was not found / completion time missing.

    Raises:
        xmlrpc.client.Fault: If Koji returned a fault response (e.g. invalid
            NVR, server error). The caller catches this and returns
            ``(None, "koji")``.
    """
    parsed, _method_name = xmlrpc.client.loads(response_bytes)
    # ``xmlrpc.client.loads`` wraps the return value in a tuple. For
    # ``getBuild`` the wrapped value is either:
    #   * ``None`` — build not found
    #   * ``dict`` — build struct with ``completion_time`` (and other keys)
    if isinstance(parsed, tuple):
        result_value: Any = parsed[0] if parsed else None
    else:
        result_value = parsed
    if not isinstance(result_value, dict):
        return None
    completion_time = result_value.get("completion_time")
    if completion_time is None:
        return None
    # Koji returns ``completion_time`` as epoch seconds (int or float).
    return datetime.fromtimestamp(float(completion_time), tz=UTC)


class KojiClient:
    """Async Koji XML-RPC client for RPM build completion-time lookup.

    See module docstring for design rationale. Always returns
    ``(datetime | None, "koji")`` from :meth:`get_build_completion_time` —
    never raises at the public API surface.
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
        self._owns_session: bool = session is None

    async def get_build_completion_time(
        self,
        nvr: str,
    ) -> tuple[datetime | None, str]:
        """Return ``(completion_time, source)`` for *nvr*.

        Args:
            nvr: NVR string (e.g. ``"curl-8.21.0~rc1-1.fc45"``).

        Returns:
            ``(datetime | None, "koji")``. The datetime is UTC-aware
            and represents the Koji build task's completion time.
            Returns ``(None, "koji")`` on:
                * build not found (Koji returns ``None``)
                * missing ``completion_time`` in the build struct
                * XML-RPC fault (caught as :class:`xmlrpc.client.Fault`)
                * any network / parse error (logged at debug)
        """
        try:
            body = _build_xmlrpc_request("getBuild", nvr)
            response_bytes = await self._post(body)
            completion_time = _parse_completion_time(response_bytes)
            return (completion_time, SOURCE_KOJI)
        except xmlrpc.client.Fault as exc:
            logger.debug(
                "Koji XML-RPC fault for nvr=%s: faultCode=%d faultString=%s",
                nvr,
                exc.faultCode,
                exc.faultString,
            )
            return (None, SOURCE_KOJI)
        except aiohttp.ClientError as exc:
            logger.debug("Koji client error for nvr=%s: %s", nvr, exc)
            return (None, SOURCE_KOJI)
        except TimeoutError as exc:
            logger.debug("Koji timeout for nvr=%s: %s", nvr, exc)
            return (None, SOURCE_KOJI)
        except (OSError, ValueError) as exc:
            # OSError: socket / DNS / connection issues
            # ValueError: malformed response body
            logger.debug("Koji transport error for nvr=%s: %s", nvr, exc)
            return (None, SOURCE_KOJI)
        except xml.parsers.expat.ExpatError as exc:
            # Malformed XML — XML-RPC's expat parser raises this on
            # non-XML bodies. Caught last to keep the specific handler
            # above for normal flow.
            logger.debug("Koji malformed XML for nvr=%s: %s", nvr, exc)
            return (None, SOURCE_KOJI)

    async def _post(self, body: bytes) -> bytes:
        """POST the XML-RPC body to Koji and return the raw response.

        Args:
            body: UTF-8 encoded XML-RPC request body.

        Returns:
            Raw response bytes from Koji.

        Raises:
            SecurityError: When KOJI_BASE_URL is not in the yum allowlist.
            aiohttp.ClientError: On network errors.
            asyncio.TimeoutError: On request timeout.
        """
        # SSRF defense-in-depth: verify Koji URL is in the yum allowlist
        if not is_domain_allowed("yum", KOJI_BASE_URL):
            raise SecurityError(f"SSRF domain check failed: Koji URL {KOJI_BASE_URL!r} is not in the yum allowlist")

        timeout_cfg = aiohttp.ClientTimeout(total=KOJI_TIMEOUT_SECONDS)
        headers = {"Content-Type": "text/xml"}
        if self._session is not None:
            async with self._session.post(KOJI_BASE_URL, data=body, headers=headers, timeout=timeout_cfg) as resp:
                resp.raise_for_status()
                return await resp.read()
        # No injected session — create a transient one. The caller is not
        # expected to ``close()`` the client in this case, so we do not
        # hold a reference.
        async with (
            aiohttp.ClientSession() as tmp_session,
            tmp_session.post(KOJI_BASE_URL, data=body, headers=headers, timeout=timeout_cfg) as resp,
        ):
            resp.raise_for_status()
            return await resp.read()

    async def close(self) -> None:
        """Close the underlying ``aiohttp`` session if owned by this client.

        Callers that pass their own session are responsible for closing
        it themselves. This method is a no-op when no session is owned
        (i.e. the caller injected a session).
        """
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None
        self._owns_session = False
