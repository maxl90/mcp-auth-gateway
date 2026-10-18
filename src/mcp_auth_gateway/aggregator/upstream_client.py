"""The gateway's MCP client side: JSON-RPC over Streamable HTTP to one upstream.

In aggregation mode the gateway is a server to the caller and a client to each
upstream: the ``initialize`` handshake, request/response RPCs on an established
session, and teardown. Requests are built from scratch, so the caller's token is
never on them; each upstream authenticates to its resource with its own identity.
The one optional addition to a ``tools/call`` is attribution metadata (the
correlation id and the human's ``oid``), never a token or an argument.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import Any

import httpx

from .. import __version__, jsonrpc
from ..config import settings
from ..http_util import ResponseTooLarge, read_capped
from ..upstreams import Upstream
from .registry import UpstreamSession

# The MCP protocol version the gateway speaks to upstreams.
PROTOCOL_VERSION = "2025-06-18"

# Control RPCs (initialize / tools/list) get a bounded read; tool calls get a
# generous one — bounded, because the aggregator buffers tool responses (they
# are catalogs/results, not open-ended streams; live streams ride GET, which
# the aggregator doesn't offer in v1).
_CONTROL_TIMEOUT = httpx.Timeout(10.0, read=30.0)
_CALL_TIMEOUT = httpx.Timeout(10.0, read=300.0)

# The handshake is request 0 of an upstream session; the session then numbers its
# own requests from 1 (``UpstreamSession.next_request_id``), never reusing one.
_INITIALIZE_ID = 0


class UpstreamError(Exception):
    """An upstream failed at the transport/protocol level (not a JSON-RPC
    ``error`` result — those are relayed to the caller, not raised)."""

    def __init__(self, upstream: str, detail: str) -> None:
        self.upstream = upstream
        self.detail = detail
        super().__init__(f"upstream '{upstream}': {detail}")


class UpstreamSessionExpired(UpstreamError):
    """The upstream no longer recognizes our session id (HTTP 404). Distinguished from
    a general failure so the aggregator can re-``initialize`` that upstream and retry
    rather than fail the whole client session."""


@dataclass(frozen=True)
class UpstreamRequest:
    """Where a request goes: the pooled HTTP client, the upstream, and the gateway's
    session with it (``None`` until ``initialize`` has issued one)."""

    client: httpx.AsyncClient
    upstream: Upstream
    session: UpstreamSession | None = None

    @property
    def session_id(self) -> str | None:
        return self.session.session_id if self.session else None


def _select_response(candidates: list[object], upstream: str, request_id: int) -> dict:
    """The JSON-RPC response to ``request_id`` among parsed messages.

    Interleaved notifications are dropped. A response carrying another id answers a
    different request and is a failure here, never handed to this caller; the one
    exception is an ``error`` with a null id, which JSON-RPC uses when the server
    could not read the request's id.
    """
    responses = [
        msg
        for msg in candidates
        if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg)
    ]
    for msg in responses:
        if msg["id"] == request_id or (msg["id"] is None and "error" in msg):
            return msg
    if responses:
        raise UpstreamError(upstream, "the response in the body answers a different request")
    raise UpstreamError(upstream, "no JSON-RPC response message in body")


def _extract_response(raw: bytes, content_type: str | None, upstream: str, request_id: int) -> dict:
    """The JSON-RPC response to ``request_id`` in a JSON or SSE body."""
    ct = (content_type or "").lower()
    if "application/json" not in ct and "text/event-stream" not in ct:
        raise UpstreamError(upstream, f"unexpected content-type: {content_type!r}")
    candidates = jsonrpc.parse_messages(raw, content_type)
    if not candidates:
        raise UpstreamError(upstream, "unparseable response body, or no message in it")
    return _select_response(candidates, upstream, request_id)


def _headers(session_id: str | None, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": PROTOCOL_VERSION,
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    if extra:
        headers.update(extra)
    return headers


def attribution_headers(correlation_id: str, claims: dict | None) -> dict[str, str]:
    """The audit metadata a ``tools/call`` may carry upstream: the record's correlation
    id and the human's ``oid``; never a token, never an argument. Empty unless
    ``forward_attribution_headers`` is on; an app-only token sends the id alone."""
    if not settings.forward_attribution_headers:
        return {}
    headers = {"x-mcp-gateway-correlation-id": correlation_id}
    oid = (claims or {}).get("oid")
    if isinstance(oid, str) and oid and (claims or {}).get("idtyp") != "app":
        headers["x-mcp-gateway-on-behalf-of"] = oid
    return headers


async def _post(
    req: UpstreamRequest,
    payload: dict,
    timeout: httpx.Timeout,
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    try:
        response = await req.client.send(
            req.client.build_request(
                "POST",
                req.upstream.url,
                content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=_headers(req.session_id, extra_headers),
                timeout=timeout,
            ),
            stream=True,
        )
    except httpx.HTTPError as exc:
        raise UpstreamError(req.upstream.name, f"transport failure: {exc}") from exc

    try:
        body = await read_capped(response, settings.max_upstream_response_bytes)
    except ResponseTooLarge as exc:
        await response.aclose()
        raise UpstreamError(req.upstream.name, f"{exc}; aborted") from exc
    except httpx.HTTPError as exc:
        await response.aclose()
        raise UpstreamError(req.upstream.name, f"transport failure while reading: {exc}") from exc
    response._content = body  # noqa: SLF001 — set the buffered body on the streamed response
    await response.aclose()
    return response


async def rpc(
    req: UpstreamRequest,
    method: str,
    params: dict | None = None,
    *,
    timeout: httpx.Timeout = _CONTROL_TIMEOUT,
    extra_headers: dict[str, str] | None = None,
) -> dict:
    """One request/response RPC on an established upstream session. Returns the
    JSON-RPC response message (which may itself be an ``error`` — relayed, not
    raised)."""
    if req.session is None:
        raise UpstreamError(req.upstream.name, f"{method} before initialize")
    request_id = req.session.next_request_id()
    payload: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    resp = await _post(req, payload, timeout, extra_headers)
    if resp.status_code == 404 and req.session_id is not None:
        # The upstream dropped our session (expiry, upstream restart). Signal a
        # reconnect rather than a hard failure.
        raise UpstreamSessionExpired(req.upstream.name, f"session expired on {method}")
    if resp.status_code >= 400:
        raise UpstreamError(req.upstream.name, f"HTTP {resp.status_code} on {method}")
    return _extract_response(
        resp.content, resp.headers.get("content-type"), req.upstream.name, request_id
    )


async def call_tool(
    req: UpstreamRequest,
    request_id: Any,
    tool: str,
    arguments: Any,
    attribution: dict[str, str] | None = None,
) -> dict:
    """Invoke ``tool`` (the upstream's *original*, un-namespaced name) and return
    the JSON-RPC response with the caller's original request id restored.
    ``attribution`` is :func:`attribution_headers`' output (empty when off)."""
    params: dict = {"name": tool}
    if arguments is not None:
        params["arguments"] = arguments
    response = await rpc(
        req, "tools/call", params, timeout=_CALL_TIMEOUT, extra_headers=attribution
    )
    response["id"] = request_id
    return response


async def initialize_session(client: httpx.AsyncClient, upstream: Upstream) -> UpstreamSession:
    """Run the MCP handshake against one upstream: ``initialize``, capture its
    ``Mcp-Session-Id`` (if it issues one), then ``notifications/initialized``."""
    payload = {
        "jsonrpc": "2.0",
        "id": _INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-auth-gateway", "version": __version__},
        },
    }
    resp = await _post(UpstreamRequest(client, upstream), payload, _CONTROL_TIMEOUT)
    if resp.status_code >= 400:
        raise UpstreamError(upstream.name, f"HTTP {resp.status_code} on initialize")
    message = _extract_response(
        resp.content, resp.headers.get("content-type"), upstream.name, _INITIALIZE_ID
    )
    if "error" in message:
        raise UpstreamError(upstream.name, f"initialize error: {message['error']}")

    session = UpstreamSession(
        upstream=upstream.name,
        url=upstream.url,
        session_id=resp.headers.get("mcp-session-id"),
    )

    # Complete the handshake. A 4xx here is fatal (the session never became
    # usable); transport errors already raise in _post.
    notified = await _post(
        UpstreamRequest(client, upstream, session),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _CONTROL_TIMEOUT,
    )
    if notified.status_code >= 400:
        raise UpstreamError(
            upstream.name, f"HTTP {notified.status_code} on notifications/initialized"
        )
    return session


async def delete_session(
    client: httpx.AsyncClient, upstream: Upstream, session: UpstreamSession
) -> None:
    """Best-effort session teardown — an upstream that has already dropped the
    session (or never issued one) is fine; cleanup must not fail the DELETE."""
    if session.session_id is None:
        return
    with contextlib.suppress(httpx.HTTPError):
        await client.delete(
            upstream.url,
            headers=_headers(session.session_id),
            timeout=_CONTROL_TIMEOUT,
        )
