"""The gateway's MCP *client* side: JSON-RPC over Streamable HTTP to one upstream.

In aggregation mode the gateway is a server to the caller and a client to each
upstream. This module speaks the client half: the ``initialize`` handshake,
request/response RPCs against an established upstream session, and teardown.

Trust boundary note: nothing here ever carries the caller's token — requests to
upstreams are built from scratch, not forwarded, so there is no header to
strip. Each upstream authenticates to its resource with its own service
identity (ADR 002).

Responses may arrive as ``application/json`` or as an SSE stream (mcp-proxy
answers POSTs with SSE); both are parsed to the single JSON-RPC response
message. Control RPCs are read-bounded — a hung upstream must not hang the
client's ``initialize`` or ``tools/list`` forever.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import httpx

from ..config import settings
from ..upstreams import Upstream
from .registry import UpstreamSession

# The session-semantics spec generation the gateway targets (ADR 005; the
# registry abstraction isolates us from the 2026-07-28 RC's proposed changes).
PROTOCOL_VERSION = "2025-06-18"

# Control RPCs (initialize / tools/list) get a bounded read; tool calls get a
# generous one — bounded, because the aggregator buffers tool responses (they
# are catalogs/results, not open-ended streams; live streams ride GET, which
# the aggregator doesn't offer in v1).
_CONTROL_TIMEOUT = httpx.Timeout(10.0, read=30.0)
_CALL_TIMEOUT = httpx.Timeout(10.0, read=300.0)


class UpstreamError(Exception):
    """An upstream failed at the transport/protocol level (not a JSON-RPC
    ``error`` result — those are relayed to the caller, not raised)."""

    def __init__(self, upstream: str, detail: str) -> None:
        self.upstream = upstream
        self.detail = detail
        super().__init__(f"upstream '{upstream}': {detail}")


class UpstreamSessionExpired(UpstreamError):
    """The upstream no longer recognizes our session id (HTTP 404 on a
    Streamable HTTP request). Distinguished from a general failure so the
    aggregator can transparently re-``initialize`` that upstream and retry,
    rather than failing the whole client session (Phase 3, Task 14)."""


def _parse_sse(text: str) -> list[Any]:
    """Extract the JSON payload of every ``data:`` frame in an SSE body."""
    messages: list[Any] = []
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for frame in normalized.split("\n\n"):
        data_parts = [
            ln[len("data:"):].lstrip(" ")
            for ln in frame.split("\n")
            if ln.startswith("data:")
        ]
        if not data_parts:
            continue
        try:
            messages.append(json.loads("\n".join(data_parts)))
        except ValueError:
            continue
    return messages


def _extract_response(raw: bytes, content_type: str | None, upstream: str) -> dict:
    """Pull the single JSON-RPC *response* out of a JSON or SSE body.

    An SSE stream may interleave server notifications with the response; the
    response is the message that carries an ``id``. v1 drops the interleaved
    notifications (tools-only scope, no client to relay them to per-upstream).
    """
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            doc = json.loads(raw)
            candidates = doc if isinstance(doc, list) else [doc]
        elif "text/event-stream" in ct:
            candidates = _parse_sse(raw.decode("utf-8"))
        else:
            raise UpstreamError(upstream, f"unexpected content-type: {content_type!r}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise UpstreamError(upstream, f"unparseable response body: {exc}") from exc

    for msg in candidates:
        if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
            return msg
    raise UpstreamError(upstream, "no JSON-RPC response message in body")


def _headers(session_id: str | None) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": PROTOCOL_VERSION,
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return headers


async def _read_capped(response: httpx.Response, upstream: str) -> bytes:
    """Read a streamed response body, aborting if it exceeds the configured cap.

    Bounds memory against a malicious/compromised upstream that streams an
    unbounded body within the read timeout (a per-read, not total, bound). The
    connection is closed the moment the cap is passed."""
    cap = settings.max_upstream_response_bytes
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if cap and total > cap:
            await response.aclose()
            raise UpstreamError(
                upstream, f"response exceeded {cap}-byte cap; aborted"
            )
        chunks.append(chunk)
    return b"".join(chunks)


async def _post(
    client: httpx.AsyncClient,
    upstream: Upstream,
    payload: dict,
    session_id: str | None,
    timeout: httpx.Timeout,
) -> httpx.Response:
    try:
        response = await client.send(
            client.build_request(
                "POST",
                upstream.url,
                content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=_headers(session_id),
            ),
            stream=True,
        )
    except httpx.HTTPError as exc:
        raise UpstreamError(upstream.name, f"transport failure: {exc}") from exc

    # Read the body under the cap, then hand back a response whose .content is
    # the (bounded) bytes so callers keep using .content / .headers unchanged.
    try:
        body = await _read_capped(response, upstream.name)
    except httpx.HTTPError as exc:
        await response.aclose()
        raise UpstreamError(upstream.name, f"transport failure while reading: {exc}") from exc
    response._content = body  # noqa: SLF001 — set the buffered body on the streamed response
    await response.aclose()
    return response


async def rpc(
    client: httpx.AsyncClient,
    upstream: Upstream,
    session: UpstreamSession,
    method: str,
    params: dict | None = None,
    *,
    timeout: httpx.Timeout = _CONTROL_TIMEOUT,
) -> dict:
    """One request/response RPC on an established upstream session. Returns the
    JSON-RPC response message (which may itself be an ``error`` — relayed, not
    raised)."""
    payload: dict = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    resp = await _post(client, upstream, payload, session.session_id, timeout)
    if resp.status_code == 404 and session.session_id is not None:
        # The upstream dropped our session (expiry, upstream restart). Signal a
        # reconnect rather than a hard failure.
        raise UpstreamSessionExpired(upstream.name, f"session expired on {method}")
    if resp.status_code >= 400:
        raise UpstreamError(upstream.name, f"HTTP {resp.status_code} on {method}")
    return _extract_response(resp.content, resp.headers.get("content-type"), upstream.name)


async def call_tool(
    client: httpx.AsyncClient,
    upstream: Upstream,
    session: UpstreamSession,
    request_id: Any,
    tool: str,
    arguments: Any,
) -> dict:
    """Invoke ``tool`` (the upstream's *original*, un-namespaced name) and return
    the JSON-RPC response with the caller's original request id restored."""
    params: dict = {"name": tool}
    if arguments is not None:
        params["arguments"] = arguments
    response = await rpc(
        client, upstream, session, "tools/call", params, timeout=_CALL_TIMEOUT
    )
    response["id"] = request_id
    return response


async def initialize_session(
    client: httpx.AsyncClient, upstream: Upstream
) -> UpstreamSession:
    """Run the MCP handshake against one upstream: ``initialize``, capture its
    ``Mcp-Session-Id`` (if it issues one), then ``notifications/initialized``."""
    payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-auth-gateway", "version": "0.3.0"},
        },
    }
    resp = await _post(client, upstream, payload, None, _CONTROL_TIMEOUT)
    if resp.status_code >= 400:
        raise UpstreamError(upstream.name, f"HTTP {resp.status_code} on initialize")
    message = _extract_response(resp.content, resp.headers.get("content-type"), upstream.name)
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
        client,
        upstream,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session.session_id,
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
