"""Forwarding to one upstream: the single-upstream ``/mcp`` proxy and the
path-routed ``/mcp/<name>`` route of aggregation mode.

Both enforce first, then forward with the caller's token stripped and the body
re-serialized from what enforcement parsed. A ``tools/list`` response is buffered
and filtered to the caller's permitted tools; every other response streams through
untouched.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable, Iterable

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from . import jsonrpc, naming, state
from .auth import enforce
from .auth.claims import Claims, principal
from .config import settings
from .http_util import BodyTooLarge, read_capped, read_request_body
from .tools_filter import extract_tools, filter_tools_list_response, is_tools_list_request

# Server-side log for operational detail that must NOT reach clients (internal
# upstream URLs, raw exception text). Client-facing error bodies stay generic.
logger = logging.getLogger("mcp_auth_gateway")


# Hop-by-hop headers (RFC 9110 §7.6.1) plus content-length/host, which the HTTP
# client and ASGI server recompute. Forwarding these corrupts the stream. A message
# can name more in its Connection field; see _connection_options.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)


# Set by the gateway's own server on every response; relaying the upstream's
# copies would send two of each.
_SERVER_OWNED = frozenset({"date", "server"})

# The gateway terminates the caller's credentials and is the client the upstream
# sees. The token and its DPoP proof are validated here and MUST NOT be forwarded:
# stripping them is the trust boundary in code form, and the upstream MCP server
# reaches its resource with its own service identity. Cookies and client-chosen
# forwarding or edge-identity headers stop here too: an upstream that read them
# would see values the caller picked, arriving from the gateway's address.
_STRIP_ON_FORWARD = frozenset({"authorization", "dpop", "cookie", "forwarded", "x-real-ip"})
_STRIP_PREFIXES_ON_FORWARD = ("x-forwarded-", "x-client-cert-")


# RFC 3986 unreserved characters: nothing an upstream could decode or reinterpret.
_SUBPATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]*")


def is_safe_subpath(subpath: str) -> bool:
    """False for a subpath that could leave the upstream endpoint it is appended to.

    The route receives the path percent-decoded once, so ``..%2F`` arrives as ``../``
    and ``%3F`` as ``?``. Each segment must be unreserved characters and not ``.`` or
    ``..``. That also refuses a second layer of encoding (``%2e%2e``, which an upstream
    decodes to ``..``), ``;`` path parameters, backslashes and control characters."""
    return all(
        _SUBPATH_SEGMENT.fullmatch(segment) and segment not in (".", "..")
        for segment in subpath.split("/")
    )


def _forward_url(request: Request, target: str) -> httpx.URL:
    url = httpx.URL(target)
    if request.url.query:
        url = url.copy_with(query=request.url.query.encode("ascii"))
    return url


def _connection_options(values: Iterable[str]) -> frozenset[str]:
    """The header names a ``Connection`` field lists (RFC 9110 §7.6.1). Each is
    hop-by-hop for that one message, so a proxy forwards none of them."""
    return frozenset(
        option.strip().lower() for value in values for option in value.split(",") if option.strip()
    )


def _forward_headers(request: Request) -> dict[str, str]:
    """Headers to send upstream: all but the hop-by-hop ones (fixed, and those the
    request's Connection field names) and what the gateway terminates (the trust
    boundary, see ``_STRIP_ON_FORWARD``)."""
    per_hop = _connection_options(request.headers.getlist("connection"))
    return {
        k: v
        for k, v in request.headers.items()
        if (name := k.lower()) not in _HOP_BY_HOP
        and name not in per_hop
        and name not in _STRIP_ON_FORWARD
        and not name.startswith(_STRIP_PREFIXES_ON_FORWARD)
    }


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    """Upstream response headers to return (incl. mcp-session-id), minus
    hop-by-hop (fixed, and those the response's Connection field names),
    server-owned and content-type. content-length is hop-by-hop here, so it's
    dropped and recomputed from the (possibly rewritten) body."""
    per_hop = _connection_options(upstream.headers.get_list("connection"))
    return {
        k: v
        for k, v in upstream.headers.items()
        if (name := k.lower()) not in _HOP_BY_HOP
        and name not in per_hop
        and name not in _SERVER_OWNED
        and name != "content-type"
    }


def _bad_gateway(error: str, detail: str) -> JSONResponse:
    return JSONResponse({"error": error, "detail": detail}, status_code=502)


def _readable_body(request: Request, body: bytes) -> bytes | JSONResponse:
    """``body`` as the gateway will forward it, or the refusal for one the upstream
    could read differently from the gateway: content-encoded (415), or refused by
    :func:`jsonrpc.canonical_request` (400)."""
    codings = (
        c.strip().lower() for v in request.headers.getlist("content-encoding") for c in v.split(",")
    )
    if any(c not in ("", "identity") for c in codings):
        return JSONResponse(
            {
                "error": "unsupported_content_encoding",
                "detail": "the request body must not be content-encoded",
            },
            status_code=415,
        )
    if not body:
        return body
    try:
        return jsonrpc.canonical_request(body)
    except (ValueError, RecursionError):
        return JSONResponse(
            {
                "error": "invalid_request",
                "detail": "the request body is not JSON the gateway can read unambiguously",
            },
            status_code=400,
        )


async def _enforce(
    request: Request,
    body: bytes,
    correlation_id: str,
    policy_key: Callable[[str], str] = lambda tool: tool,
    upstream_for: Callable[[str], str | None] = lambda _tool: None,
) -> tuple[bytes, enforce.Admitted | None] | Response:
    """:func:`enforce.enforce` on the body the upstream will receive, with that body.

    Enforcement and the upstream must read the same message, so what is checked and
    forwarded is the gateway's own serialization of what it parsed. A body it cannot
    read is refused, after authentication so an anonymous caller still gets the 401."""
    readable = _readable_body(request, body)
    checked = readable if isinstance(readable, bytes) else b""
    guard, admitted = await enforce.enforce(
        request, checked, correlation_id, policy_key=policy_key, upstream_for=upstream_for
    )
    if guard is not None:
        return guard
    if isinstance(readable, Response):
        return readable
    return readable, admitted


def _take_slot(
    request: Request, admitted: enforce.Admitted | None
) -> Callable[[], None] | Response:
    """One of the caller's forwarding slots (:class:`state.ForwardSlots`): the function
    that frees it once the upstream response is done, or a 429 when all are in use.
    With auth off there is no principal and no cap."""
    if admitted is None:
        return lambda: None
    caller = principal(admitted.claims) or ""
    slots = state.of(request).forward_slots
    if not slots.acquire(caller):
        return JSONResponse(
            {
                "error": "too_many_requests",
                "detail": "too many upstream requests are in flight for this caller",
            },
            status_code=429,
            headers={"Retry-After": "1"},
        )
    return lambda: slots.release(caller)


async def _send(
    request: Request, target: str, body: bytes, release: Callable[[], None]
) -> httpx.Response | JSONResponse:
    """Send the caller's request to ``target`` and return the streamed upstream
    response, or a 502 when it cannot be sent (refused, timed out, reset). When no
    response comes back the caller's slot is freed here; otherwise the caller frees
    it once the response is done.

    ``body`` was already read by the enforcement step. The caller's credentials are
    dropped here: the gateway has validated and terminated them.
    """
    client = state.of(request).client
    try:
        upstream_req = client.build_request(
            request.method,
            _forward_url(request, target),
            headers=_forward_headers(request),
            content=body,
        )
        return await client.send(upstream_req, stream=True)
    except BaseException as exc:
        release()
        if not isinstance(exc, httpx.HTTPError):
            raise
        # Detail (internal URL + exception text) goes to the server log only —
        # the client-facing body must not leak internal topology.
        logger.error("upstream unreachable: %s (%s)", target, exc)
        return _bad_gateway("upstream_unreachable", "the upstream MCP server could not be reached")


async def _forward(
    request: Request, target: str, body: bytes, release: Callable[[], None]
) -> Response:
    """Forward one request to ``target`` and stream the response back verbatim."""
    upstream = await _send(request, target, body, release)
    if isinstance(upstream, JSONResponse):
        return upstream
    return _UpstreamStream(upstream, release)


class _UpstreamStream(StreamingResponse):
    """An upstream response streamed back as received. It closes the upstream and
    frees the caller's slot however it ends: finished, cut off by the client, or
    never started because the client was already gone."""

    def __init__(self, upstream: httpx.Response, release: Callable[[], None]) -> None:
        super().__init__(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            media_type=upstream.headers.get("content-type"),
        )
        self._upstream = upstream
        self._release = release

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self._upstream.aclose()
            finally:
                self._release()


async def _forward_filtered(
    request: Request,
    target: str,
    body: bytes,
    allowed: set[str],
    release: Callable[[], None],
    *,
    correlation_id: str,
    claims: Claims | None,
    manifest_upstream: str | None = None,
) -> Response:
    """Forward a ``tools/list`` request and filter the response to ``allowed``.

    Unlike :func:`_forward` this buffers the upstream response (capped by
    ``MAX_UPSTREAM_RESPONSE_BYTES``) to rewrite it. The unfiltered catalog is also
    observed for manifest pinning, keyed under ``manifest_upstream`` when given.
    """
    upstream = await _send(request, target, body, release)
    if isinstance(upstream, JSONResponse):
        return upstream

    try:
        raw = await read_capped(upstream.aiter_bytes(), settings.max_upstream_response_bytes)
    except BodyTooLarge as exc:
        logger.error("upstream response too large: %s (%s)", target, exc)
        return _bad_gateway(
            "upstream_response_too_large", "the upstream response exceeded the configured size cap"
        )
    except httpx.HTTPError as exc:
        logger.error("upstream response unreadable: %s (%s)", target, exc)
        return _bad_gateway(
            "upstream_response_incomplete", "the upstream response could not be read in full"
        )
    finally:
        try:
            await upstream.aclose()
        finally:
            release()

    catalog = extract_tools(raw, upstream.headers.get("content-type"))
    if catalog:
        state.of(request).manifests.observe_catalog(
            manifest_upstream, catalog, correlation_id=correlation_id, claims=claims
        )

    filtered = filter_tools_list_response(raw, upstream.headers.get("content-type"), allowed)
    return Response(
        content=filtered,
        status_code=upstream.status_code,
        headers=_response_headers(upstream),
        media_type=upstream.headers.get("content-type"),
    )


async def single_upstream(request: Request, target: str) -> Response:
    """Single-upstream proxy: enforce, then forward, filtering a ``tools/list``
    response to the caller's permitted tools."""
    body = await read_request_body(request)
    if isinstance(body, Response):
        return body
    correlation_id = uuid.uuid4().hex
    enforced = await _enforce(request, body, correlation_id)
    if isinstance(enforced, Response):
        return enforced
    body, admitted = enforced
    release = _take_slot(request, admitted)
    if isinstance(release, Response):
        return release
    if admitted is not None:
        admitted.record_allowed()  # nothing below refuses the call: it is forwarded
    if admitted is not None and is_tools_list_request(body):
        return await _forward_filtered(
            request,
            target,
            body,
            admitted.allowed_tools(),
            release,
            correlation_id=correlation_id,
            claims=admitted.claims,
        )
    return await _forward(request, target, body, release)


async def path_routed(request: Request, subpath: str) -> Response:
    """Aggregation-mode ``/mcp/<name>[/...]``: stateless passthrough to one named
    upstream. Wire tool names are the upstream's own, so RBAC and audit prefix
    them; the same namespaced policy governs both routes."""
    name, _, rest = subpath.partition("/")
    upstream = state.of(request).upstreams.get(name)
    if upstream is None:
        return JSONResponse(
            {"error": "unknown_upstream", "detail": f"no upstream named '{name}'"},
            status_code=404,
        )
    target = f"{upstream.url}/{rest}" if rest else upstream.url

    body = await read_request_body(request)
    if isinstance(body, Response):
        return body
    correlation_id = uuid.uuid4().hex
    enforced = await _enforce(
        request,
        body,
        correlation_id,
        policy_key=lambda tool: naming.namespace_tool(name, tool),
        upstream_for=lambda _tool: name,
    )
    if isinstance(enforced, Response):
        return enforced
    body, admitted = enforced
    release = _take_slot(request, admitted)
    if isinstance(release, Response):
        return release
    if admitted is not None:
        admitted.record_allowed()  # nothing below refuses the call: it is forwarded
    if admitted is not None and is_tools_list_request(body):
        # The upstream answers with its own (un-namespaced) tool names; project
        # the caller's namespaced allow-set down to this upstream's slice.
        namespaced = admitted.allowed_tools()
        allowed = {
            split[1]
            for split in map(naming.split_namespaced, namespaced)
            if split and split[0] == name
        }
        return await _forward_filtered(
            request,
            target,
            body,
            allowed,
            release,
            correlation_id=correlation_id,
            claims=admitted.claims,
            manifest_upstream=name,
        )
    return await _forward(request, target, body, release)
