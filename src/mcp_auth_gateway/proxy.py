"""Forwarding to one upstream: the single-upstream ``/mcp`` proxy and the
path-routed ``/mcp/<name>`` route of aggregation mode.

Both enforce first, then forward with the caller's token stripped. A
``tools/list`` response is buffered and filtered to the caller's permitted
tools; everything else streams through untouched.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from . import naming, upstreams
from .audit import manifest as audit_manifest
from .auth import enforce
from .config import settings
from .http_util import ResponseTooLarge, read_capped
from .tools_filter import extract_tools, filter_tools_list_response, is_tools_list_request

# Server-side log for operational detail that must NOT reach clients (internal
# upstream URLs, raw exception text). Client-facing error bodies stay generic.
logger = logging.getLogger("mcp_auth_gateway")


# Hop-by-hop headers (RFC 9110 §7.6.1) plus content-length/host, which the HTTP
# client and ASGI server recompute. Forwarding these corrupts the stream.
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


# The gateway terminates the user's token: it is validated here and MUST NOT be
# forwarded upstream. Stripping it is the trust boundary in code form — the
# upstream MCP server connects to the database with its own service identity.
_STRIP_ON_FORWARD = frozenset({"authorization"})


def _forward_url(request: Request, target: str) -> httpx.URL:
    url = httpx.URL(target)
    if request.url.query:
        url = url.copy_with(query=request.url.query.encode("ascii"))
    return url


def _forward_headers(request: Request) -> dict[str, str]:
    """Headers to send upstream: drop hop-by-hop ones and — the trust boundary —
    the caller's already-validated ``Authorization``."""
    return {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() not in _STRIP_ON_FORWARD
    }


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    """Upstream response headers to return (incl. mcp-session-id), minus
    hop-by-hop and content-type. content-length is hop-by-hop here, so it's
    dropped and recomputed from the (possibly rewritten) body."""
    return {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "content-type"
    }


async def _forward(request: Request, target: str, body: bytes) -> Response:
    """Forward one request to ``target`` and stream the response back verbatim.

    ``body`` was already read by the enforcement step. The caller's ``Authorization``
    header is dropped here: the gateway has validated and terminated the token.
    """
    client: httpx.AsyncClient = request.app.state.client

    url = _forward_url(request, target)
    fwd_headers = _forward_headers(request)

    upstream_req = client.build_request(request.method, url, headers=fwd_headers, content=body)
    try:
        upstream = await client.send(upstream_req, stream=True)
    except httpx.ConnectError as exc:
        # Detail (internal URL + exception text) goes to the server log only —
        # the client-facing body must not leak internal topology.
        logger.error("upstream unreachable: %s (%s)", target, exc)
        return JSONResponse(
            {
                "error": "upstream_unreachable",
                "detail": "the upstream MCP server could not be reached",
            },
            status_code=502,
        )

    media_type = upstream.headers.get("content-type")
    resp_headers = _response_headers(upstream)

    async def body_stream() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(
        body_stream(),
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=media_type,
    )


async def _forward_filtered(
    request: Request,
    target: str,
    body: bytes,
    allowed: set[str],
    *,
    correlation_id: str,
    claims: dict | None,
    manifest_upstream: str | None = None,
) -> Response:
    """Forward a ``tools/list`` request and filter the response to ``allowed``.

    Unlike :func:`_forward` this buffers the upstream response (capped by
    ``MAX_UPSTREAM_RESPONSE_BYTES``) to rewrite it. The unfiltered catalog is also
    observed for manifest pinning, keyed under ``manifest_upstream`` when given.
    """
    client: httpx.AsyncClient = request.app.state.client
    upstream_req = client.build_request(
        request.method,
        _forward_url(request, target),
        headers=_forward_headers(request),
        content=body,
    )
    try:
        upstream = await client.send(upstream_req, stream=True)
    except httpx.ConnectError as exc:
        logger.error("upstream unreachable: %s (%s)", target, exc)
        return JSONResponse(
            {
                "error": "upstream_unreachable",
                "detail": "the upstream MCP server could not be reached",
            },
            status_code=502,
        )

    try:
        raw = await read_capped(upstream, settings.max_upstream_response_bytes)
    except ResponseTooLarge as exc:
        logger.error("upstream response too large: %s (%s)", target, exc)
        return JSONResponse(
            {
                "error": "upstream_response_too_large",
                "detail": "the upstream response exceeded the configured size cap",
            },
            status_code=502,
        )
    finally:
        await upstream.aclose()

    catalog = extract_tools(raw, upstream.headers.get("content-type"))
    if catalog:
        audit_manifest.observe_catalog(
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
    body = await request.body()
    correlation_id = uuid.uuid4().hex
    guard, claims = await enforce.enforce(request, body, correlation_id)
    if guard is not None:
        return guard
    if claims is not None and is_tools_list_request(body):
        allowed = enforce.allowed_tools(claims)
        return await _forward_filtered(
            request,
            target,
            body,
            allowed,
            correlation_id=correlation_id,
            claims=claims,
        )
    return await _forward(request, target, body)


async def path_routed(request: Request, subpath: str) -> Response:
    """Aggregation-mode ``/mcp/<name>[/...]``: stateless passthrough to one named
    upstream. Wire tool names are the upstream's own, so RBAC and audit prefix
    them; the same namespaced policy governs both routes."""
    name, _, rest = subpath.partition("/")
    upstream = upstreams.get_upstream(name)
    if upstream is None:
        return JSONResponse(
            {"error": "unknown_upstream", "detail": f"no upstream named '{name}'"},
            status_code=404,
        )
    target = f"{upstream.url}/{rest}" if rest else upstream.url

    body = await request.body()
    correlation_id = uuid.uuid4().hex
    guard, claims = await enforce.enforce(
        request,
        body,
        correlation_id,
        policy_key=lambda tool: naming.namespace_tool(name, tool),
        upstream_for=lambda _tool: name,
    )
    if guard is not None:
        return guard
    if claims is not None and is_tools_list_request(body):
        # The upstream answers with its own (un-namespaced) tool names; project
        # the caller's namespaced allow-set down to this upstream's slice.
        namespaced = enforce.allowed_tools(claims)
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
            correlation_id=correlation_id,
            claims=claims,
            manifest_upstream=name,
        )
    return await _forward(request, target, body)
