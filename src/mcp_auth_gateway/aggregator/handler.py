"""The aggregated ``/mcp`` endpoint: one virtual MCP server over N upstreams.

The gateway answers ``initialize`` itself (issuing its own ``Mcp-Session-Id`` and
eagerly opening a session to every upstream), merges ``tools/list`` under
namespaced names, routes each ``tools/call`` to the owning upstream, and cascades
teardown. Authentication, RBAC and audit happen first, in ``auth.enforce``, on
the namespaced names the caller sees. A dead upstream degrades the catalog
(served partial, audited, never silent) while a call to it fails closed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .. import __version__, jsonrpc, state
from ..audit import writer as audit
from ..auth import enforce
from ..auth.claims import Claims
from ..http_util import read_request_body
from ..naming import namespace_tool, split_namespaced
from ..upstreams import Upstream
from . import upstream_client
from .registry import ClientSession, RouteEntry
from .upstream_client import UpstreamRequest

_SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}

_SERVER_INFO = {"name": "mcp-auth-gateway", "version": __version__}

# Tools only: these answer empty-but-valid results, not errors, so well-behaved
# clients that probe them see nothing to use.
_EMPTY_RESULTS: dict[str, dict[str, list[Any]]] = {
    "resources/list": {"resources": []},
    "resources/templates/list": {"resourceTemplates": []},
    "prompts/list": {"prompts": []},
}

# Upstream failure detail (transport errors name internal hosts) goes here, never
# into a client-facing body; the correlation id ties the two together.
logger = logging.getLogger("mcp_auth_gateway")


@dataclass(frozen=True)
class _Call:
    """One authenticated request to the virtual server."""

    request: Request
    claims: Claims | None
    correlation_id: str

    @property
    def gateway(self) -> state.Gateway:
        return state.of(self.request)

    @property
    def client(self) -> httpx.AsyncClient:
        return self.gateway.client


def _rpc_error(
    request_id: Any,
    code: int,
    message: str,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status_code=status,
        headers=headers,
    )


def _principal(claims: Claims | None) -> str | None:
    """Who a session belongs to: the human's ``oid``, else ``sub``, else the app's ``azp``."""
    if not claims:
        return None
    return claims.get("oid") or claims.get("sub") or claims.get("azp")


def _session_from(request: Request, claims: Claims | None) -> ClientSession | None:
    """Resolve the caller's session from ``Mcp-Session-Id`` — but only if it
    belongs to them.

    Security: the session id is returned in a response header and can leak
    (proxy logs, client config). Binding it to the creator's Entra ``oid`` at
    ``initialize`` is not enough on its own — it must be *re-checked* on every
    reuse, or a second caller presenting a leaked id would operate inside the
    first user's session (and its open upstream sessions). A mismatch is treated
    as "no session" (the caller re-initializes their own)."""
    session_id = request.headers.get("mcp-session-id")
    if not session_id:
        return None
    session = state.of(request).sessions.get(session_id)
    if session is None:
        return None
    if session.principal != _principal(claims):
        return None
    return session


async def _teardown(gateway: state.Gateway, session: ClientSession) -> None:
    """Best-effort DELETE of every upstream session a client session holds."""
    await asyncio.gather(
        *(
            upstream_client.delete_session(
                gateway.client, upstream, session.upstreams[upstream.name]
            )
            for upstream in gateway.upstreams.values()
            if upstream.name in session.upstreams
        ),
        return_exceptions=True,
    )


def _audit_degraded(upstream: str, phase: str, call: _Call, detail: str) -> None:
    """A partial catalog is allowed; a silent partial catalog is not."""
    call.gateway.audit.record(
        audit.AuditEvent(
            outcome="degraded",
            tool=None,
            correlation_id=call.correlation_id,
            claims=call.claims,
            reason=f"upstream unavailable during {phase}: {detail}",
            upstream=upstream,
        )
    )


# --- initialize -------------------------------------------------------------------


async def _initialize(call: _Call, message: dict[str, Any]) -> Response:
    """Answer ``initialize`` as the virtual server and open a session to every
    upstream now, so the first ``tools/list`` is complete."""
    upstreams = list(call.gateway.upstreams.values())
    registry = call.gateway.sessions
    session = registry.create(_principal(call.claims))
    for stale in registry.pop_evicted():  # over the per-principal cap, or idle too long
        await _teardown(call.gateway, stale)

    results = await asyncio.gather(
        *(upstream_client.initialize_session(call.client, u) for u in upstreams),
        return_exceptions=True,
    )
    for up, result in zip(upstreams, results, strict=True):
        if isinstance(result, BaseException):
            _audit_degraded(up.name, "initialize", call, str(result))
        else:
            session.upstreams[up.name] = result

    requested = jsonrpc.params_of(message).get("protocolVersion") or ""
    protocol = (
        requested if requested in _SUPPORTED_PROTOCOL_VERSIONS else upstream_client.PROTOCOL_VERSION
    )
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": _SERVER_INFO,
            },
        },
        headers={"Mcp-Session-Id": session.id},
    )


# --- tools/list -------------------------------------------------------------------


async def _fetch_catalogs(
    gateway: state.Gateway, session: ClientSession
) -> list[tuple[Upstream, dict[str, Any] | BaseException]]:
    """Each upstream's ``tools/list`` answer, or the exception it raised."""
    live = [
        (u, session.upstreams[u.name])
        for u in gateway.upstreams.values()
        if u.name in session.upstreams
    ]
    results = await asyncio.gather(
        *(
            upstream_client.rpc(UpstreamRequest(gateway.client, upstream, up_session), "tools/list")
            for upstream, up_session in live
        ),
        return_exceptions=True,
    )
    return [(upstream, result) for (upstream, _), result in zip(live, results, strict=True)]


def _catalog_of(response: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The named tool entries of a ``tools/list`` response, or ``None`` when its
    ``result`` is not an object carrying a ``tools`` list."""
    result = response.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return None
    return [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]


def _merge_catalog(
    upstream: Upstream, catalog: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, RouteEntry]]:
    """Namespace one upstream's tools and map each wire name back to its owner.

    The namespaced name is what the client calls and what the policy keys; the
    original is preserved for display."""
    tools: list[dict[str, Any]] = []
    routes: dict[str, RouteEntry] = {}
    for tool in catalog:
        original = tool["name"]
        wire_name = namespace_tool(upstream.name, original)
        routes[wire_name] = RouteEntry(upstream=upstream, tool=original)
        tools.append({**tool, "name": wire_name, "title": tool.get("title") or original})
    return tools, routes


async def _tools_list(
    call: _Call, message: dict[str, Any], session: ClientSession, allowed: set[str] | None
) -> Response:
    """Fan out, merge under namespaced names, rebuild the route map, filter to
    the caller's RBAC. ``allowed`` is None only when auth is disabled."""
    merged: list[dict[str, Any]] = []
    routes: dict[str, RouteEntry] = {}
    for upstream, result in await _fetch_catalogs(call.gateway, session):
        if isinstance(result, BaseException) or "error" in result:
            detail = str(result if isinstance(result, BaseException) else result["error"])
            _audit_degraded(upstream.name, "tools/list", call, detail)
            continue
        catalog = _catalog_of(result)
        if catalog is None:
            _audit_degraded(upstream.name, "tools/list", call, "result carries no tools list")
            continue
        # Pin/compare tool manifests before RBAC filtering — drift evidence
        # covers the full served catalog, not just this caller's slice.
        call.gateway.manifests.observe_catalog(
            upstream.name, catalog, correlation_id=call.correlation_id, claims=call.claims
        )
        tools, upstream_routes = _merge_catalog(upstream, catalog)
        merged.extend(tools)
        routes.update(upstream_routes)

    # Replace (don't update) so tools an upstream stopped serving drop out.
    session.routes = routes

    if allowed is not None:
        merged = [t for t in merged if t["name"] in allowed]
    return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": merged}})


# --- tools/call -------------------------------------------------------------------


def _resolve_route(
    upstreams: Mapping[str, Upstream], session: ClientSession, wire_name: object
) -> RouteEntry | None:
    """The owning upstream and original name: from the session's route map, or,
    before the first ``tools/list``, from the namespace prefix itself (it is how
    the policy names the tool too)."""
    if not isinstance(wire_name, str):
        return None
    route = session.routes.get(wire_name)
    if route is None:
        parts = split_namespaced(wire_name)
        if parts and (upstream := upstreams.get(parts[0])) is not None:
            route = RouteEntry(upstream=upstream, tool=parts[1])
    return route


async def _call_with_reconnect(
    call: _Call, session: ClientSession, route: RouteEntry, request_id: Any, arguments: Any
) -> dict[str, Any]:
    """Call the tool; if the upstream forgot our session (expiry, restart), re-open
    exactly that upstream's session and retry once rather than drop the whole
    client session. A second failure propagates and fails closed."""
    upstream = route.upstream
    attribution = upstream_client.attribution_headers(call.correlation_id, call.claims)
    try:
        req = UpstreamRequest(call.client, upstream, session.upstreams[upstream.name])
        return await upstream_client.call_tool(req, request_id, route.tool, arguments, attribution)
    except upstream_client.UpstreamSessionExpired:
        pass
    try:
        new_session = await upstream_client.initialize_session(call.client, upstream)
        session.upstreams[upstream.name] = new_session
        req = UpstreamRequest(call.client, upstream, new_session)
        return await upstream_client.call_tool(req, request_id, route.tool, arguments, attribution)
    except upstream_client.UpstreamError as exc:
        raise upstream_client.UpstreamError(
            upstream.name, f"after reconnect: {exc.detail}"
        ) from exc


def _upstream_failed(
    upstream: str, exc: upstream_client.UpstreamError, call: _Call, request_id: Any
) -> JSONResponse:
    """A generic error for the caller; the upstream's detail goes to the server log."""
    logger.error(
        "upstream %s failed: %s [correlation %s]", upstream, exc.detail, call.correlation_id
    )
    return _rpc_error(
        request_id,
        -32000,
        f"upstream '{upstream}' failed",
        headers={"X-Correlation-Id": call.correlation_id},
    )


async def _tools_call(call: _Call, message: dict[str, Any], session: ClientSession) -> Response:
    """Route the call to its upstream; RBAC already passed. Unknown tools and dead
    upstreams fail closed. With ``forward_attribution_headers`` on, the upstream
    request carries the correlation id and the human's oid as audit metadata."""
    params = jsonrpc.params_of(message)
    wire_name = params.get("name")
    request_id = message.get("id")

    route = _resolve_route(call.gateway.upstreams, session, wire_name)
    if route is None:
        return _rpc_error(request_id, -32602, f"unknown tool: {wire_name!r}")
    if route.upstream.name not in session.upstreams:
        # Fail closed on calls to an upstream that was down at initialize.
        return _rpc_error(
            request_id,
            -32000,
            f"upstream '{route.upstream.name}' is unavailable",
            headers={"X-Correlation-Id": call.correlation_id},
        )

    try:
        response = await _call_with_reconnect(
            call, session, route, request_id, params.get("arguments")
        )
    except upstream_client.UpstreamError as exc:
        return _upstream_failed(route.upstream.name, exc, call, request_id)
    return JSONResponse(response)


# --- dispatch ---------------------------------------------------------------------


def _parse_message(body: bytes) -> dict[str, Any] | JSONResponse:
    """The one JSON-RPC request in the body, or the error response for anything else."""
    try:
        message = json.loads(body)
    except ValueError:
        return _rpc_error(None, -32700, "parse error: body is not valid JSON")
    if isinstance(message, list):
        # JSON-RPC batching was removed in MCP 2025-06-18; the aggregator does
        # not accept it (the legacy single-upstream path still passes batches
        # through untouched).
        return _rpc_error(None, -32600, "batch requests are not supported")
    if not isinstance(message, dict):
        return _rpc_error(None, -32600, "invalid request")
    return message


async def handle_post(
    request: Request,
    body: bytes,
    claims: Claims | None,
    correlation_id: str,
    allowed: set[str] | None,
) -> Response:
    """Dispatch one authenticated JSON-RPC message to the virtual server."""
    message = _parse_message(body)
    if isinstance(message, Response):
        return message
    call = _Call(request, claims, correlation_id)
    method = message.get("method")

    if method == "initialize":
        return await _initialize(call, message)
    if isinstance(method, str) and method.startswith("notifications/"):
        # Accepted, no body — the gateway is the session peer, nothing to relay.
        return Response(status_code=202)
    if method == "ping":
        return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "result": {}})

    # Everything below operates on an established session. 404 tells a
    # Streamable HTTP client its session is gone — it re-initializes. A session
    # whose owner doesn't match the caller resolves to None here too, so a
    # leaked session id can't be driven by another user.
    session = _session_from(request, claims)
    if session is None:
        return _rpc_error(message.get("id"), -32000, "no valid session", status=404)

    if method == "tools/list":
        return await _tools_list(call, message, session, allowed)
    if method == "tools/call":
        return await _tools_call(call, message, session)
    if method in _EMPTY_RESULTS:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": message.get("id"), "result": _EMPTY_RESULTS[method]}
        )
    return _rpc_error(message.get("id"), -32601, f"method not supported: {method}")


async def handle_delete(request: Request, claims: Claims | None) -> Response:
    """End the client session and cascade teardown to every upstream session.

    Ownership is re-checked before deletion (via ``_session_from``) so a leaked
    session id can't be used by another caller to tear down someone else's
    session."""
    session = _session_from(request, claims)
    if session is None:
        return Response(status_code=404)
    gateway = state.of(request)
    gateway.sessions.delete(session.id)
    await _teardown(gateway, session)
    return Response(status_code=204)


def handle_get() -> Response:
    """No server-initiated SSE stream (tools only): 405, as Streamable HTTP specifies
    for servers without one."""
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


def upstream_for_tool(upstreams: Mapping[str, Upstream], tool: str) -> str | None:
    """Audit helper: the namespace prefix of an aggregated wire name, if it
    names a configured upstream."""
    parts = split_namespaced(tool)
    return parts[0] if parts and parts[0] in upstreams else None


async def handle_mcp(request: Request) -> Response:
    """Aggregation-mode ``/mcp``: the same authentication/RBAC/audit pass, then the
    virtual server instead of a passthrough. Wire tool names are already
    namespaced, so they are the policy keys."""
    if request.method == "GET":
        return handle_get()

    body = await read_request_body(request) if request.method == "POST" else b""
    if isinstance(body, Response):
        return body
    correlation_id = uuid.uuid4().hex
    upstreams = state.of(request).upstreams
    guard, admitted = await enforce.enforce(
        request, body, correlation_id, upstream_for=lambda tool: upstream_for_tool(upstreams, tool)
    )
    if guard is not None:
        return guard
    claims = admitted.claims if admitted else None

    if request.method == "DELETE":
        return await handle_delete(request, claims)
    if request.method != "POST":
        return Response(status_code=405, headers={"Allow": "POST, DELETE"})

    # Auth disabled (plumbing checks): serve the catalog unfiltered.
    allowed = admitted.allowed_tools() if admitted else None
    return await handle_post(request, body, claims, correlation_id, allowed)
