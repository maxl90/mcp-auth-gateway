"""The aggregated ``/mcp`` endpoint: one virtual MCP server over N upstreams.

The gateway answers ``initialize`` itself (issuing its own ``Mcp-Session-Id``
and eagerly opening a session to every upstream — ADR 005 gate 3), merges
``tools/list`` under namespaced names, routes each ``tools/call`` to the
owning upstream, and cascades teardown. AuthN/RBAC/audit happen *before* this
module (``main._enforce``), on the namespaced names the caller sees — the one
policy file spans all upstreams (gate 2).

Failure posture (gate 4): a dead upstream degrades the catalog — served
partial, loudly audited, never silently — while a *call* routed to a dead
upstream fails closed.

v1 scope (gate 5): tools only. ``resources/list`` / ``prompts/list`` get valid
empty results; the GET SSE stream is not offered (405); server-initiated
messages from upstreams are dropped, which is coherent because nothing is
advertised that would produce them.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from ..audit import manifest as audit_manifest
from ..audit import writer as audit
from ..upstreams import get_upstream, get_upstreams, namespace_tool, split_namespaced
from . import upstream_client
from .registry import ClientSession, RouteEntry, get_registry

_SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}

_SERVER_INFO = {"name": "mcp-auth-gateway", "version": "0.3.0"}


def _rpc_error(
    request_id: Any, code: int, message: str, status: int = 200, headers: dict | None = None
) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status_code=status,
        headers=headers,
    )


def _session_from(request: Request, claims: dict | None) -> ClientSession | None:
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
    session = get_registry().get(session_id)
    if session is None:
        return None
    caller_oid = (claims or {}).get("oid")
    if session.oid != caller_oid:
        return None
    return session


def _audit_degraded(
    upstream: str, phase: str, correlation_id: str, claims: dict | None, detail: str
) -> None:
    """A partial catalog is allowed; a *silent* partial catalog is not (gate 4)."""
    audit.record(
        outcome="degraded",
        tool=None,
        correlation_id=correlation_id,
        claims=claims,
        reason=f"upstream unavailable during {phase}: {detail}",
        upstream=upstream,
    )


async def _initialize(
    request: Request, message: dict, claims: dict | None, correlation_id: str
) -> Response:
    """Answer ``initialize`` as the virtual server and eagerly open a session to
    every upstream (gate 3 — the first ``tools/list`` must be complete)."""
    client: httpx.AsyncClient = request.app.state.client
    upstreams = get_upstreams()
    session = get_registry().create(oid=(claims or {}).get("oid"))

    results = await asyncio.gather(
        *(upstream_client.initialize_session(client, u) for u in upstreams),
        return_exceptions=True,
    )
    for up, result in zip(upstreams, results, strict=True):
        if isinstance(result, BaseException):
            _audit_degraded(up.name, "initialize", correlation_id, claims, str(result))
        else:
            session.upstreams[up.name] = result

    requested = ((message.get("params") or {}).get("protocolVersion")) or ""
    protocol = (
        requested
        if requested in _SUPPORTED_PROTOCOL_VERSIONS
        else upstream_client.PROTOCOL_VERSION
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


async def _tools_list(
    request: Request,
    message: dict,
    session: ClientSession,
    claims: dict | None,
    correlation_id: str,
    allowed: set[str] | None,
) -> Response:
    """Fan out, merge under namespaced names, rebuild the route map, filter to
    the caller's RBAC. ``allowed`` is None only when auth is disabled."""
    client: httpx.AsyncClient = request.app.state.client
    live = [
        (get_upstream(name), up_session)
        for name, up_session in session.upstreams.items()
        if up_session.alive
    ]
    results = await asyncio.gather(
        *(
            upstream_client.rpc(client, upstream, up_session, "tools/list")
            for upstream, up_session in live
        ),
        return_exceptions=True,
    )

    merged: list[dict] = []
    routes: dict[str, RouteEntry] = {}
    for (upstream, _), result in zip(live, results, strict=True):
        if isinstance(result, BaseException) or "error" in result:
            detail = str(result if isinstance(result, BaseException) else result["error"])
            _audit_degraded(upstream.name, "tools/list", correlation_id, claims, detail)
            continue
        catalog = [
            t
            for t in (result.get("result") or {}).get("tools") or []
            if isinstance(t, dict) and isinstance(t.get("name"), str)
        ]
        # Pin/compare tool manifests before RBAC filtering — drift evidence
        # covers the full served catalog, not just this caller's slice.
        audit_manifest.observe_catalog(
            upstream.name, catalog, correlation_id=correlation_id, claims=claims
        )
        for tool in catalog:
            original = tool["name"]
            wire_name = namespace_tool(upstream.name, original)
            routes[wire_name] = RouteEntry(upstream=upstream.name, tool=original)
            # The namespaced name is what the client calls and what the policy
            # keys; the original is preserved for display (gate 2).
            merged.append({**tool, "name": wire_name, "title": tool.get("title") or original})

    # Replace (don't update) so tools an upstream stopped serving drop out.
    session.routes = routes

    if allowed is not None:
        merged = [t for t in merged if t["name"] in allowed]
    return JSONResponse(
        {"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": merged}}
    )


async def _tools_call(
    request: Request, message: dict, session: ClientSession, correlation_id: str
) -> Response:
    """Route the call to the owning upstream (RBAC already passed upstream of
    here). Unknown tools and dead upstreams fail closed."""
    params = message.get("params") or {}
    wire_name = params.get("name")
    request_id = message.get("id")

    route = session.routes.get(wire_name) if isinstance(wire_name, str) else None
    if route is None and isinstance(wire_name, str):
        # No route map yet (call before first tools/list): the namespace prefix
        # itself is authoritative — it's how the policy names the tool too.
        parts = split_namespaced(wire_name)
        if parts and get_upstream(parts[0]) is not None:
            route = RouteEntry(upstream=parts[0], tool=parts[1])
    if route is None:
        return _rpc_error(request_id, -32602, f"unknown tool: {wire_name!r}")

    upstream = get_upstream(route.upstream)
    up_session = session.upstreams.get(route.upstream)
    if upstream is None or up_session is None or not up_session.alive:
        # Fail closed on calls to a dead upstream (gate 4).
        return _rpc_error(
            request_id,
            -32000,
            f"upstream '{route.upstream}' is unavailable",
            headers={"X-Correlation-Id": correlation_id},
        )

    client: httpx.AsyncClient = request.app.state.client
    arguments = params.get("arguments")
    try:
        response = await upstream_client.call_tool(
            client, upstream, up_session, request_id, route.tool, arguments
        )
    except upstream_client.UpstreamSessionExpired:
        # The upstream forgot our session (expiry / upstream restart). Re-open
        # exactly that upstream's session and retry ONCE — don't drop the whole
        # client session (Phase 3, Task 14). A second failure falls through to
        # the general handler below and fails closed.
        try:
            new_session = await upstream_client.initialize_session(client, upstream)
            session.upstreams[route.upstream] = new_session
            response = await upstream_client.call_tool(
                client, upstream, new_session, request_id, route.tool, arguments
            )
        except upstream_client.UpstreamError as exc:
            return _rpc_error(
                request_id,
                -32000,
                f"upstream '{route.upstream}' failed after reconnect: {exc.detail}",
                headers={"X-Correlation-Id": correlation_id},
            )
    except upstream_client.UpstreamError as exc:
        return _rpc_error(
            request_id,
            -32000,
            f"upstream '{route.upstream}' failed: {exc.detail}",
            headers={"X-Correlation-Id": correlation_id},
        )
    return JSONResponse(response)


async def handle_post(
    request: Request,
    body: bytes,
    claims: dict | None,
    correlation_id: str,
    allowed: set[str] | None,
) -> Response:
    """Dispatch one authenticated JSON-RPC message to the virtual server."""
    try:
        message = json.loads(body)
    except (ValueError, TypeError):
        return _rpc_error(None, -32700, "parse error: body is not valid JSON")
    if isinstance(message, list):
        # JSON-RPC batching was removed in MCP 2025-06-18; the aggregator does
        # not accept it (the legacy single-upstream path still passes batches
        # through untouched).
        return _rpc_error(None, -32600, "batch requests are not supported")
    if not isinstance(message, dict):
        return _rpc_error(None, -32600, "invalid request")

    method = message.get("method")

    if method == "initialize":
        return await _initialize(request, message, claims, correlation_id)

    if isinstance(method, str) and method.startswith("notifications/"):
        # Accepted, no body — the gateway is the session peer, nothing to relay.
        return Response(status_code=202)

    if method == "ping":
        return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "result": {}})

    # Everything below operates on an established session. 404 tells a
    # Streamable HTTP client its session is gone — it re-initializes. A session
    # whose owning oid doesn't match the caller resolves to None here too, so a
    # leaked session id can't be driven by another user.
    session = _session_from(request, claims)
    if session is None:
        return _rpc_error(message.get("id"), -32000, "no valid session", status=404)

    if method == "tools/list":
        return await _tools_list(request, message, session, claims, correlation_id, allowed)
    if method == "tools/call":
        return await _tools_call(request, message, session, correlation_id)

    # v1 is tools-only (gate 5): empty-but-valid results, not errors, so
    # well-behaved clients that probe these simply see nothing to use.
    empty_results = {
        "resources/list": {"resources": []},
        "resources/templates/list": {"resourceTemplates": []},
        "prompts/list": {"prompts": []},
    }
    if method in empty_results:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": message.get("id"), "result": empty_results[method]}
        )

    return _rpc_error(message.get("id"), -32601, f"method not supported: {method}")


async def handle_delete(request: Request, claims: dict | None) -> Response:
    """End the client session and cascade teardown to every upstream session.

    Ownership is re-checked before deletion (via ``_session_from``) so a leaked
    session id can't be used by another caller to tear down someone else's
    session."""
    session = _session_from(request, claims)
    if session is None:
        return Response(status_code=404)
    get_registry().delete(session.id)

    client: httpx.AsyncClient = request.app.state.client
    await asyncio.gather(
        *(
            upstream_client.delete_session(client, upstream, up_session)
            for name, up_session in session.upstreams.items()
            if (upstream := get_upstream(name)) is not None
        ),
        return_exceptions=True,
    )
    return Response(status_code=204)


def handle_get() -> Response:
    """No server-initiated SSE stream in v1 (tools-only): 405 per the Streamable
    HTTP spec for servers that don't offer one."""
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})
