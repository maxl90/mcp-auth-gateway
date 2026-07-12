"""mcp-auth-gateway — Phase 1 governed proxy.

A reverse proxy in front of an MCP server. Every ``/mcp`` request must carry a
valid Entra ID token (else 401); ``tools/call`` requests are additionally
checked against tool-level RBAC (else 403, request never forwarded). Each
tool invocation produces a structured, argument-redacted audit record.

Crucially, the gateway **terminates** the user token: it is validated locally
against the tenant JWKS and then stripped before forwarding — the token and the
raw arguments never leave the gateway. That trust boundary is the whole point
(see CONTEXT.md). Step-up auth and tools/list filtering are later phases; they
layer onto this same path.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from . import upstreams
from .aggregator import handler as aggregator
from .audit import conformance as audit_conformance
from .audit import manifest as audit_manifest
from .audit import structure as audit_structure
from .audit import writer as audit
from .auth import discovery, dpop, step_up
from .auth.policy_resolver import get_policy
from .auth.token_validator import TokenError, get_validator
from .config import settings
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

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# The gateway terminates the user's token: it is validated here and MUST NOT be
# forwarded upstream. Stripping it is the trust boundary in code form — the
# upstream MCP server connects to the database with its own service identity.
_STRIP_ON_FORWARD = frozenset({"authorization"})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Fail closed at boot: if auth is on, build the validator and load the policy
    # now so a misconfigured gateway refuses to start rather than 500-ing (or,
    # worse, silently mis-enforcing) on the first request.
    if settings.auth_enabled:
        get_validator()
        get_policy()
        # Phase 1.5: validate the resource-server config now so a gateway missing
        # GATEWAY_RESOURCE_URL refuses to start rather than serving a 401 whose
        # discovery pointer leads to an unconfigured PRM document.
        discovery.build_prm_document()
    # Phase 3: in aggregation mode a bad upstreams.yaml must also refuse to
    # start — an aggregator that can't tell its upstreams apart mis-routes.
    if upstreams.aggregation_enabled():
        upstreams.get_upstreams()

    # One pooled client for the process. No read timeout: MCP responses can be
    # long-lived SSE streams. Only the connect attempt is bounded.
    timeout = httpx.Timeout(10.0, read=None)
    async with httpx.AsyncClient(timeout=timeout) as client:
        app.state.client = client
        yield


app = FastAPI(title="mcp-auth-gateway", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    if upstreams.aggregation_enabled():
        return JSONResponse(
            {
                "status": "ok",
                "mode": "aggregate",
                "upstreams": {u.name: u.url for u in upstreams.get_upstreams()},
            }
        )
    return JSONResponse({"status": "ok", "upstream": settings.upstream_mcp_url})


@app.get(discovery.PRM_WELL_KNOWN_PATH)
async def protected_resource_metadata() -> Response:
    """Protected Resource Metadata (RFC 9728), Phase 1.5 REQ-1.5.3.

    Unauthenticated discovery anchor: a cold client reads this to learn the
    gateway's resource identifier and which authorization server to use. Returns
    404 if the gateway has no resource URL configured (e.g. Phase 0 passthrough).
    """
    try:
        return JSONResponse(discovery.build_prm_document())
    except RuntimeError:
        return JSONResponse({"error": "not_configured"}, status_code=404)


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

    ``body`` is passed in (already read by the enforcement step) so the request
    isn't consumed twice. The caller's ``Authorization`` header is dropped here —
    the gateway has already validated and terminated the token.
    """
    client: httpx.AsyncClient = request.app.state.client

    url = _forward_url(request, target)
    fwd_headers = _forward_headers(request)

    upstream_req = client.build_request(
        request.method, url, headers=fwd_headers, content=body
    )
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

    # Preserve upstream response headers (incl. mcp-session-id) except hop-by-hop.
    # content-type is handled via media_type to avoid a duplicate header.
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


class _ResponseTooLarge(Exception):
    """An upstream response body exceeded the configured buffering cap."""


async def _read_capped(response: httpx.Response) -> bytes:
    """Read a streamed response body, aborting past ``max_upstream_response_bytes``.

    Bounds gateway memory against an upstream that streams an unbounded body
    within the read timeout (which is per-read, not total). 0 disables the cap."""
    cap = settings.max_upstream_response_bytes
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if cap and total > cap:
            raise _ResponseTooLarge(f"response exceeded {cap}-byte cap")
        chunks.append(chunk)
    return b"".join(chunks)


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
    """Forward a ``tools/list`` request, then return the response with tools
    outside the caller's ``allowed`` set removed (Phase 2).

    Unlike :func:`_forward`, this **buffers** the upstream response so it can
    rewrite the body. A ``tools/list`` reply is a bounded catalog, but a
    malicious/compromised upstream could stream an unbounded one, so the read is
    capped (``MAX_UPSTREAM_RESPONSE_BYTES``). Filtering is visibility-only: on any
    parse failure the body is returned unchanged (see ``tools_filter``).

    The **unfiltered** catalog is also observed for manifest pinning/drift
    (``audit.manifest``) — evidence covers every tool the upstream serves, not
    just this caller's slice. ``manifest_upstream`` namespaces the pin keys in
    path-routed mode; ``None`` (legacy mode) pins under the bare tool names,
    matching the policy/audit keys of each route.
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
        raw = await _read_capped(upstream)
    except _ResponseTooLarge as exc:
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

    filtered = filter_tools_list_response(
        raw, upstream.headers.get("content-type"), allowed
    )
    return Response(
        content=filtered,
        status_code=upstream.status_code,
        headers=_response_headers(upstream),
        media_type=upstream.headers.get("content-type"),
    )


def _credentials(request: Request) -> tuple[str, str] | None:
    """The Authorization header's ``(scheme, token)``, lowercased scheme.

    ``Bearer`` is the plain OAuth scheme; ``DPoP`` (RFC 9449 §7.1) is how a
    sender-constrained token is presented — same token string, different
    scheme, and it signals that a DPoP proof header accompanies the request.
    Token *validation* is identical for both; the binding check happens after.
    """
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() in ("bearer", "dpop") and token.strip():
        return scheme.lower(), token.strip()
    return None


def _edge_identity(request: Request) -> dict | None:
    """The edge proxy's forwarded mTLS client-cert identity, when configured
    trusted (TRUST_EDGE_HEADERS — only safe when nothing but the proxy can
    reach the gateway). Returns the audit ``channel`` fragment or None."""
    if not settings.trust_edge_headers:
        return None
    serial = request.headers.get("x-client-cert-serial")
    dn = request.headers.get("x-client-cert-dn")
    if not (serial or dn):
        return None
    return {"edge_client_cert_serial": serial, "edge_client_cert_dn": dn}


def _quote_escape(value: str) -> str:
    """Escape a value for an RFC 7235 quoted-string auth-param.

    The ``error_description`` can contain attacker-influenced text — the token's
    unverified ``kid`` header is echoed through the JWKS-resolution error. Left
    raw, an embedded ``"`` would close the quoted-string and let the attacker
    inject additional auth-params (e.g. a rogue ``resource_metadata`` pointer)
    into the challenge. Backslash-escape ``\\`` and ``"`` per the quoted-pair
    grammar, and drop control characters (CR/LF header-splitting defense in
    depth — the ASGI server also blocks them).
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return "".join(ch for ch in escaped if ch >= " " and ch != "\x7f")


def _www_authenticate(
    error: str | None = None,
    description: str | None = None,
    resource_metadata: str | None = None,
) -> str:
    """Build the WWW-Authenticate challenge for a 401.

    Phase 1.5 (RFC 9728, REQ-1.5.4): the ``resource_metadata`` pointer tells a
    cold client where to begin the auth flow. ``error``/``error_description``
    are added on token-specific failures (expired, bad signature, bad audience).
    All interpolated values are quoted-string-escaped — some carry
    attacker-controlled token header data.
    """
    parts = ['realm="mcp"']
    if resource_metadata:
        parts.append(f'resource_metadata="{_quote_escape(resource_metadata)}"')
    if error:
        parts.append(f'error="{_quote_escape(error)}"')
    if description:
        parts.append(f'error_description="{_quote_escape(description)}"')
    return "Bearer " + ", ".join(parts)


def _tool_calls(body: bytes) -> list[tuple[str, object, object]]:
    """Return ``(tool_name, request_id, arguments)`` for each ``tools/call``.

    Returns an empty list for non-JSON bodies and for methods other than
    ``tools/call`` (initialize, tools/list, ping, notifications) — those are
    authenticated pass-throughs in Phase 1. Handles single requests and batches.
    The request id rides along so a step-up challenge can echo it in the
    JSON-RPC error object; ``arguments`` is used only to derive **value-free**
    structural audit metadata (``audit.structure``) — the values themselves are
    never stored or forwarded through this path.
    """
    if not body:
        return []
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return []

    entries = doc if isinstance(doc, list) else [doc]
    calls: list[tuple[str, object, object]] = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("method") == "tools/call":
            params = entry.get("params") or {}
            name = params.get("name")
            calls.append(
                (
                    name if isinstance(name, str) else "<unknown>",
                    entry.get("id"),
                    params.get("arguments"),
                )
            )
    return calls


def _step_up_challenge(
    request_id: object, requirement, correlation_id: str
) -> JSONResponse:
    """The RFC 9470 step-up challenge (ADR 006), carried on BOTH an HTTP 401 with
    a ``WWW-Authenticate`` header AND a JSON-RPC error object — so HTTP-aware and
    JSON-RPC-only MCP clients can each read it and re-auth. 401 (not 403): the
    token was valid, just not strong enough (``insufficient_user_authentication``).
    """
    challenge = (
        'Bearer error="insufficient_user_authentication", '
        f'acr_values="{requirement.require_acr}", max_age={requirement.max_age}'
    )
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32001,
                "message": "step-up authentication required",
                "data": {
                    "error": "insufficient_user_authentication",
                    "acr_values": requirement.require_acr,
                    "max_age": requirement.max_age,
                    "correlation_id": correlation_id,
                },
            },
        },
        status_code=401,
        headers={
            "WWW-Authenticate": challenge,
            "X-Correlation-Id": correlation_id,
        },
    )


async def _enforce(
    request: Request,
    body: bytes,
    correlation_id: str,
    policy_key: Callable[[str], str] = lambda tool: tool,
    upstream_for: Callable[[str], str | None] = lambda tool: None,
) -> tuple[Response | None, dict | None]:
    """Authenticate and (for tools/call) authorize.

    ``policy_key`` maps a wire tool name to its policy/audit key — identity in
    legacy and aggregated modes (where wire names already carry the namespace),
    a namespacing prefix for path-routed requests (Phase 3), so one namespaced
    policy file governs every route. ``upstream_for`` names the owning upstream
    for the audit record, from the same wire name.

    Returns ``(guard, claims)``:
    - ``guard`` is a 401/403 ``Response`` that short-circuits the proxy, or
      ``None`` to allow forwarding.
    - ``claims`` are the validated token claims when the request is allowed (used
      downstream to filter ``tools/list``), or ``None`` when auth is disabled or
      the request was rejected.
    """
    if not settings.auth_enabled:
        return None, None

    # The 401 challenge points cold clients at the PRM document (REQ-1.5.4);
    # build it from the request origin (or configured external base URL).
    prm_url = discovery.resource_metadata_url(str(request.base_url))

    # --- AuthN: every /mcp request needs a valid token ---
    creds = _credentials(request)
    if creds is None:
        return JSONResponse(
            {"error": "missing_token", "detail": "Authorization: Bearer <token> required"},
            status_code=401,
            headers={"WWW-Authenticate": _www_authenticate(resource_metadata=prm_url)},
        ), None
    scheme, token = creds
    try:
        claims = get_validator().validate(token)
    except TokenError as exc:
        return JSONResponse(
            {"error": exc.error, "detail": exc.description},
            status_code=401,
            headers={
                "WWW-Authenticate": _www_authenticate(
                    exc.error, exc.description, resource_metadata=prm_url
                )
            },
        ), None

    # --- DPoP: sender-constrained token binding (RFC 9449, ADR 008) ---
    # A token the AS bound to a key (cnf.jkt) must prove possession on every
    # request; a stolen token without the key dies here. Mode-gated; see config.
    try:
        dpop_jkt = dpop.enforce(
            scheme=scheme,
            access_token=token,
            claims=claims,
            proofs=request.headers.getlist("dpop"),
            method=request.method,
            accepted_htus=dpop.expected_htus(str(request.url), request.url.path),
        )
    except dpop.DpopError as exc:
        return JSONResponse(
            {"error": exc.error, "detail": exc.description},
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'DPoP algs="ES256 ES384 RS256 RS384 PS256 PS384", '
                    f'error="{_quote_escape(exc.error)}", '
                    f'error_description="{_quote_escape(exc.description)}"'
                )
            },
        ), None

    # Transport-layer identity for the audit trail: edge mTLS cert (network
    # identity) + DPoP key thumbprint (token identity). Either may be absent.
    channel: dict | None = _edge_identity(request) or {}
    if dpop_jkt:
        channel["dpop_jkt"] = dpop_jkt
    channel = channel or None

    # --- AuthZ: tool-level RBAC, only for tools/call ---
    calls = _tool_calls(body)
    if not calls:
        # Authenticated pass-through (initialize, tools/list, ping...). Claims are
        # returned so the caller can filter a tools/list response by group.
        return None, claims

    groups = claims.get("groups") or []
    policy = get_policy()

    def _evidence(tool: str, arguments: object) -> dict:
        """Per-call evidence stamps, identical on every outcome: the pinned
        manifest hash the agent saw (item 10), the value-free inputSchema
        conformance verdict (item 11), and the transport channel identity
        (ADR 008) — telemetry only, never a gate."""
        key = policy_key(tool)
        return {
            "structure": audit_structure.describe(tool, arguments),
            "manifest": audit_manifest.stamp_for(key),
            "conformance": audit_conformance.check(
                audit_manifest.input_schema_for(key), arguments
            ),
            "channel": channel,
        }

    for tool, _, arguments in calls:
        if not policy.is_allowed(groups, policy_key(tool)):
            audit.record(
                outcome="denied",
                tool=policy_key(tool),
                correlation_id=correlation_id,
                claims=claims,
                reason="tool not permitted for caller's group memberships",
                upstream=upstream_for(tool),
                **_evidence(tool, arguments),
            )
            return JSONResponse(
                {
                    "error": "forbidden",
                    "detail": f"tool '{tool}' is not permitted for your role",
                    "correlation_id": correlation_id,
                },
                status_code=403,
                headers={"X-Correlation-Id": correlation_id},
            ), None

    # --- Step-up: destructive tools need a fresh, strong auth (ADR 006) ---
    # RBAC passed; now, before forwarding, any destructive tool must carry a
    # satisfied Entra authentication context. If not, challenge and do NOT
    # forward — the token was valid, just not strong enough.
    for tool, request_id, arguments in calls:
        requirement = policy.step_up_for(policy_key(tool))
        if requirement is None:
            continue
        result = step_up.evaluate(claims, requirement)
        if not result.satisfied:
            audit.record(
                outcome="step_up_required",
                tool=policy_key(tool),
                correlation_id=correlation_id,
                claims=claims,
                reason=f"step-up not satisfied: {result.reason}",
                upstream=upstream_for(tool),
                **_evidence(tool, arguments),
            )
            return _step_up_challenge(request_id, requirement, correlation_id), None

    for tool, _, arguments in calls:
        audit.record(
            outcome="allowed",
            tool=policy_key(tool),
            correlation_id=correlation_id,
            claims=claims,
            upstream=upstream_for(tool),
            **_evidence(tool, arguments),
        )
    return None, claims


async def _proxy(request: Request, target: str) -> Response:
    """Legacy single-upstream proxy path: enforce, then forward — filtering a
    ``tools/list`` response down to the caller's permitted tools (Phase 2)."""
    body = await request.body()
    correlation_id = uuid.uuid4().hex
    guard, claims = await _enforce(request, body, correlation_id)
    if guard is not None:
        return guard
    if claims is not None and is_tools_list_request(body):
        allowed = get_policy().allowed_tools(claims.get("groups") or [])
        return await _forward_filtered(
            request, target, body, allowed,
            correlation_id=correlation_id, claims=claims,
        )
    return await _forward(request, target, body)


def _aggregated_upstream_for(tool: str) -> str | None:
    """Audit helper: the namespace prefix of an aggregated wire name, if it
    names a configured upstream."""
    parts = upstreams.split_namespaced(tool)
    return parts[0] if parts and upstreams.get_upstream(parts[0]) else None


async def _aggregated_mcp(request: Request) -> Response:
    """Aggregation mode ``/mcp`` (Phase 3): the same authN/RBAC/audit pass, then
    the virtual-server handler instead of a passthrough. Wire tool names are
    already namespaced, so they are the policy keys directly."""
    if request.method == "GET":
        return aggregator.handle_get()

    body = await request.body() if request.method == "POST" else b""
    correlation_id = uuid.uuid4().hex
    guard, claims = await _enforce(
        request, body, correlation_id, upstream_for=_aggregated_upstream_for
    )
    if guard is not None:
        return guard

    if request.method == "DELETE":
        return await aggregator.handle_delete(request, claims)
    if request.method != "POST":
        return Response(status_code=405, headers={"Allow": "GET, POST, DELETE"})

    allowed = (
        get_policy().allowed_tools(claims.get("groups") or [])
        if claims is not None
        else None  # auth disabled (plumbing checks) — serve unfiltered
    )
    return await aggregator.handle_post(request, body, claims, correlation_id, allowed)


async def _path_routed_mcp(request: Request, subpath: str) -> Response:
    """Aggregation mode ``/mcp/<name>[/...]`` (Phase 3 stage 3a): stateless
    passthrough to one named upstream. Wire tool names are the upstream's own,
    so RBAC/audit prefix them — the same namespaced policy governs both routes."""
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
    guard, claims = await _enforce(
        request,
        body,
        correlation_id,
        policy_key=lambda tool: upstreams.namespace_tool(name, tool),
        upstream_for=lambda tool: name,
    )
    if guard is not None:
        return guard
    if claims is not None and is_tools_list_request(body):
        # The upstream answers with its own (un-namespaced) tool names; project
        # the caller's namespaced allow-set down to this upstream's slice.
        namespaced = get_policy().allowed_tools(claims.get("groups") or [])
        allowed = {
            split[1]
            for split in map(upstreams.split_namespaced, namespaced)
            if split and split[0] == name
        }
        return await _forward_filtered(
            request, target, body, allowed,
            correlation_id=correlation_id, claims=claims, manifest_upstream=name,
        )
    return await _forward(request, target, body)


@app.api_route("/mcp", methods=_PROXY_METHODS)
async def proxy_mcp(request: Request) -> Response:
    if upstreams.aggregation_enabled():
        return await _aggregated_mcp(request)
    return await _proxy(request, settings.upstream_mcp_url)


@app.api_route("/mcp/{subpath:path}", methods=_PROXY_METHODS)
async def proxy_mcp_subpath(request: Request, subpath: str) -> Response:
    if upstreams.aggregation_enabled():
        return await _path_routed_mcp(request, subpath)
    return await _proxy(request, f"{settings.upstream_mcp_url}/{subpath}")


def run() -> None:
    """Console-script entry point (``mcp-auth-gateway``).

    With GATEWAY_TLS_CERTFILE set, the gateway serves TLS itself — the inner
    hop of the edge pattern (ADR 008). With ..._REQUIRE_CLIENT_CERT, only
    holders of a cert from GATEWAY_TLS_CA_CERTS (the internal CA — i.e. the
    edge proxy) can even open a connection. (The container image passes the
    equivalent uvicorn --ssl-* flags via the compose overlay instead.)
    """
    import uvicorn

    ssl_kwargs: dict = {}
    if settings.gateway_tls_certfile:
        import ssl as _ssl

        ssl_kwargs = {
            "ssl_certfile": settings.gateway_tls_certfile,
            "ssl_keyfile": settings.gateway_tls_keyfile or None,
            "ssl_ca_certs": settings.gateway_tls_ca_certs or None,
            "ssl_cert_reqs": (
                _ssl.CERT_REQUIRED
                if settings.gateway_tls_require_client_cert
                else _ssl.CERT_NONE
            ),
        }
    uvicorn.run(app, host=settings.gateway_host, port=settings.gateway_port, **ssl_kwargs)
