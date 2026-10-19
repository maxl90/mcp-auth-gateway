"""mcp-auth-gateway: an OAuth 2.1 reverse proxy for MCP servers.

Every ``/mcp`` request must carry a valid Entra ID token; a ``tools/call`` is
also checked against tool-level RBAC and step-up requirements, and every tool
invocation produces an argument-free audit record. The gateway terminates the
token: it is validated locally and stripped before anything is forwarded, so the
token and the raw arguments never leave the gateway.
"""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import proxy
from .aggregator import handler as aggregator
from .audit.manifest import ManifestBaseline
from .audit.writer import AuditLog
from .auth import discovery
from .auth.policy_resolver import Policy, load_policy
from .auth.token_validator import TokenValidator
from .config import settings
from .state import Auth, Gateway
from .upstreams import Upstream, aggregation_enabled, load_upstreams

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

router = APIRouter()


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Liveness and mode only: upstream addresses stay off an unauthenticated route."""
    mode = "aggregate" if aggregation_enabled() else "single"
    return JSONResponse({"status": "ok", "mode": mode})


@router.get(discovery.PRM_WELL_KNOWN_PATH)
async def protected_resource_metadata() -> Response:
    """Protected Resource Metadata (RFC 9728): the unauthenticated discovery anchor a
    cold client reads to learn the resource identifier and authorization server.
    404 when no resource URL is configured (auth off)."""
    try:
        return JSONResponse(discovery.build_prm_document())
    except RuntimeError:
        return JSONResponse({"error": "not_configured"}, status_code=404)


@router.api_route("/mcp", methods=_PROXY_METHODS)
async def proxy_mcp(request: Request) -> Response:
    if aggregation_enabled():
        return await aggregator.handle_mcp(request)
    return await proxy.single_upstream(request, settings.upstream_mcp_url)


@router.api_route("/mcp/{subpath:path}", methods=_PROXY_METHODS)
async def proxy_mcp_subpath(request: Request, subpath: str) -> Response:
    if not proxy.is_safe_subpath(subpath):
        return JSONResponse(
            {"error": "invalid_path", "detail": "path segments allow only A-Z a-z 0-9 - . _ ~"},
            status_code=404,
        )
    if aggregation_enabled():
        return await proxy.path_routed(request, subpath)
    return await proxy.single_upstream(request, f"{settings.upstream_mcp_url}/{subpath}")


def create_app(
    *,
    validator: TokenValidator | None = None,
    policy: Policy | None = None,
    upstreams: list[Upstream] | None = None,
) -> FastAPI:
    """The gateway app. Settings still decide what it needs (``AUTH_ENABLED``,
    ``UPSTREAMS_CONFIG_PATH``) and which mode serves each request. A part passed in
    replaces the one startup would load, and is unused when settings do not call for
    it; the module-level ``app`` loads every part from settings."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Fail closed at boot: if auth is on, build the validator and load the policy
        # now so a misconfigured gateway refuses to start rather than 500-ing (or,
        # worse, silently mis-enforcing) on the first request.
        auth: Auth | None = None
        if settings.auth_enabled:
            auth = Auth(
                validator if validator is not None else TokenValidator(),
                policy if policy is not None else load_policy(),
            )
            # Validate the resource-server config now so a gateway missing
            # GATEWAY_RESOURCE_URL refuses to start rather than serving a 401 whose
            # discovery pointer leads to an unconfigured PRM document.
            discovery.build_prm_document()
        # In aggregation mode a bad upstreams.yaml must also refuse to
        # start — an aggregator that can't tell its upstreams apart mis-routes.
        configured: list[Upstream] = []
        if aggregation_enabled():
            configured = upstreams if upstreams is not None else load_upstreams()
        audit_log = AuditLog(settings.audit_log_path)

        # One pooled client for the process. No read timeout: MCP responses can be
        # long-lived SSE streams. Only the connect attempt is bounded.
        timeout = httpx.Timeout(10.0, read=None)
        async with httpx.AsyncClient(timeout=timeout) as client:
            app.state.gateway = Gateway(
                client=client,
                audit=audit_log,
                manifests=ManifestBaseline(settings.manifest_baseline_path, audit_log),
                auth=auth,
                upstreams={u.name: u for u in configured},
            )
            yield

    app = FastAPI(title="mcp-auth-gateway", lifespan=lifespan)
    app.include_router(router)
    return app


app = create_app()


def run() -> None:
    """Console-script entry point (``mcp-auth-gateway``).

    With ``GATEWAY_TLS_CERTFILE`` set the gateway serves TLS itself, and with
    ``GATEWAY_TLS_REQUIRE_CLIENT_CERT`` only holders of a cert from
    ``GATEWAY_TLS_CA_CERTS`` (the edge proxy) can open a connection.
    """
    ssl_kwargs: dict[str, Any] = {}
    if settings.gateway_tls_certfile:
        ssl_kwargs = {
            "ssl_certfile": settings.gateway_tls_certfile,
            "ssl_keyfile": settings.gateway_tls_keyfile or None,
            "ssl_ca_certs": settings.gateway_tls_ca_certs or None,
            "ssl_cert_reqs": (
                ssl.CERT_REQUIRED if settings.gateway_tls_require_client_cert else ssl.CERT_NONE
            ),
        }
    uvicorn.run(app, host=settings.gateway_host, port=settings.gateway_port, **ssl_kwargs)
