"""Authentication and authorization for every ``/mcp`` request.

The caller's token is validated here and never forwarded. A ``tools/call`` is
also checked against tool-level RBAC and the step-up requirements, and every
decision is written to the audit log. :func:`enforce` returns either a
short-circuit response or the validated claims.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .. import jsonrpc
from ..audit import conformance as audit_conformance
from ..audit import manifest as audit_manifest
from ..audit import structure as audit_structure
from ..audit import writer as audit
from ..config import settings
from . import discovery, dpop, step_up
from .policy_resolver import get_policy
from .token_validator import TokenError, get_validator

_DPOP_ALGS = "ES256 ES384 RS256 RS384 PS256 PS384"


def _credentials(request: Request) -> tuple[str, str] | None:
    """The ``(scheme, token)`` of a ``Bearer`` or ``DPoP`` (RFC 9449 §7.1) Authorization header."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() in ("bearer", "dpop") and token.strip():
        return scheme.lower(), token.strip()
    return None


def _edge_identity(request: Request) -> dict | None:
    """The edge proxy's forwarded client-cert identity, only when TRUST_EDGE_HEADERS is on."""
    if not settings.trust_edge_headers:
        return None
    serial = request.headers.get("x-client-cert-serial")
    dn = request.headers.get("x-client-cert-dn")
    if not (serial or dn):
        return None
    return {"edge_client_cert_serial": serial, "edge_client_cert_dn": dn}


def quote_escape(value: str) -> str:
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


def www_authenticate(
    error: str | None = None,
    description: str | None = None,
    resource_metadata: str | None = None,
) -> str:
    """Build the ``WWW-Authenticate`` challenge for a 401.

    ``resource_metadata`` points a cold client at the PRM document (RFC 9728).
    Every value is quoted-string-escaped: some carry attacker-controlled token data.
    """
    parts = ['realm="mcp"']
    if resource_metadata:
        parts.append(f'resource_metadata="{quote_escape(resource_metadata)}"')
    if error:
        parts.append(f'error="{quote_escape(error)}"')
    if description:
        parts.append(f'error_description="{quote_escape(description)}"')
    return "Bearer " + ", ".join(parts)


class _ToolCall(NamedTuple):
    tool: str
    request_id: object
    arguments: object


def _tool_calls(body: bytes) -> list[_ToolCall]:
    """One entry per ``tools/call`` in the body (single request or batch); ``[]`` otherwise.

    ``arguments`` feeds only the value-free audit structure; values are never stored."""
    if not body:
        return []
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return []

    entries = doc if isinstance(doc, list) else [doc]
    calls: list[_ToolCall] = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("method") == "tools/call":
            params = jsonrpc.params_of(entry)
            name = params.get("name")
            calls.append(
                _ToolCall(
                    name if isinstance(name, str) else "<unknown>",
                    entry.get("id"),
                    params.get("arguments"),
                )
            )
    return calls


def _step_up_challenge(request_id: object, requirement, correlation_id: str) -> JSONResponse:
    """RFC 9470 challenge on both the ``WWW-Authenticate`` header and the JSON-RPC error.

    401, not 403: the token was valid, just not strong enough."""
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


def _forbidden(tool: str, correlation_id: str) -> JSONResponse:
    return JSONResponse(
        {
            "error": "forbidden",
            "detail": f"tool '{tool}' is not permitted for your role",
            "correlation_id": correlation_id,
        },
        status_code=403,
        headers={"X-Correlation-Id": correlation_id},
    )


def _authenticate(request: Request, prm_url: str) -> tuple[str, str, dict] | JSONResponse:
    """Validate the Bearer or DPoP token; otherwise a 401 that carries the discovery pointer."""
    creds = _credentials(request)
    if creds is None:
        return JSONResponse(
            {"error": "missing_token", "detail": "Authorization: Bearer <token> required"},
            status_code=401,
            headers={"WWW-Authenticate": www_authenticate(resource_metadata=prm_url)},
        )
    scheme, token = creds
    try:
        claims = get_validator().validate(token)
    except TokenError as exc:
        return JSONResponse(
            {"error": exc.error, "detail": exc.description},
            status_code=401,
            headers={
                "WWW-Authenticate": www_authenticate(
                    exc.error, exc.description, resource_metadata=prm_url
                )
            },
        )
    return scheme, token, claims


def _bind_dpop(
    request: Request, scheme: str, token: str, claims: dict
) -> str | None | JSONResponse:
    """Apply ``DPOP_MODE``: the bound key's thumbprint, ``None`` for an allowed bearer
    token, or the 401 challenge."""
    try:
        return dpop.enforce(
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
                    f'DPoP algs="{_DPOP_ALGS}", '
                    f'error="{quote_escape(exc.error)}", '
                    f'error_description="{quote_escape(exc.description)}"'
                )
            },
        )


def _channel(request: Request, dpop_jkt: str | None) -> dict | None:
    """Transport-layer identity for the audit record: the edge mTLS cert (network
    identity) and the DPoP key thumbprint (token identity). Either may be absent."""
    channel = _edge_identity(request) or {}
    if dpop_jkt:
        channel["dpop_jkt"] = dpop_jkt
    return channel or None


@dataclass(frozen=True)
class _Caller:
    """What every authorization decision for one request is recorded with."""

    claims: dict
    channel: dict | None
    correlation_id: str
    policy_key: Callable[[str], str]
    upstream_for: Callable[[str], str | None]

    def record(self, outcome: audit.Outcome, call: _ToolCall, reason: str | None = None) -> None:
        key = self.policy_key(call.tool)
        audit.record(
            audit.AuditEvent(
                outcome=outcome,
                tool=key,
                correlation_id=self.correlation_id,
                claims=self.claims,
                reason=reason,
                upstream=self.upstream_for(call.tool),
                # The value-free evidence stamps, identical on every outcome.
                structure=audit_structure.describe(call.tool, call.arguments),
                manifest=audit_manifest.stamp_for(key),
                conformance=audit_conformance.check(
                    audit_manifest.input_schema_for(key), call.arguments
                ),
                channel=self.channel,
            )
        )


def _authorize_calls(calls: list[_ToolCall], caller: _Caller) -> Response | None:
    """RBAC, then step-up, over every call in the request.

    A denial outranks a step-up challenge, and the first failing call is the one
    recorded: a refused batch yields exactly one record, a forwarded one yields an
    ``allowed`` record per call.
    """
    policy = get_policy()
    groups = caller.claims.get("groups") or []
    for call in calls:
        if not policy.is_allowed(groups, caller.policy_key(call.tool)):
            caller.record("denied", call, "tool not permitted for caller's group memberships")
            return _forbidden(call.tool, caller.correlation_id)
    for call in calls:
        requirement = policy.step_up_for(caller.policy_key(call.tool))
        if requirement is None:
            continue
        result = step_up.evaluate(caller.claims, requirement)
        if not result.satisfied:
            caller.record("step_up_required", call, f"step-up not satisfied: {result.reason}")
            return _step_up_challenge(call.request_id, requirement, caller.correlation_id)
    for call in calls:
        caller.record("allowed", call)
    return None


async def enforce(
    request: Request,
    body: bytes,
    correlation_id: str,
    policy_key: Callable[[str], str] = lambda tool: tool,
    upstream_for: Callable[[str], str | None] = lambda _tool: None,
) -> tuple[Response | None, dict | None]:
    """Authenticate the request and, for ``tools/call``, authorize every call.

    Returns ``(guard, claims)``: a 401/403 response to return as is, or ``None`` with
    the validated claims (``None`` when auth is off). ``policy_key`` maps a wire tool
    name to its policy/audit key; ``upstream_for`` names its upstream for the record.
    """
    if not settings.auth_enabled:
        return None, None

    # The 401 challenge points cold clients at the PRM document (RFC 9728).
    prm_url = discovery.resource_metadata_url(str(request.base_url))
    authenticated = _authenticate(request, prm_url)
    if isinstance(authenticated, Response):
        return authenticated, None
    scheme, token, claims = authenticated

    # DPoP (RFC 9449): a key-bound token must prove possession on every request.
    bound = _bind_dpop(request, scheme, token, claims)
    if isinstance(bound, Response):
        return bound, None

    calls = _tool_calls(body)
    if not calls:
        # Authenticated pass-through (initialize, tools/list, ping...). Claims are
        # returned so the caller can filter a tools/list response by group.
        return None, claims

    caller = _Caller(claims, _channel(request, bound), correlation_id, policy_key, upstream_for)
    guard = _authorize_calls(calls, caller)
    return guard, (None if guard is not None else claims)


def allowed_tools(claims: dict) -> set[str]:
    """The wire tool names the caller may invoke, from the token's groups."""
    return get_policy().allowed_tools(claims.get("groups") or [])
