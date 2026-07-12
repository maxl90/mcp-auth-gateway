"""Protected Resource Metadata (RFC 9728) + discovery helpers — Phase 1.5.

The gateway is an OAuth 2.1 *resource server*. A spec-compliant MCP client that
hits a protected route cold gets a 401 whose ``WWW-Authenticate`` header points
at the Protected Resource Metadata (PRM) document served from this module; the
client reads it to learn this gateway's canonical resource identifier and which
authorization server (Entra) to obtain a token from. This is step 1 of the MCP
authorization handshake.

No governance logic lives here — this is the authentication-handshake discovery
anchor only (REQ-1.5.3/1.5.4). RBAC, audit, and step-up remain Phase 2+. The
gateway is a resource server, not an authorization server, so Dynamic Client
Registration is deliberately out of scope (that's Entra's concern).
"""

from __future__ import annotations

from ..config import settings

# RFC 9728 well-known location. Unauthenticated by design: clients fetch it
# *before* they have a token.
PRM_WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"


def build_prm_document() -> dict:
    """Return the Protected Resource Metadata document (RFC 9728).

    Values come from settings, never hardcoded. Raises :class:`RuntimeError` if
    the canonical resource URL is unset — the boot path calls this so a
    misconfigured gateway fails closed (refuses to start) rather than serving a
    resource document that can't be matched against any token audience.
    """
    resource = settings.gateway_resource_url
    if not resource:
        raise RuntimeError(
            "GATEWAY_RESOURCE_URL is required when auth is enabled: it is the "
            "canonical resource identifier published as the PRM `resource` field "
            "and the anchor the token audience is matched against (RFC 8707/9728)."
        )

    # RFC 9728 `authorization_servers` is a list of issuer *identifiers*; the
    # client derives the auth-server metadata URL from each. For Entra the
    # issuer (https://login.microsoftonline.com/<tenant>/v2.0) is that value.
    auth_server = settings.entra_auth_server_metadata_url or settings.gateway_issuer

    return {
        "resource": resource,
        "authorization_servers": [auth_server] if auth_server else [],
        "scopes_supported": list(settings.scopes_supported),
        "bearer_methods_supported": ["header"],
    }


def resource_metadata_url(request_base_url: str) -> str:
    """Absolute URL of the PRM document, for the ``resource_metadata`` pointer
    in a 401 ``WWW-Authenticate`` header (REQ-1.5.4).

    Prefers the configured external base URL (so the pointer is correct when the
    gateway sits behind a reverse proxy); otherwise uses the origin of the
    incoming request. The result must be fetchable by an external client, so we
    never build it from the ``api://`` resource URI.
    """
    base = settings.gateway_external_base_url or request_base_url
    return f"{base.rstrip('/')}{PRM_WELL_KNOWN_PATH}"
