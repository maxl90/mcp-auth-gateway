"""Protected Resource Metadata (RFC 9728): how a cold client finds the authorization server.

The gateway is an OAuth 2.1 resource server. An unauthenticated request gets a
401 whose ``WWW-Authenticate`` header points at the PRM document served here; the
client reads the gateway's resource identifier and authorization server from it.
Dynamic Client Registration is out of scope: Entra, not the gateway, is the AS.
"""

from __future__ import annotations

from typing import Any

from ..config import settings

# RFC 9728 well-known location. Unauthenticated by design: clients fetch it
# *before* they have a token.
PRM_WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"


def build_prm_document() -> dict[str, Any]:
    """The PRM document (RFC 9728), built from settings.

    Raises :class:`RuntimeError` when ``GATEWAY_RESOURCE_URL`` is unset; the boot
    path calls this so a misconfigured gateway refuses to start.
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
    """Absolute URL of the PRM document for a 401's ``resource_metadata`` pointer.

    Uses the configured external base URL when set (correct behind a reverse proxy),
    else the request origin. Never built from the ``api://`` resource URI.
    """
    base = settings.gateway_external_base_url or request_base_url
    return f"{base.rstrip('/')}{PRM_WELL_KNOWN_PATH}"
