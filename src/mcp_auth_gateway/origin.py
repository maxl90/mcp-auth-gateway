"""``Origin`` validation on the MCP routes, before authentication.

A web page can make the user's browser send requests to a gateway the browser can
reach, including one on loopback or the local network (DNS rebinding). The MCP
transport requires a server to validate ``Origin`` when present and answer 403 when
it is not acceptable. Clients that are not browsers send no ``Origin``, so a request
without one is allowed.

Acceptable origins are ``GATEWAY_EXTERNAL_BASE_URL`` and ``ALLOWED_ORIGINS``, both
configured. The request's own ``Host`` is never one of them: under DNS rebinding the
attacker's name is in both ``Origin`` and ``Host``, so deriving the gateway's origin
from the request would accept exactly the request this check exists to refuse.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse

from .config import settings

logger = logging.getLogger("mcp_auth_gateway")

_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_LOGGED = 200


def _origin(value: str, *, path_allowed: bool) -> str | None:
    """``scheme://host[:port]`` in comparison form, or ``None`` when ``value`` is not an
    http(s) origin. Host is lowercased and a default port dropped, as browsers send it."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if scheme not in _DEFAULT_PORTS or not host or parts.username or parts.password:
        return None
    if not path_allowed and (parts.path not in ("", "/") or parts.query or parts.fragment):
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _acceptable() -> set[str]:
    configured = [settings.gateway_external_base_url, *settings.allowed_origins]
    return {o for c in configured if c and (o := _origin(c, path_allowed=True)) is not None}


def refuse(request: Request) -> JSONResponse | None:
    """The 403 for an unacceptable ``Origin``, or ``None`` when the request may go on.

    No audit record: like a 401, this is decided before the caller is known."""
    header = request.headers.get("origin")
    if header is None:
        return None
    if _origin(header, path_allowed=False) in _acceptable():
        return None
    logger.warning("origin refused: %r on %s", header[:_MAX_LOGGED], request.url.path)
    return JSONResponse(
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "origin not allowed"}},
        status_code=403,
    )
