"""What the gateway holds for its lifetime, built once at startup.

The app's lifespan builds one :class:`Gateway` and keeps it on ``app.state``;
request handlers reach it through :func:`of`. None of it is a module global, so
each app starts from its own; the settings it is built from stay process-wide.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from fastapi import Request

from .aggregator.registry import InMemorySessionRegistry
from .audit.manifest import ManifestBaseline
from .audit.writer import AuditLog
from .auth.dpop import ReplayCache
from .auth.policy_resolver import Policy
from .auth.token_validator import TokenValidator
from .upstreams import Upstream


@dataclass(frozen=True)
class Auth:
    """Token validation and RBAC. Absent when ``AUTH_ENABLED`` is off."""

    validator: TokenValidator
    policy: Policy


@dataclass
class Gateway:
    client: httpx.AsyncClient  # pooled, for every upstream request
    audit: AuditLog
    manifests: ManifestBaseline
    auth: Auth | None
    upstreams: dict[str, Upstream]  # by name, in config order; empty unless aggregating
    sessions: InMemorySessionRegistry = field(default_factory=InMemorySessionRegistry)
    replay: ReplayCache = field(default_factory=ReplayCache)


def of(request: Request) -> Gateway:
    """The state of the app serving ``request``."""
    gateway: Gateway = request.app.state.gateway
    return gateway
