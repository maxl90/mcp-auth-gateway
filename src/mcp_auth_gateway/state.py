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


class ForwardSlots:
    """Upstream requests in flight per principal on the forwarding routes.

    Those routes share one connection pool, and a forwarded response stays open as
    long as the upstream keeps it open, so without a cap one caller could hold every
    connection. A principal's entry goes when its last request finishes."""

    def __init__(self, per_principal: int = 16) -> None:
        self.per_principal = per_principal
        self._in_flight: dict[str, int] = {}

    def acquire(self, principal: str) -> bool:
        """Take a slot; False when the principal already holds ``per_principal``."""
        held = self._in_flight.get(principal, 0)
        if held >= self.per_principal:
            return False
        self._in_flight[principal] = held + 1
        return True

    def release(self, principal: str) -> None:
        held = self._in_flight.get(principal, 0) - 1
        if held > 0:
            self._in_flight[principal] = held
        else:
            self._in_flight.pop(principal, None)


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
    forward_slots: ForwardSlots = field(default_factory=ForwardSlots)


def of(request: Request) -> Gateway:
    """The state of the app serving ``request``."""
    gateway: Gateway = request.app.state.gateway
    return gateway
