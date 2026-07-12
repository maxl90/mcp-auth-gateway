"""The session registry: one client session ↔ N upstream sessions.

This is the state that makes the aggregator a *stateful* MCP server (ADR 004
records where that state may live: in-memory now; a Redis-style KV holding only
id-mappings if multi-replica HA ever forces it — never tokens or arguments).

The registry is deliberately an **interface** (ADR 005 gate 7): v1 binds one
set of upstream sessions per client session (eager, M×N), but routing code only
ever talks to the interface, so a pooled/lazy implementation — multiplexing
many users over a few upstream sessions, viable because the user token
terminates at the gateway — can replace it without touching the handler.

It also carries the caller's Entra ``oid`` per session: that is the hook the
SCIM stretch goal needs to kill all of a deprovisioned user's sessions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class UpstreamSession:
    """The gateway's session with one upstream. ``session_id`` is the upstream's
    ``Mcp-Session-Id`` (some servers run stateless and issue none)."""

    upstream: str
    url: str
    session_id: str | None = None
    alive: bool = True


@dataclass
class RouteEntry:
    """Where a namespaced tool lives: the owning upstream + its original name."""

    upstream: str
    tool: str


@dataclass
class ClientSession:
    """One MCP client's session with the gateway."""

    id: str
    oid: str | None  # caller's Entra object id — the SCIM kill-switch key
    upstreams: dict[str, UpstreamSession] = field(default_factory=dict)
    routes: dict[str, RouteEntry] = field(default_factory=dict)  # namespaced -> owner


class SessionRegistry(Protocol):
    """What routing code may assume about session storage — nothing more."""

    def create(self, oid: str | None) -> ClientSession: ...

    def get(self, session_id: str) -> ClientSession | None: ...

    def delete(self, session_id: str) -> ClientSession | None: ...

    def sessions_for_oid(self, oid: str) -> list[ClientSession]: ...


class InMemorySessionRegistry:
    """v1: plain dict, single replica (ADR 004/005). Sessions die with the
    process; clients transparently re-``initialize`` — tokens are client-held,
    so a restart never costs re-authentication."""

    def __init__(self) -> None:
        self._sessions: dict[str, ClientSession] = {}

    def create(self, oid: str | None) -> ClientSession:
        session = ClientSession(id=uuid.uuid4().hex, oid=oid)
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> ClientSession | None:
        return self._sessions.get(session_id)

    def delete(self, session_id: str) -> ClientSession | None:
        return self._sessions.pop(session_id, None)

    def sessions_for_oid(self, oid: str) -> list[ClientSession]:
        return [s for s in self._sessions.values() if s.oid == oid]


_registry: SessionRegistry | None = None


def get_registry() -> SessionRegistry:
    """Process-wide registry, one per gateway process."""
    global _registry
    if _registry is None:
        _registry = InMemorySessionRegistry()
    return _registry
