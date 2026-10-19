"""The session registry: one client session, N upstream sessions.

This is the state that makes the aggregator a stateful MCP server. It lives in
memory, in one process: sessions die with the process and clients re-``initialize``
(tokens are client-held, so no re-authentication). Each session remembers the
principal that created it; it is only ever reused by that caller.
"""

from __future__ import annotations

import itertools
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ..upstreams import Upstream


@dataclass
class UpstreamSession:
    """The gateway's session with one upstream. ``session_id`` is the upstream's
    ``Mcp-Session-Id`` (some servers run stateless and issue none)."""

    session_id: str | None = None
    # ``initialize`` is request 0; every later request takes the next id.
    _request_ids: Iterator[int] = field(
        default_factory=lambda: itertools.count(1), repr=False, compare=False
    )

    def next_request_id(self) -> int:
        """A JSON-RPC id no other request on this session has used. A stateful
        upstream keys each pending response by its request id, so two in-flight
        requests that share one get a single answer between them."""
        return next(self._request_ids)


@dataclass
class RouteEntry:
    """Where a namespaced tool lives: the owning upstream + its original name."""

    upstream: Upstream
    tool: str


@dataclass
class ClientSession:
    """One MCP client's session with the gateway."""

    id: str
    principal: str | None  # who created it; reuse by anyone else is refused
    upstreams: dict[str, UpstreamSession] = field(default_factory=dict)
    routes: dict[str, RouteEntry] = field(default_factory=dict)  # namespaced -> owner
    last_seen: float = 0.0  # registry clock; drives idle eviction


class InMemorySessionRegistry:
    """A plain dict for a single process. Sessions die with it; clients re-``initialize``.

    Two bounds keep one caller from exhausting memory and upstream sessions by
    looping ``initialize``: at most ``max_sessions_per_principal`` live sessions
    per principal (the least recently used goes), and sessions idle longer than
    ``idle_ttl`` seconds are dropped on the next ``create``. Evicted sessions are
    handed back through :meth:`pop_evicted` so the caller can tear down their
    upstream sessions.
    """

    def __init__(
        self,
        *,
        max_sessions_per_principal: int = 16,
        idle_ttl: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sessions: dict[str, ClientSession] = {}
        self._evicted: list[ClientSession] = []
        self.max_sessions_per_principal = max_sessions_per_principal
        self.idle_ttl = idle_ttl
        self._clock = clock

    def create(self, principal: str | None) -> ClientSession:
        now = self._clock()
        self._evict(lambda s: now - s.last_seen > self.idle_ttl)
        mine = sorted(
            (s for s in self._sessions.values() if s.principal == principal),
            key=lambda s: s.last_seen,
        )
        excess = len(mine) - self.max_sessions_per_principal + 1
        for stale in mine[: max(excess, 0)]:
            self._evicted.append(self._sessions.pop(stale.id))
        session = ClientSession(id=uuid.uuid4().hex, principal=principal, last_seen=now)
        self._sessions[session.id] = session
        return session

    def _evict(self, is_stale: Callable[[ClientSession], bool]) -> None:
        for session_id in [sid for sid, s in self._sessions.items() if is_stale(s)]:
            self._evicted.append(self._sessions.pop(session_id))

    def get(self, session_id: str) -> ClientSession | None:
        session = self._sessions.get(session_id)
        if session is not None:
            session.last_seen = self._clock()
        return session

    def delete(self, session_id: str) -> ClientSession | None:
        return self._sessions.pop(session_id, None)

    def pop_evicted(self) -> list[ClientSession]:
        evicted, self._evicted = self._evicted, []
        return evicted
