"""Session registry bounds: a per-principal cap and idle eviction."""

from __future__ import annotations

from mcp_auth_gateway.aggregator.registry import InMemorySessionRegistry


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_per_principal_cap_evicts_the_least_recently_used():
    clock = _Clock()
    reg = InMemorySessionRegistry(max_sessions_per_principal=3, clock=clock)
    first = reg.create("alice")
    others = []
    for _ in range(2):
        clock.now += 1
        others.append(reg.create("alice"))
    bob = reg.create("bob")
    assert reg.pop_evicted() == []

    clock.now += 1
    newest = reg.create("alice")
    assert reg.get(first.id) is None
    assert all(reg.get(s.id) is not None for s in [*others, bob, newest])
    assert [s.id for s in reg.pop_evicted()] == [first.id]


def test_a_recently_used_session_outlives_an_older_idle_one():
    clock = _Clock()
    reg = InMemorySessionRegistry(max_sessions_per_principal=2, clock=clock)
    a = reg.create("alice")
    clock.now += 1
    b = reg.create("alice")
    clock.now += 1
    reg.get(a.id)  # a is now the most recently used
    clock.now += 1
    reg.create("alice")
    assert reg.get(a.id) is not None
    assert reg.get(b.id) is None


def test_idle_sessions_are_evicted_on_the_next_create():
    clock = _Clock()
    reg = InMemorySessionRegistry(idle_ttl=60, clock=clock)
    idle = reg.create("alice")
    clock.now += 61
    fresh = reg.create("bob")
    assert reg.get(idle.id) is None
    assert reg.get(fresh.id) is not None
    assert [s.id for s in reg.pop_evicted()] == [idle.id]
