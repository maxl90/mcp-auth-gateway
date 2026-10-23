"""One caller cannot hold the upstream connection pool.

The forwarding routes share one pooled client with the aggregator, and a forwarded
response stays open as long as the upstream keeps it open. Each principal gets a
fixed number of requests in flight; past it the gateway answers 429 and forwards
nothing, so the rest of the pool stays free for everyone else.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from starlette.requests import ClientDisconnect

from mcp_auth_gateway import proxy
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.state import ForwardSlots

from .conftest import ANALYST_GROUP, PG_URL, UPSTREAM

_POLICY = Policy(groups={ANALYST_GROUP: ["list_schemas", "postgres__list_schemas"]})

_ROUTES = pytest.mark.parametrize(
    ("mode", "path", "target"),
    [("single", "/mcp", UPSTREAM), ("aggregate", "/mcp/postgres", PG_URL)],
    ids=["single", "path-routed"],
)

_CALL = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_schemas"}}
).encode()
_LIST = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
_OK = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "list_schemas"}]}}


@pytest.fixture
def policy() -> Policy:
    return _POLICY


def test_slots_are_counted_per_principal_and_freed_on_release():
    slots = ForwardSlots(per_principal=2)
    assert slots.acquire("a") and slots.acquire("a")
    assert not slots.acquire("a")
    assert slots.acquire("b")
    slots.release("a")
    assert slots.acquire("a")
    for principal in ("a", "a", "b"):
        slots.release(principal)
    assert slots.acquire("a") and slots.acquire("a")


@_ROUTES
def test_caller_over_their_slots_gets_429_and_others_are_still_served(
    gateway_client, policy, upstreams, make_token, mode, path, target
):
    busy = make_token(oid="busy-caller")
    other = make_token(oid="other-caller")
    with gateway_client(mode, policy, upstreams=upstreams) as c, respx.mock:
        route = respx.post(target).mock(return_value=httpx.Response(200, json=_OK))
        slots = c.app.state.gateway.forward_slots
        while slots.acquire("busy-caller"):  # responses the upstream keeps open
            pass
        refused = c.post(path, content=_CALL, headers={"Authorization": f"Bearer {busy}"})
        served = c.post(path, content=_CALL, headers={"Authorization": f"Bearer {other}"})
        audit_log = c.app.state.gateway.audit.path.read_text()
    assert refused.status_code == 429
    assert refused.json()["error"] == "too_many_requests"
    assert served.status_code == 200
    assert route.call_count == 1  # only the other caller's request was forwarded
    records = [json.loads(line) for line in audit_log.splitlines()]
    assert [r["outcome"] for r in records] == ["allowed"]  # the refusal forwarded nothing


@_ROUTES
@pytest.mark.parametrize("body", [_CALL, _LIST], ids=["streamed", "tools-list"])
def test_a_finished_forward_frees_its_slot(
    gateway_client, policy, upstreams, make_token, mode, path, target, body
):
    token = make_token()
    with gateway_client(mode, policy, upstreams=upstreams) as c, respx.mock:
        c.app.state.gateway.forward_slots.per_principal = 1
        respx.post(target).mock(return_value=httpx.Response(200, json=_OK))
        statuses = [
            c.post(path, content=body, headers={"Authorization": f"Bearer {token}"}).status_code
            for _ in range(3)
        ]
    assert statuses == [200, 200, 200]


def test_a_response_the_client_left_before_it_started_closes_upstream_and_frees_the_slot():
    """Starlette never starts the body iterator when the client is gone before the
    response starts, so the cleanup cannot live in the iterator."""

    class _Body(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b"never sent"

        async def aclose(self) -> None:
            _Body.closed = True

    released: list[bool] = []
    upstream = httpx.Response(200, stream=_Body())
    response = proxy._UpstreamStream(upstream, lambda: released.append(True))

    async def gone(_message):
        raise OSError("client disconnected")

    async def receive():
        return {"type": "http.disconnect"}

    scope = {"type": "http", "asgi": {"spec_version": "2.4"}}
    with pytest.raises(ClientDisconnect):
        asyncio.run(response(scope, receive, gone))
    assert released == [True]
    assert _Body.closed


@_ROUTES
def test_an_unreachable_upstream_frees_the_slot(
    gateway_client, policy, upstreams, make_token, mode, path, target
):
    token = make_token()
    with gateway_client(mode, policy, upstreams=upstreams) as c, respx.mock:
        c.app.state.gateway.forward_slots.per_principal = 1
        respx.post(target).mock(
            side_effect=[httpx.ConnectError("down"), httpx.Response(200, json=_OK)]
        )
        first = c.post(path, content=_CALL, headers={"Authorization": f"Bearer {token}"})
        second = c.post(path, content=_CALL, headers={"Authorization": f"Bearer {token}"})
    assert (first.status_code, second.status_code) == (502, 200)
