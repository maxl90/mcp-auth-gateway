"""The forwarding routes enforce on the message the upstream receives.

Enforcement parses the body; the upstream parses it again. A body two parsers can
read differently (a duplicate key, a key in another case, bytes that are not UTF-8
JSON, a compressed body) would let a call be checked as one thing and run as
another, so ``/mcp`` (single mode) and ``/mcp/<name>`` refuse it, and forward the
gateway's own re-serialization of what it checked.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_auth_gateway.auth.policy_resolver import Policy

from .conftest import ANALYST_GROUP, PG_URL, UPSTREAM

# list_schemas is permitted on both routes (path routing namespaces it); execute_sql
# is permitted on neither.
_POLICY = Policy(groups={ANALYST_GROUP: ["list_schemas", "postgres__list_schemas"]})

_ROUTES = pytest.mark.parametrize(
    ("mode", "path", "target"),
    [("single", "/mcp", UPSTREAM), ("aggregate", "/mcp/postgres", PG_URL)],
    ids=["single", "path-routed"],
)


@pytest.fixture
def policy() -> Policy:
    return _POLICY


def _post(gateway_client, policy, upstreams, mode, path, target, body, headers):
    with gateway_client(mode, policy, upstreams=upstreams) as c, respx.mock:
        route = respx.post(target).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        resp = c.post(path, content=body, headers=headers)
    return resp, route


_UNREADABLE = {
    "not-json": b"tools/call execute_sql",
    "invalid-utf8": (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"execute_sql","arguments":{"q":"\xff"}}}'
    ),
    "duplicate-name": (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"execute_sql","name":"list_schemas"}}'
    ),
    "duplicate-method": (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping",'
        b'"params":{"name":"execute_sql"}}'
    ),
    "method-in-another-case": (
        b'{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"execute_sql"}}'
    ),
    "batch-entry-in-another-case": (
        b'[{"jsonrpc":"2.0","id":1,"method":"ping"},'
        b'{"jsonrpc":"2.0","id":2,"METHOD":"tools/call","params":{"name":"execute_sql"}}]'
    ),
    "nan": b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
    "lone-surrogate": (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"list_schemas","arguments":{"q":"\\ud800"}}}'
    ),
    "utf16": json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_sql"}}
    ).encode("utf-16"),
}


@_ROUTES
@pytest.mark.parametrize("body", _UNREADABLE.values(), ids=_UNREADABLE.keys())
def test_body_two_parsers_could_read_differently_is_refused(
    gateway_client, policy, upstreams, make_token, mode, path, target, body
):
    token = make_token(groups=[ANALYST_GROUP])
    resp, route = _post(
        gateway_client,
        policy,
        upstreams,
        mode,
        path,
        target,
        body,
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert route.call_count == 0


@_ROUTES
@pytest.mark.parametrize("encoding", ["gzip", "identity, gzip"])
def test_content_encoded_body_is_refused(
    gateway_client, policy, upstreams, make_token, mode, path, target, encoding
):
    token = make_token(groups=[ANALYST_GROUP])
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    resp, route = _post(
        gateway_client,
        policy,
        upstreams,
        mode,
        path,
        target,
        body,
        {"Authorization": f"Bearer {token}", "Content-Encoding": encoding},
    )
    assert resp.status_code == 415
    assert resp.json()["error"] == "unsupported_content_encoding"
    assert route.call_count == 0


@_ROUTES
def test_unreadable_body_from_an_unauthenticated_caller_is_still_401(
    gateway_client, policy, upstreams, mode, path, target
):
    resp, route = _post(gateway_client, policy, upstreams, mode, path, target, b"not json", {})
    assert resp.status_code == 401
    assert route.call_count == 0


@_ROUTES
def test_permitted_call_forwards_the_gateways_serialization(
    gateway_client, policy, upstreams, make_token, mode, path, target
):
    token = make_token(groups=[ANALYST_GROUP])
    body = (
        b'{ "jsonrpc" : "2.0", "id" : 1, "method" : "tools/call",\n'
        b'  "params" : { "name" : "list_schemas", "arguments" : { "q" : "caf\\u00e9" } } }'
    )
    resp, route = _post(
        gateway_client,
        policy,
        upstreams,
        mode,
        path,
        target,
        body,
        {"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert (
        route.calls.last.request.content
        == (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            '"params":{"name":"list_schemas","arguments":{"q":"café"}}}'
        ).encode()
    )


@_ROUTES
def test_tool_arguments_may_use_keys_that_differ_only_in_case(
    gateway_client, policy, upstreams, make_token, mode, path, target
):
    """Only the JSON-RPC members and the tools/call params the gateway authorizes on
    must be unambiguous; argument values are the tool's business."""
    token = make_token(groups=[ANALYST_GROUP])
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_schemas", "arguments": {"Name": "a", "name": "b"}},
    }
    resp, route = _post(
        gateway_client,
        policy,
        upstreams,
        mode,
        path,
        target,
        json.dumps(call).encode(),
        {"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert json.loads(route.calls.last.request.content) == call
