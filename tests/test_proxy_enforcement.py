"""End-to-end proxy path: AuthN + RBAC + audit + token termination.

Uses respx to stand in for the upstream MCP server, and injects a validator
backed by an in-process RSA key (see conftest), so the real enforcement code
runs without Entra or a live upstream.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_auth_gateway.auth.policy_resolver import Policy

from .conftest import ANALYST_GROUP, DENIED_GROUP

UPSTREAM = "http://localhost:9000/mcp"

_POLICY = Policy(
    groups={ANALYST_GROUP: ["list_schemas", "execute_sql"], DENIED_GROUP: []},
    destructive=["execute_sql"],
)


@pytest.fixture
def policy() -> Policy:
    return _POLICY


def _tools_call(name: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name}}
    ).encode()


def test_missing_token_is_401_with_challenge(legacy_client):
    resp = legacy_client.post("/mcp", content=_tools_call("execute_sql"))
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert challenge.startswith('Bearer realm="mcp"')
    # The challenge points cold clients at the PRM doc (RFC 9728).
    assert 'resource_metadata="' in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


def test_invalid_token_is_401(legacy_client, make_token):
    resp = legacy_client.post(
        "/mcp",
        content=_tools_call("execute_sql"),
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate", "")
    assert "invalid_token" in challenge
    # Token-specific 401s still carry the discovery pointer.
    assert "/.well-known/oauth-protected-resource" in challenge


def test_denied_tool_is_403_and_never_forwarded(legacy_client, make_token):
    token = make_token(groups=[DENIED_GROUP])
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call("execute_sql"),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 403
    assert route.call_count == 0  # request never reached the upstream
    assert "X-Correlation-Id" in resp.headers


def test_allowed_tool_forwards_with_token_stripped(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call(
                "list_schemas"
            ),  # allowed + non-destructive (step-up is a separate test)
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert route.call_count == 1
    # The trust boundary: the user's token must NOT be forwarded upstream.
    forwarded = route.calls.last.request
    assert "authorization" not in {k.lower() for k in forwarded.headers}


def test_non_toolcall_is_authenticated_passthrough(legacy_client, make_token):
    """initialize carries a valid token but is not a tools/call — it forwards
    without an RBAC check."""
    token = make_token(groups=[DENIED_GROUP])  # even a denied user can initialize
    init = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}).encode()
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp", content=init, headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 200
    assert route.call_count == 1


def test_audit_line_written_for_allow_and_deny(legacy_client, make_token, tmp_path):
    log = tmp_path / "audit.log"
    with respx.mock:
        respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        legacy_client.post(
            "/mcp",
            content=_tools_call("list_schemas"),  # allowed + non-destructive → "allowed"
            headers={"Authorization": f"Bearer {make_token(groups=[ANALYST_GROUP])}"},
        )
        legacy_client.post(
            "/mcp",
            content=_tools_call("execute_sql"),  # denied by RBAC before step-up is reached
            headers={"Authorization": f"Bearer {make_token(groups=[DENIED_GROUP])}"},
        )
    outcomes = [json.loads(line)["outcome"] for line in log.read_text().splitlines()]
    assert outcomes == ["allowed", "denied"]


def test_tools_call_with_non_object_params_is_denied_not_an_error(legacy_client, make_token):
    """A list where the params object belongs cannot name a tool, so RBAC denies it
    like any unknown tool instead of the request failing inside the gateway."""
    token = make_token(groups=[ANALYST_GROUP])
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["x"]}).encode()
    resp = legacy_client.post("/mcp", content=body, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
