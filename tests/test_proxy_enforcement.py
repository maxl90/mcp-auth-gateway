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

from mcp_auth_gateway import proxy
from mcp_auth_gateway.auth.policy_resolver import Policy, StepUpRequirement

from .conftest import ANALYST_GROUP, DENIED_GROUP, UPSTREAM
from .fakes import CutOffStream

_POLICY = Policy(
    groups={ANALYST_GROUP: ["list_schemas", "execute_sql"], DENIED_GROUP: []},
    destructive={"execute_sql": StepUpRequirement("c1", 300)},
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


def test_invalid_token_is_401(legacy_client):
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


def test_upstream_date_and_server_headers_are_not_relayed(legacy_client, make_token):
    """The gateway's own server sets date and server; relaying the upstream's
    copies produced two of each. Session and other headers still pass."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {}},
                headers={
                    "date": "Mon, 01 Jan 2024 00:00:00 GMT",
                    "server": "upstream/9",
                    "mcp-session-id": "abc123",
                    "x-upstream-extra": "kept",
                },
            )
        )
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call("list_schemas"),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert "01 Jan 2024" not in resp.headers.get("date", "")
    assert resp.headers.get("server") != "upstream/9"
    assert resp.headers["mcp-session-id"] == "abc123"
    assert resp.headers["x-upstream-extra"] == "kept"


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


def test_credentials_and_client_forwarding_headers_stay_at_the_gateway(legacy_client, make_token):
    """The gateway terminates the caller's credentials and is the client the upstream
    sees: no token, proof or cookie, and no client-chosen forwarding or edge-identity
    header, reaches the upstream."""
    token = make_token(groups=[ANALYST_GROUP])
    terminated = {
        "DPoP": "a-proof",
        "Cookie": "sid=abc",
        "Forwarded": "for=1.2.3.4",
        "X-Forwarded-For": "1.2.3.4",
        "X-Forwarded-Host": "evil.example",
        "X-Real-IP": "1.2.3.4",
        "X-Client-Cert-Serial": "SPOOF",
        "X-Client-Cert-DN": "CN=spoof",
    }
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call("list_schemas"),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": "s-1", **terminated},
        )
    assert resp.status_code == 200
    sent = {k.lower() for k in route.calls.last.request.headers}
    assert sent.isdisjoint({"authorization", *(h.lower() for h in terminated)})
    assert "mcp-session-id" in sent  # the MCP session still reaches its server


def test_headers_the_connection_field_names_stop_at_the_gateway(legacy_client, make_token):
    # RFC 9110 7.6.1: a header the Connection field lists is for this hop only, so it
    # is not forwarded in either direction.
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {}},
                headers={"Connection": "X-Upstream-Hop", "X-Upstream-Hop": "1", "X-Kept": "1"},
            )
        )
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call("list_schemas"),
            headers={
                "Authorization": f"Bearer {token}",
                "Connection": "x-client-hop, keep-alive",
                "X-Client-Hop": "1",
                "X-Client-Extra": "kept",
            },
        )
    assert resp.status_code == 200
    sent = {k.lower() for k in route.calls.last.request.headers}
    assert "x-client-hop" not in sent
    assert "x-client-extra" in sent
    assert "x-upstream-hop" not in resp.headers
    assert resp.headers["x-kept"] == "1"


def test_subpath_forwards_under_the_upstream_endpoint(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.post(f"{UPSTREAM}/sub").mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp/sub", content=b"{}", headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 200
    assert route.call_count == 1


@pytest.mark.parametrize(
    "path",
    [
        "/mcp/..%2Fadmin",
        "/mcp/.%2F..%2Fadmin",
        "/mcp/x%3Fadmin=1",
        "/mcp/x%23frag",
        "/mcp/..;/admin",  # a path parameter some servers strip before resolving
        "/mcp/..%5Cadmin",  # a backslash some servers treat as a separator
        "/mcp/a%01b",  # a control character httpx refuses to put in a URL
    ],
)
def test_subpath_cannot_leave_the_upstream_endpoint(legacy_client, make_token, path):
    """Starlette hands the route a percent-decoded subpath: ``..%2F`` arrives as ``../``
    and ``%3F`` as ``?``. No form of it may steer the upstream request off its endpoint."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.route(host="localhost").mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(path, content=b"{}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404
    assert route.call_count == 0


@pytest.mark.parametrize(
    ("subpath", "safe"),
    [
        ("postgres", True),
        ("postgres/sub/path", True),
        ("access_as_user", True),
        ("a-b_c.d~e/", True),
        ("", True),
        # What uvicorn hands the route for /mcp/%252e%252e/admin: one decode, so the
        # upstream (or a proxy in front of it) would decode %2e%2e to .. again.
        ("%2e%2e/admin", False),
        ("../admin", False),
        ("x/./y", False),
        ("..;/admin", False),
        ("..\\admin", False),
        ("a\x01b", False),
        ("x?y=1", False),
        ("x#y", False),
    ],
)
def test_safe_subpath_allows_only_unreserved_segments(subpath, safe):
    assert proxy.is_safe_subpath(subpath) is safe


@pytest.mark.parametrize(
    ("mode", "path"), [("single", "/mcp"), ("aggregate", "/mcp"), ("aggregate", "/mcp/postgres")]
)
def test_request_body_is_capped_before_authentication(
    gateway_client, policy, upstreams, mode, path
):
    """The body is read before the token is checked, so the cap is what bounds the
    memory an unauthenticated client can make the gateway hold."""
    with gateway_client(mode, policy, upstreams=upstreams, max_upstream_response_bytes=64) as c:
        over = c.post(path, content=b"x" * 65)
        at_cap = c.post(path, content=b"x" * 64)
    assert over.status_code == 413
    assert over.json()["error"] == "request_too_large"
    assert at_cap.status_code == 401  # within the cap, authentication runs as before


def test_request_body_cap_of_zero_means_unlimited(gateway_client, policy):
    with gateway_client("single", policy, max_upstream_response_bytes=0) as c:
        resp = c.post("/mcp", content=b"x" * 100_000)
    assert resp.status_code == 401


@pytest.mark.parametrize("error", [httpx.ConnectTimeout("slow"), httpx.ReadTimeout("hung")])
@pytest.mark.parametrize("method", ["tools/call", "tools/list"])
def test_upstream_transport_failure_is_502_not_500(legacy_client, make_token, error, method):
    """A timeout is not a ConnectError; every transport failure must answer the same 502."""
    token = make_token(groups=[ANALYST_GROUP])
    params = {"name": "list_schemas"} if method == "tools/call" else None
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with respx.mock:
        respx.post(UPSTREAM).mock(side_effect=error)
        resp = legacy_client.post(
            "/mcp", content=body, headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 502
    assert resp.json()["error"] == "upstream_unreachable"


def test_upstream_cut_off_while_tools_list_is_buffered_is_502(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/json"}, stream=CutOffStream()
            )
        )
        resp = legacy_client.post(
            "/mcp", content=body, headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 502
    assert resp.json()["error"] == "upstream_response_incomplete"


def test_group_overage_is_denied_with_a_reason_that_names_it(legacy_client, make_token, tmp_path):
    """Entra drops ``groups`` for a ``_claim_names`` pointer when a user is in too many
    groups. The policy then sees none: deny, and say why in the record."""
    token = make_token(
        groups=None,
        _claim_names={"groups": "src1"},
        _claim_sources={
            "src1": {"endpoint": "https://graph.microsoft.com/v1.0/me/getMemberObjects"}
        },
    )
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp",
            content=_tools_call("list_schemas"),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 403
    assert route.call_count == 0
    record = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert record["outcome"] == "denied"
    assert "overage" in record["reason"]


def test_non_list_groups_claim_grants_nothing(legacy_client, make_token):
    token = make_token(groups=ANALYST_GROUP)  # a bare string, not a list of ids
    resp = legacy_client.post(
        "/mcp", content=_tools_call("list_schemas"), headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
