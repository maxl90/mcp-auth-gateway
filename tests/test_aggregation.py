"""Phase 3 stage 3b: the aggregated ``/mcp`` virtual server, end to end.

Two respx-faked upstreams (postgres-ish and github-ish) behind the real
gateway app: gateway-answered ``initialize`` with eager upstream init, merged
+ namespaced + RBAC-filtered ``tools/list``, ``tools/call`` routing with the
original tool name restored, fail-closed calls to dead upstreams, audited
partial catalogs, cascade teardown — and the trust boundary (no caller token
ever reaches an upstream).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway import upstreams as upstreams_mod
from mcp_auth_gateway.aggregator import registry as registry_mod
from mcp_auth_gateway.aggregator.registry import InMemorySessionRegistry
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.upstreams import Upstream

from .conftest import ANALYST_GROUP, DENIED_GROUP, ISSUER, RESOURCE_URL

PG_URL = "http://pg-upstream:9000/mcp"
GH_URL = "http://gh-upstream:9001/mcp"

PG_TOOLS = ["execute_sql", "list_schemas"]
GH_TOOLS = ["list_issues", "merge_pull_request"]

# One namespaced policy spanning both upstreams (ADR 005 gate 2). The analyst
# sees a cross-upstream slice; readonly sees only github reads.
_POLICY = Policy(
    groups={
        ANALYST_GROUP: [
            "postgres__execute_sql",
            "postgres__list_schemas",
            "github__list_issues",
        ],
        DENIED_GROUP: ["github__list_issues"],
    },
    destructive=["postgres__execute_sql", "github__merge_pull_request"],
)


def fake_upstream(name: str, tools: list[str], session_id: str, *, sse: bool = False):
    """A minimal Streamable HTTP MCP server as a respx side-effect."""

    def responder(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in {k.lower() for k in request.headers}, (
            "trust boundary violated: caller token reached an upstream"
        )
        if request.method == "DELETE":
            return httpx.Response(204)
        msg = json.loads(request.content)
        method = msg.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": name, "version": "1.0"},
                    },
                },
                headers={"mcp-session-id": session_id},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)

        assert request.headers.get("mcp-session-id") == session_id, (
            f"request to {name} without its upstream session id"
        )
        if method == "tools/list":
            payload = {
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {
                    "tools": [
                        {"name": t, "description": f"{name} tool", "inputSchema": {}}
                        for t in tools
                    ]
                },
            }
            if sse:  # mcp-proxy answers POSTs as SSE — exercise that parse path
                body = f"event: message\ndata: {json.dumps(payload)}\n\n"
                return httpx.Response(
                    200, content=body.encode(), headers={"content-type": "text/event-stream"}
                )
            return httpx.Response(200, json=payload)
        if method == "tools/call":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "content": [
                            {"type": "text", "text": f"{name} ran {msg['params']['name']}"}
                        ]
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32601, "message": f"unhandled: {method}"},
            },
        )

    return responder


@pytest.fixture
def client(validator, monkeypatch, tmp_path):
    """TestClient in aggregation mode with two fake upstreams and a fresh
    session registry per test."""
    monkeypatch.setattr(main, "get_validator", lambda: validator)
    monkeypatch.setattr(main, "get_policy", lambda: _POLICY)
    monkeypatch.setattr(main.settings, "auth_enabled", True)
    monkeypatch.setattr(main.settings, "gateway_resource_url", RESOURCE_URL)
    monkeypatch.setattr(main.settings, "gateway_issuer", ISSUER)
    monkeypatch.setattr(main.settings, "gateway_external_base_url", "")
    monkeypatch.setattr(main.audit.settings, "audit_log_path", str(tmp_path / "audit.log"))
    # Aggregation mode: truthy config path + injected upstream list (no disk).
    monkeypatch.setattr(main.settings, "upstreams_config_path", "injected")
    monkeypatch.setattr(
        upstreams_mod,
        "_upstreams",
        [Upstream("postgres", PG_URL), Upstream("github", GH_URL)],
    )
    monkeypatch.setattr(registry_mod, "_registry", InMemorySessionRegistry())
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def mock_upstreams():
    with respx.mock:
        pg = respx.route(url=PG_URL).mock(
            side_effect=fake_upstream("postgres", PG_TOOLS, "pg-sess", sse=True)
        )
        gh = respx.route(url=GH_URL).mock(
            side_effect=fake_upstream("github", GH_TOOLS, "gh-sess")
        )
        yield pg, gh


def _rpc(method: str, params: dict | None = None, id_: int | None = 1) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        msg["id"] = id_
    if params is not None:
        msg["params"] = params
    return msg


def _initialize(client, token: str) -> str:
    resp = client.post(
        "/mcp",
        json=_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, 0),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    return resp.headers["mcp-session-id"]


def test_initialize_answered_by_gateway_and_inits_upstreams(
    client, make_token, mock_upstreams
):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    resp = client.post(
        "/mcp",
        json=_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, 0),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["serverInfo"]["name"] == "mcp-auth-gateway"
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert resp.headers["mcp-session-id"]
    # Eager init (gate 3): both upstreams saw initialize + notifications/initialized.
    assert pg.call_count == 2
    assert gh.call_count == 2


def test_initialize_requires_token(client, mock_upstreams):
    resp = client.post("/mcp", json=_rpc("initialize", {}, 0))
    assert resp.status_code == 401


def test_tools_list_merges_namespaces_and_filters(client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    resp = client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()["result"]["tools"]}
    # Merged across upstreams, namespaced, filtered to the analyst's slice —
    # github__merge_pull_request exists upstream but is not in the allow-set.
    assert set(tools) == {
        "postgres__execute_sql",
        "postgres__list_schemas",
        "github__list_issues",
    }
    # The original name is preserved for display (gate 2).
    assert tools["postgres__execute_sql"]["title"] == "execute_sql"


def test_tools_list_filtered_per_user(client, make_token, mock_upstreams):
    token = make_token(groups=[DENIED_GROUP])
    session = _initialize(client, token)
    resp = client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    names = [t["name"] for t in resp.json()["result"]["tools"]]
    assert names == ["github__list_issues"]  # nothing of postgres is even visible


def test_tools_call_routes_to_owning_upstream(client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    client.post(  # build the route map
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    resp = client.post(
        "/mcp",
        # list_schemas is allowed + non-destructive; routing is the assertion here,
        # step-up has its own test.
        json=_rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 7),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 7  # caller's request id restored
    # Routed to postgres, with the ORIGINAL (un-namespaced) tool name.
    assert body["result"]["content"][0]["text"] == "postgres ran list_schemas"


def test_tools_call_routes_by_prefix_without_route_map(client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    resp = client.post(  # no tools/list first — the namespace itself routes
        "/mcp",
        json=_rpc("tools/call", {"name": "github__list_issues"}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.json()["result"]["content"][0]["text"] == "github ran list_issues"


def test_denied_tool_is_403_and_never_routed(client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[DENIED_GROUP])
    session = _initialize(client, token)
    calls_before = pg.call_count + gh.call_count
    resp = client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "postgres__execute_sql"}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 403
    assert pg.call_count + gh.call_count == calls_before  # never left the gateway


def test_call_without_session_is_404(client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    resp = client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "github__list_issues"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_partial_catalog_when_upstream_down(client, make_token, tmp_path):
    """Gate 4: one dead upstream degrades the catalog — served partial, audited
    loudly; a call to the dead upstream fails closed."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=httpx.ConnectError("down"))
        respx.route(url=GH_URL).mock(
            side_effect=fake_upstream("github", GH_TOOLS, "gh-sess")
        )
        session = _initialize(client, token)
        resp = client.post(
            "/mcp",
            json=_rpc("tools/list"),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
        assert resp.status_code == 200
        names = [t["name"] for t in resp.json()["result"]["tools"]]
        assert names == ["github__list_issues"]  # postgres absent, github intact

        call = client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__execute_sql"}),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
        assert "error" in call.json()  # fail closed on the dead upstream

    log = (tmp_path / "audit.log").read_text().splitlines()
    degraded = [json.loads(line) for line in log if json.loads(line)["outcome"] == "degraded"]
    assert degraded, "partial catalog must be audited, never silent"
    assert degraded[0]["upstream"] == "postgres"


def test_delete_cascades_teardown(client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    resp = client.delete(
        "/mcp",
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 204
    deletes = [
        c.request.method for c in list(pg.calls) + list(gh.calls) if c.request.method == "DELETE"
    ]
    assert len(deletes) == 2  # both upstream sessions torn down
    # The session is gone: further use 404s (client re-initializes).
    resp = client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 404


def test_tools_only_v1_scope(client, make_token, mock_upstreams):
    """Gate 5: resources/prompts answer empty-but-valid; GET (SSE) is 405;
    batches are rejected; unknown methods error cleanly."""
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    headers = {"Authorization": f"Bearer {token}", "Mcp-Session-Id": session}

    resources = client.post("/mcp", json=_rpc("resources/list"), headers=headers)
    assert resources.json()["result"] == {"resources": []}
    prompts = client.post("/mcp", json=_rpc("prompts/list"), headers=headers)
    assert prompts.json()["result"] == {"prompts": []}

    assert client.get("/mcp", headers=headers).status_code == 405

    batch = client.post("/mcp", json=[_rpc("ping"), _rpc("ping")], headers=headers)
    assert batch.json()["error"]["code"] == -32600

    unknown = client.post("/mcp", json=_rpc("sampling/createMessage"), headers=headers)
    assert unknown.json()["error"]["code"] == -32601


def test_expired_upstream_session_reconnects_and_retries(client, make_token):
    """Phase 3 Task 14: if an upstream drops our session (404), the aggregator
    re-initializes that upstream and retries the call once — the client session
    survives."""
    token = make_token(groups=[ANALYST_GROUP])

    # postgres 404s a tools/call ONCE (session expired), then behaves after the
    # gateway re-initializes it.
    state = {"expired_once": False}

    def responder(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(204)
        msg = json.loads(request.content)
        method = msg.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "serverInfo": {"name": "postgres", "version": "1"}}},
                headers={"mcp-session-id": "pg-sess"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/call" and not state["expired_once"]:
            state["expired_once"] = True
            return httpx.Response(404)  # our session is gone
        if method == "tools/call":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": "postgres ran list_schemas"}]}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}})

    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(client, token)
        resp = client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 9),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 9
    assert body["result"]["content"][0]["text"] == "postgres ran list_schemas"
    assert state["expired_once"] is True  # the first attempt did 404 and was retried


def test_step_up_enforced_on_aggregated_destructive_call(client, make_token, mock_upstreams):
    """A destructive namespaced tool challenges through the aggregated route too —
    step-up rides the same _enforce seam (ADR 006). postgres__execute_sql is in
    this policy's destructive set."""
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])  # no acrs
    session = _initialize(client, token)
    calls_before = pg.call_count
    resp = client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "postgres__execute_sql", "arguments": {}}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 401
    assert 'error="insufficient_user_authentication"' in resp.headers["www-authenticate"]
    assert pg.call_count == calls_before  # challenged before routing — never forwarded


def test_ping_and_notifications_answered_locally(client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(client, token)
    calls_before = pg.call_count + gh.call_count
    headers = {"Authorization": f"Bearer {token}", "Mcp-Session-Id": session}

    ping = client.post("/mcp", json=_rpc("ping"), headers=headers)
    assert ping.json()["result"] == {}
    note = client.post("/mcp", json=_rpc("notifications/initialized", id_=None), headers=headers)
    assert note.status_code == 202
    assert pg.call_count + gh.call_count == calls_before  # nothing fanned out
