"""The aggregated ``/mcp`` virtual server, end to end.

Two respx-faked upstreams (postgres-ish and github-ish) behind the real
gateway app: gateway-answered ``initialize`` with eager upstream init, merged
+ namespaced + RBAC-filtered ``tools/list``, ``tools/call`` routing with the
original tool name restored, fail-closed calls to dead upstreams, audited
partial catalogs, cascade teardown — and the trust boundary (no caller token
ever reaches an upstream).
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
import respx

from mcp_auth_gateway import main
from mcp_auth_gateway.aggregator import upstream_client
from mcp_auth_gateway.aggregator.registry import UpstreamSession
from mcp_auth_gateway.aggregator.upstream_client import UpstreamRequest
from mcp_auth_gateway.auth.policy_resolver import Policy, StepUpRequirement
from mcp_auth_gateway.upstreams import Upstream

from .conftest import ANALYST_GROUP, DENIED_GROUP, GH_URL, PG_URL
from .fakes import fake_upstream

PG_TOOLS = ["execute_sql", "list_schemas"]
GH_TOOLS = ["list_issues", "merge_pull_request"]

# One namespaced policy spanning both upstreams. The analyst
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
    destructive={
        "postgres__execute_sql": StepUpRequirement("c1", 300),
        "github__merge_pull_request": StepUpRequirement("c1", 300),
    },
)


@pytest.fixture
def policy() -> Policy:
    return _POLICY


@pytest.fixture
def upstreams() -> list[Upstream]:
    return [Upstream("postgres", PG_URL), Upstream("github", GH_URL)]


@pytest.fixture
def mock_upstreams():
    with respx.mock:
        pg = respx.route(url=PG_URL).mock(
            side_effect=fake_upstream("postgres", PG_TOOLS, "pg-sess", sse=True)
        )
        gh = respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        yield pg, gh


def _rpc(method: str, params: dict | None = None, id_: int | None = 1) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        msg["id"] = id_
    if params is not None:
        msg["params"] = params
    return msg


def _initialize(aggregate_client, token: str) -> str:
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, 0),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    return resp.headers["mcp-session-id"]


def test_initialize_answered_by_gateway_and_inits_upstreams(
    aggregate_client, make_token, mock_upstreams
):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, 0),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["serverInfo"]["name"] == "mcp-auth-gateway"
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert resp.headers["mcp-session-id"]
    # Eager init: both upstreams saw initialize + notifications/initialized.
    assert pg.call_count == 2
    assert gh.call_count == 2


def test_initialize_requires_token(aggregate_client, mock_upstreams):
    resp = aggregate_client.post("/mcp", json=_rpc("initialize", {}, 0))
    assert resp.status_code == 401


def test_tools_list_merges_namespaces_and_filters(aggregate_client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    resp = aggregate_client.post(
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
    # The original name is preserved for display.
    assert tools["postgres__execute_sql"]["title"] == "execute_sql"


def test_tools_list_filtered_per_user(aggregate_client, make_token, mock_upstreams):
    token = make_token(groups=[DENIED_GROUP])
    session = _initialize(aggregate_client, token)
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    names = [t["name"] for t in resp.json()["result"]["tools"]]
    assert names == ["github__list_issues"]  # nothing of postgres is even visible


def test_tools_call_routes_to_owning_upstream(aggregate_client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    aggregate_client.post(  # build the route map
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    resp = aggregate_client.post(
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


def test_tools_call_routes_by_prefix_without_route_map(
    aggregate_client, make_token, mock_upstreams
):
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    resp = aggregate_client.post(  # no tools/list first — the namespace itself routes
        "/mcp",
        json=_rpc("tools/call", {"name": "github__list_issues"}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.json()["result"]["content"][0]["text"] == "github ran list_issues"


def test_denied_tool_is_403_and_never_routed(aggregate_client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[DENIED_GROUP])
    session = _initialize(aggregate_client, token)
    calls_before = pg.call_count + gh.call_count
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "postgres__execute_sql"}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 403
    assert pg.call_count + gh.call_count == calls_before  # never left the gateway


def test_call_without_session_is_404(aggregate_client, make_token, mock_upstreams):
    token = make_token(groups=[ANALYST_GROUP])
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "github__list_issues"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_partial_catalog_when_upstream_down(aggregate_client, make_token, tmp_path):
    """One dead upstream degrades the catalog — served partial, audited
    loudly; a call to the dead upstream fails closed."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=httpx.ConnectError("down"))
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(aggregate_client, token)
        resp = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/list"),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
        assert resp.status_code == 200
        names = [t["name"] for t in resp.json()["result"]["tools"]]
        assert names == ["github__list_issues"]  # postgres absent, github intact

        call = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__execute_sql"}),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
        assert "error" in call.json()  # fail closed on the dead upstream

    log = (tmp_path / "audit.log").read_text().splitlines()
    degraded = [json.loads(line) for line in log if json.loads(line)["outcome"] == "degraded"]
    assert degraded, "partial catalog must be audited, never silent"
    assert degraded[0]["upstream"] == "postgres"


def test_delete_cascades_teardown(aggregate_client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    resp = aggregate_client.delete(
        "/mcp",
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 204
    deletes = [
        c.request.method for c in list(pg.calls) + list(gh.calls) if c.request.method == "DELETE"
    ]
    assert len(deletes) == 2  # both upstream sessions torn down
    # The session is gone: further use 404s (client re-initializes).
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 404


def test_tools_only_v1_scope(aggregate_client, make_token, mock_upstreams):
    """Tools only: resources/prompts answer empty-but-valid; GET (SSE) is 405;
    batches are rejected; unknown methods error cleanly."""
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    headers = {"Authorization": f"Bearer {token}", "Mcp-Session-Id": session}

    resources = aggregate_client.post("/mcp", json=_rpc("resources/list"), headers=headers)
    assert resources.json()["result"] == {"resources": []}
    prompts = aggregate_client.post("/mcp", json=_rpc("prompts/list"), headers=headers)
    assert prompts.json()["result"] == {"prompts": []}

    assert aggregate_client.get("/mcp", headers=headers).status_code == 405

    batch = aggregate_client.post("/mcp", json=[_rpc("ping"), _rpc("ping")], headers=headers)
    assert batch.json()["error"]["code"] == -32600

    unknown = aggregate_client.post("/mcp", json=_rpc("sampling/createMessage"), headers=headers)
    assert unknown.json()["error"]["code"] == -32601


def test_expired_upstream_session_reconnects_and_retries(aggregate_client, make_token):
    """If an upstream drops our session (404), the aggregator
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
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "serverInfo": {"name": "postgres", "version": "1"},
                    },
                },
                headers={"mcp-session-id": "pg-sess"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/call" and not state["expired_once"]:
            state["expired_once"] = True
            return httpx.Response(404)  # our session is gone
        if method == "tools/call":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {"content": [{"type": "text", "text": "postgres ran list_schemas"}]},
                },
            )
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}
        )

    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(aggregate_client, token)
        resp = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 9),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 9
    assert body["result"]["content"][0]["text"] == "postgres ran list_schemas"
    assert state["expired_once"] is True  # the first attempt did 404 and was retried


def test_step_up_enforced_on_aggregated_destructive_call(
    aggregate_client, make_token, mock_upstreams
):
    """A destructive namespaced tool challenges through the aggregated route too —
    step-up rides the same enforce seam. postgres__execute_sql is in
    this policy's destructive set."""
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])  # no acrs
    session = _initialize(aggregate_client, token)
    calls_before = pg.call_count
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "postgres__execute_sql", "arguments": {}}),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 401
    assert 'error="insufficient_user_authentication"' in resp.headers["www-authenticate"]
    assert pg.call_count == calls_before  # challenged before routing — never forwarded


def test_ping_and_notifications_answered_locally(aggregate_client, make_token, mock_upstreams):
    pg, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    calls_before = pg.call_count + gh.call_count
    headers = {"Authorization": f"Bearer {token}", "Mcp-Session-Id": session}

    ping = aggregate_client.post("/mcp", json=_rpc("ping"), headers=headers)
    assert ping.json()["result"] == {}
    note = aggregate_client.post(
        "/mcp", json=_rpc("notifications/initialized", id_=None), headers=headers
    )
    assert note.status_code == 202
    assert pg.call_count + gh.call_count == calls_before  # nothing fanned out


# --- Attribution headers to upstreams (off by default) ---


def _call_list_issues(aggregate_client, token: str, session: str):
    return aggregate_client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "github__list_issues", "arguments": {}}, 9),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )


def test_no_attribution_headers_by_default(aggregate_client, make_token, mock_upstreams):
    _, gh = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    assert _call_list_issues(aggregate_client, token, session).status_code == 200
    sent = gh.calls[-1].request.headers
    assert "x-mcp-gateway-correlation-id" not in sent
    assert "x-mcp-gateway-on-behalf-of" not in sent


def test_attribution_headers_carry_the_audit_correlation_id_and_oid(
    aggregate_client, make_token, mock_upstreams, monkeypatch, tmp_path
):
    _, gh = mock_upstreams
    monkeypatch.setattr(main.settings, "forward_attribution_headers", True)
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    calls_after_init = gh.call_count
    assert _call_list_issues(aggregate_client, token, session).status_code == 200
    # Only the tools/call carries them; the handshake never did.
    for call in gh.calls[:calls_after_init]:
        assert "x-mcp-gateway-correlation-id" not in call.request.headers
    sent = gh.calls[-1].request.headers
    records = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    allowed = [
        r
        for r in records
        if r.get("tool") == "github__list_issues" and r.get("outcome") == "allowed"
    ]
    assert sent["x-mcp-gateway-correlation-id"] == allowed[-1]["correlation_id"]
    assert sent["x-mcp-gateway-on-behalf-of"] == "object-id-123"
    # Metadata only: still no token, and the arguments travel only in the body.
    assert "authorization" not in {k.lower() for k in sent}


def test_app_only_token_sends_the_correlation_id_alone(
    aggregate_client, make_token, mock_upstreams, monkeypatch
):
    _, gh = mock_upstreams
    monkeypatch.setattr(main.settings, "forward_attribution_headers", True)
    token = make_token(groups=[ANALYST_GROUP], idtyp="app")
    session = _initialize(aggregate_client, token)
    assert _call_list_issues(aggregate_client, token, session).status_code == 200
    sent = gh.calls[-1].request.headers
    assert sent.get("x-mcp-gateway-correlation-id")
    assert "x-mcp-gateway-on-behalf-of" not in sent


# -- request ids on an upstream session --------------------------------------
#
# A JSON-RPC id must be unique among a session's requests. A stateful upstream
# (the official SDK's Streamable HTTP server is one) keys each pending response
# by its request id, so two in-flight requests that share an id get one answer
# between them: the last to arrive receives the first result, the others none.


def _stateful_upstream(expected_calls: int):
    """Answers by request id, as a stateful MCP server does: whichever request
    registered an id last owns the answer for it. Records the ids it was sent, and
    answers nothing until all ``expected_calls`` requests are in flight."""
    owner: dict = {}
    seen: list = []
    all_in_flight = asyncio.Event()

    async def responder(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        seen.append(msg["id"])
        owner[msg["id"]] = msg["params"]["name"]
        if len(seen) >= expected_calls:
            all_in_flight.set()
        await all_in_flight.wait()
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"content": [{"type": "text", "text": owner[msg["id"]]}]},
            },
        )

    return responder, seen


def test_concurrent_calls_on_one_session_get_their_own_answers():
    tools = ["list_items", "summary", "get_item", "activity"]
    responder, seen = _stateful_upstream(len(tools))
    upstream = Upstream("planner", PG_URL)
    session = UpstreamSession(session_id="pl-sess")

    async def go() -> list[dict]:
        async with httpx.AsyncClient() as http:
            return await asyncio.gather(
                *(
                    upstream_client.call_tool(
                        UpstreamRequest(http, upstream, session), f"caller-{t}", t, {}
                    )
                    for t in tools
                )
            )

    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        results = asyncio.run(go())

    assert len(set(seen)) == len(tools), f"upstream request ids were reused: {seen}"
    for tool, result in zip(tools, results, strict=True):
        assert result["result"]["content"][0]["text"] == tool  # its own answer
        assert result["id"] == f"caller-{tool}"  # the caller's id restored


def test_request_ids_are_never_reused_across_a_session(
    aggregate_client, make_token, mock_upstreams
):
    pg, _ = mock_upstreams
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    headers = {"Authorization": f"Bearer {token}", "Mcp-Session-Id": session}
    aggregate_client.post("/mcp", json=_rpc("tools/list"), headers=headers)
    for _ in range(3):
        call = _rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 7)
        assert aggregate_client.post("/mcp", json=call, headers=headers).json()["id"] == 7
    sent = [json.loads(c.request.content) for c in pg.calls]
    ids = [m["id"] for m in sent if "id" in m]  # initialize, tools/list, three calls
    assert len(ids) == 5 and len(set(ids)) == 5, ids


def test_an_answer_to_a_different_request_is_refused(aggregate_client, make_token):
    """A response whose id is not the request's is another request's answer.
    It is an upstream failure, never relayed as this caller's result."""

    def responder(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "tools/call":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 999_999,
                    "result": {"content": [{"type": "text", "text": "someone else's rows"}]},
                },
            )
        return fake_upstream("postgres", PG_TOOLS, "pg-sess")(request)

    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(aggregate_client, token)
        resp = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 9),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    body = resp.json()
    assert "result" not in body
    assert body["id"] == 9 and body["error"]["code"] == -32000
    assert "someone else's rows" not in resp.text


# -- read timeouts on upstream requests ----------------------------------------


def test_control_rpc_carries_its_read_timeout():
    """The control read bound must reach the request itself: the pooled client has
    no read timeout, so without it a hung upstream hangs the caller."""
    upstream = Upstream("planner", PG_URL)
    session = UpstreamSession(session_id="pl-sess")

    async def go() -> dict:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None)) as http:
            return await upstream_client.rpc(UpstreamRequest(http, upstream, session), "tools/list")

    with respx.mock:
        route = respx.route(url=PG_URL).mock(
            return_value=httpx.Response(
                200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
            )
        )
        asyncio.run(go())
    sent = route.calls[-1].request.extensions["timeout"]
    assert sent["read"] == upstream_client._CONTROL_TIMEOUT.read


def test_control_rpc_times_out():
    """Against a socket that accepts the request and never answers, the RPC fails
    as an UpstreamError within the timeout it was given instead of hanging."""

    async def go() -> tuple[str, float]:
        release = asyncio.Event()

        async def hang(reader, writer):
            await reader.read(4096)  # take the request, never answer
            await release.wait()
            writer.close()

        server = await asyncio.start_server(hang, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        upstream = Upstream("slow", f"http://127.0.0.1:{port}/mcp")
        session = UpstreamSession(session_id="s")
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None)) as http:
                with pytest.raises(upstream_client.UpstreamError) as info:
                    await upstream_client.rpc(
                        UpstreamRequest(http, upstream, session),
                        "tools/list",
                        timeout=httpx.Timeout(2.0, read=0.1),
                    )
            return str(info.value), time.monotonic() - started
        finally:
            release.set()
            server.close()
            await server.wait_closed()

    detail, elapsed = asyncio.run(go())
    assert "transport failure" in detail
    assert elapsed < 2.0


def test_upstream_failure_detail_stays_out_of_the_response(aggregate_client, make_token, caplog):
    """A transport error names the internal host; the caller gets a generic error
    with a correlation id, and the detail goes to the server log under that id."""
    token = make_token(groups=[ANALYST_GROUP])
    healthy = fake_upstream("postgres", PG_TOOLS, "pg-sess")

    def responder(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and json.loads(request.content).get("method") == "tools/call":
            raise httpx.ConnectError("secret-internal-host.corp refused")
        return healthy(request)

    with respx.mock, caplog.at_level("WARNING", logger="mcp_auth_gateway"):
        respx.route(url=PG_URL).mock(side_effect=responder)
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(aggregate_client, token)
        resp = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/call", {"name": "postgres__list_schemas", "arguments": {}}, 4),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    body = resp.json()
    assert body["error"]["code"] == -32000
    assert "secret-internal-host" not in resp.text
    correlation = resp.headers["x-correlation-id"]
    assert "secret-internal-host" in caplog.text and correlation in caplog.text


def test_tools_call_with_non_object_params_is_denied(aggregate_client, make_token, mock_upstreams):
    """A list where the params object belongs names no tool; enforcement denies it
    (403) before the aggregator, instead of the request failing inside the gateway."""
    token = make_token(groups=[ANALYST_GROUP])
    session = _initialize(aggregate_client, token)
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/call", ["postgres__list_schemas"], 5),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 403


def test_app_only_tokens_are_distinct_session_principals(
    aggregate_client, make_token, mock_upstreams
):
    """Two app-only tokens carry no oid; the session binds to azp, so one app cannot
    drive the other's session."""
    token_a = make_token(groups=[ANALYST_GROUP], oid=None, sub=None, idtyp="app", azp="app-a")
    token_b = make_token(groups=[ANALYST_GROUP], oid=None, sub=None, idtyp="app", azp="app-b")
    session = _initialize(aggregate_client, token_a)
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token_b}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 404
    resp = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token_a}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 200


def test_session_cap_evicts_the_oldest_and_tears_down_its_upstreams(
    aggregate_client, make_token, mock_upstreams
):
    pg, gh = mock_upstreams
    aggregate_client.app.state.gateway.sessions.max_sessions_per_principal = 1
    token = make_token(groups=[ANALYST_GROUP])
    first = _initialize(aggregate_client, token)
    second = _initialize(aggregate_client, token)
    assert first != second

    deletes = [c for c in list(pg.calls) + list(gh.calls) if c.request.method == "DELETE"]
    assert len(deletes) == 2  # the evicted session's two upstream sessions were torn down
    gone = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": first},
    )
    assert gone.status_code == 404
    alive = aggregate_client.post(
        "/mcp",
        json=_rpc("tools/list"),
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": second},
    )
    assert alive.status_code == 200


@pytest.mark.parametrize("result", [[1], "tools", {"tools": 5}, {"tools": "x"}])
def test_malformed_tools_list_result_degrades_that_upstream(
    aggregate_client, make_token, tmp_path, result
):
    """An upstream's ``result`` is its own to shape. One that is not an object with a
    ``tools`` list is treated like any other failed upstream: left out, and audited."""
    healthy = fake_upstream("postgres", PG_TOOLS, "pg-sess")

    def responder(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            msg = json.loads(request.content)
            if msg.get("method") == "tools/list":
                return httpx.Response(
                    200, json={"jsonrpc": "2.0", "id": msg["id"], "result": result}
                )
        return healthy(request)

    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        respx.route(url=GH_URL).mock(side_effect=fake_upstream("github", GH_TOOLS, "gh-sess"))
        session = _initialize(aggregate_client, token)
        resp = aggregate_client.post(
            "/mcp",
            json=_rpc("tools/list"),
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    assert resp.status_code == 200
    assert [t["name"] for t in resp.json()["result"]["tools"]] == ["github__list_issues"]
    records = [json.loads(ln) for ln in (tmp_path / "audit.log").read_text().splitlines()]
    assert [r["upstream"] for r in records if r["outcome"] == "degraded"] == ["postgres"]


@pytest.mark.parametrize("method", ["GET", "PUT"])
def test_405_advertises_only_the_methods_that_work(aggregate_client, make_token, method):
    token = make_token(groups=[ANALYST_GROUP])
    resp = aggregate_client.request(method, "/mcp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 405
    assert resp.headers["allow"] == "POST, DELETE"
