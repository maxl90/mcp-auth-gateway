"""Aggregation-mode session ownership and the upstream response cap.

A leaked ``Mcp-Session-Id`` cannot be driven or torn down by another user, and an
oversized upstream body is aborted rather than buffered.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_auth_gateway import main
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.upstreams import Upstream

from .conftest import ANALYST_GROUP, PG_URL

_POLICY = Policy(groups={ANALYST_GROUP: ["postgres__list_schemas"]})


@pytest.fixture
def policy() -> Policy:
    return _POLICY


@pytest.fixture
def upstreams() -> list[Upstream]:
    return [Upstream("postgres", PG_URL)]


def _pg_responder(request: httpx.Request) -> httpx.Response:
    msg = json.loads(request.content)
    if msg.get("method") == "initialize":
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "serverInfo": {"name": "pg", "version": "1"},
                },
            },
            headers={"mcp-session-id": "pg-sess"},
        )
    if msg.get("method") == "notifications/initialized":
        return httpx.Response(202)
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}
    )


def _init(aggregate_client, token) -> str:
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=_pg_responder)
        resp = aggregate_client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    return resp.headers["mcp-session-id"]


def test_leaked_session_id_rejected_for_different_user(aggregate_client, make_token):
    """A session created by user A (oid X) must not be usable by user B (oid Y)
    who presents A's Mcp-Session-Id."""
    token_a = make_token(groups=[ANALYST_GROUP], oid="user-a-oid")
    session = _init(aggregate_client, token_a)

    # User B: a valid token, different oid, presenting A's session id.
    token_b = make_token(groups=[ANALYST_GROUP], oid="user-b-oid")
    resp = aggregate_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token_b}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 404  # resolves to "no session" for the wrong owner

    # And B can't tear down A's session either.
    deleted = aggregate_client.delete(
        "/mcp",
        headers={"Authorization": f"Bearer {token_b}", "Mcp-Session-Id": session},
    )
    assert deleted.status_code == 404

    # The real owner still works.
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=_pg_responder)
        ok = aggregate_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token_a}", "Mcp-Session-Id": session},
        )
    assert ok.status_code == 200


def test_oversized_upstream_response_is_rejected(aggregate_client, make_token, monkeypatch):
    """An upstream response beyond the cap is aborted, not buffered into an OOM.
    Tiny cap so the test body is small."""
    # settings is a shared singleton, so this one patch reaches both the proxy
    # and the upstream client.
    monkeypatch.setattr(main.settings, "max_upstream_response_bytes", 512)
    token = make_token(groups=[ANALYST_GROUP], oid="user-a-oid")

    huge = "x" * 10000

    def responder(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "serverInfo": {"name": "pg", "version": "1"},
                    },
                },
                headers={"mcp-session-id": "pg-sess"},
            )
        if msg.get("method") == "notifications/initialized":
            return httpx.Response(202)
        # An oversized tools/list result.
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": [{"name": huge}]}},
        )

    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=responder)
        resp = aggregate_client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        session = resp.headers["mcp-session-id"]
        listing = aggregate_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    # The oversized upstream body was aborted → that upstream is treated as
    # degraded and contributes no tools, rather than being buffered whole.
    assert listing.status_code == 200
    assert listing.json()["result"]["tools"] == []
