"""Regression tests for the Phase 3 security-review findings (2026-07-06).

Each test pins a fix from the adversarial review so the defect can't silently
return:

1. session-oid re-check — a leaked Mcp-Session-Id can't be driven by another user
2. response size cap — an oversized upstream body is rejected, not buffered
3. tools/list filter fails CLOSED on a crafted non-string tool name
4. WWW-Authenticate quoted-string escaping — no header-param injection via `kid`
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
from mcp_auth_gateway.tools_filter import filter_tools_list_response
from mcp_auth_gateway.upstreams import Upstream

from .conftest import ANALYST_GROUP, ISSUER, RESOURCE_URL

# --- Finding 4: header-injection escaping (pure) ----------------------------


def test_www_authenticate_escapes_injected_quotes():
    # A crafted kid echoed into error_description must not be able to open a new
    # auth-param (e.g. a rogue resource_metadata pointer).
    malicious = 'zzz", resource_metadata="https://attacker.example/evil'
    header = main._www_authenticate(error="invalid_token", description=malicious)
    # The injected closing quote is backslash-escaped, so only OUR
    # resource_metadata (absent here) could ever appear — the attacker's doesn't.
    assert 'resource_metadata="https://attacker.example/evil"' not in header
    assert '\\"' in header  # the quote was escaped, not passed through


def test_www_authenticate_strips_control_chars():
    header = main._www_authenticate(description="a\r\nb")
    assert "\r" not in header and "\n" not in header


# --- Finding 3: filter fails closed on non-string name ----------------------


def test_filter_drops_non_string_tool_name_and_still_filters():
    allowed = {"safe_tool"}
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "safe_tool"},
                    {"name": "secret_tool"},  # not allowed → must be removed
                    {"name": ["crafted"]},  # unhashable → must not blow the filter open
                ]
            },
        }
    ).encode()
    out = json.loads(filter_tools_list_response(body, "application/json", allowed))
    names = [t.get("name") for t in out["result"]["tools"]]
    # The crafted entry did NOT cause a fail-open: secret_tool is still gone.
    assert names == ["safe_tool"]


# --- Findings 1 & 2: aggregation-mode integration ---------------------------

PG_URL = "http://pg-upstream:9000/mcp"

_POLICY = Policy(groups={ANALYST_GROUP: ["postgres__list_schemas"]}, destructive={})


@pytest.fixture
def client(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "get_validator", lambda: validator)
    monkeypatch.setattr(main, "get_policy", lambda: _POLICY)
    monkeypatch.setattr(main.settings, "auth_enabled", True)
    monkeypatch.setattr(main.settings, "gateway_resource_url", RESOURCE_URL)
    monkeypatch.setattr(main.settings, "gateway_issuer", ISSUER)
    monkeypatch.setattr(main.settings, "gateway_external_base_url", "")
    monkeypatch.setattr(main.audit.settings, "audit_log_path", str(tmp_path / "audit.log"))
    monkeypatch.setattr(main.settings, "upstreams_config_path", "injected")
    monkeypatch.setattr(upstreams_mod, "_upstreams", [Upstream("postgres", PG_URL)])
    monkeypatch.setattr(registry_mod, "_registry", InMemorySessionRegistry())
    with TestClient(main.app) as c:
        yield c


def _pg_responder(request: httpx.Request) -> httpx.Response:
    msg = json.loads(request.content)
    if msg.get("method") == "initialize":
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "pg", "version": "1"}}},
            headers={"mcp-session-id": "pg-sess"},
        )
    if msg.get("method") == "notifications/initialized":
        return httpx.Response(202)
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}})


def _init(client, token) -> str:
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=_pg_responder)
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
            headers={"Authorization": f"Bearer {token}"},
        )
    return resp.headers["mcp-session-id"]


def test_leaked_session_id_rejected_for_different_user(client, make_token):
    """Finding 1: a session created by user A (oid X) must not be usable by user
    B (oid Y) who presents A's Mcp-Session-Id."""
    token_a = make_token(groups=[ANALYST_GROUP], oid="user-a-oid")
    session = _init(client, token_a)

    # User B: a valid token, different oid, presenting A's session id.
    token_b = make_token(groups=[ANALYST_GROUP], oid="user-b-oid")
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token_b}", "Mcp-Session-Id": session},
    )
    assert resp.status_code == 404  # resolves to "no session" for the wrong owner

    # And B can't tear down A's session either.
    deleted = client.delete(
        "/mcp",
        headers={"Authorization": f"Bearer {token_b}", "Mcp-Session-Id": session},
    )
    assert deleted.status_code == 404

    # The real owner still works.
    with respx.mock:
        respx.route(url=PG_URL).mock(side_effect=_pg_responder)
        ok = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token_a}", "Mcp-Session-Id": session},
        )
    assert ok.status_code == 200


def test_oversized_upstream_response_is_rejected(client, make_token, monkeypatch):
    """Finding 2: an upstream response beyond the cap is aborted, not buffered
    into an OOM. Tiny cap so the test body is small."""
    # settings is a shared singleton, so this one patch reaches both main and
    # upstream_client.
    monkeypatch.setattr(main.settings, "max_upstream_response_bytes", 512)
    token = make_token(groups=[ANALYST_GROUP], oid="user-a-oid")

    huge = "x" * 10000

    def responder(request: httpx.Request) -> httpx.Response:
        msg = json.loads(request.content)
        if msg.get("method") == "initialize":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "pg", "version": "1"}}},
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
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
            headers={"Authorization": f"Bearer {token}"},
        )
        session = resp.headers["mcp-session-id"]
        listing = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session},
        )
    # The oversized upstream body was aborted → that upstream is treated as
    # degraded and contributes no tools, rather than being buffered whole.
    assert listing.status_code == 200
    assert listing.json()["result"]["tools"] == []
