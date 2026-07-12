"""Phase 3 stage 3a: stateless path routing — ``/mcp/<name>`` per upstream.

Both upstreams reachable at once without the stateful aggregator; the SAME
namespaced policy file governs these routes (the gateway prefixes wire names
before the RBAC check), so path routing and aggregation can't drift apart.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway import upstreams as upstreams_mod
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.upstreams import Upstream

from .conftest import ANALYST_GROUP, DENIED_GROUP, ISSUER, RESOURCE_URL

PG_URL = "http://pg-upstream:9000/mcp"
GH_URL = "http://gh-upstream:9001/mcp"

_POLICY = Policy(
    groups={
        ANALYST_GROUP: ["postgres__execute_sql", "github__list_issues"],
        DENIED_GROUP: [],
    },
    destructive=[],
)


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
    monkeypatch.setattr(
        upstreams_mod,
        "_upstreams",
        [Upstream("postgres", PG_URL), Upstream("github", GH_URL)],
    )
    with TestClient(main.app) as c:
        yield c


def _tools_call(name: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name}}


def test_routes_to_named_upstream(client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        pg = respx.post(PG_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        gh = respx.post(GH_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        resp = client.post(
            "/mcp/postgres",
            json=_tools_call("execute_sql"),  # un-namespaced on this route
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert pg.call_count == 1 and gh.call_count == 0
    # Trust boundary holds on path routes too.
    assert "authorization" not in {k.lower() for k in pg.calls.last.request.headers}


def test_namespaced_policy_governs_path_routes(client, make_token, tmp_path):
    """The analyst may run postgres__execute_sql but NOT github__execute_sql —
    the same wire name is allowed on one path and 403 on the other."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        gh = respx.post(GH_URL).mock(return_value=httpx.Response(200, json={}))
        resp = client.post(
            "/mcp/github",
            json=_tools_call("execute_sql"),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 403
    assert gh.call_count == 0
    # The audit record carries the namespaced name and the upstream.
    record = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert record["tool"] == "github__execute_sql"
    assert record["upstream"] == "github"
    assert record["outcome"] == "denied"


def test_unknown_upstream_is_404(client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    resp = client.post(
        "/mcp/nope",
        json=_tools_call("anything"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_tools_list_filtered_to_upstream_slice(client, make_token):
    """A path-routed tools/list is filtered against this upstream's slice of
    the namespaced allow-set, compared un-prefixed (as the upstream names them)."""
    token = make_token(groups=[ANALYST_GROUP])
    upstream_reply = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "execute_sql", "inputSchema": {}},
                {"name": "drop_everything", "inputSchema": {}},
            ]
        },
    }
    with respx.mock:
        respx.post(PG_URL).mock(return_value=httpx.Response(200, json=upstream_reply))
        resp = client.post(
            "/mcp/postgres",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    names = [t["name"] for t in resp.json()["result"]["tools"]]
    assert names == ["execute_sql"]  # allowed via postgres__execute_sql only
