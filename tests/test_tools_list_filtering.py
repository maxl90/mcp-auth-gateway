"""Phase 2: ``tools/list`` response filtering.

Two layers:
- pure-function unit tests over ``tools_filter`` (JSON + SSE framing, edge cases),
- end-to-end proxy tests that drive ``/mcp`` with a real (synthetic) token and a
  respx-mocked upstream, asserting the caller only sees their permitted tools.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.tools_filter import (
    filter_tools_list_response,
    is_tools_list_request,
)

from .conftest import ANALYST_GROUP, DENIED_GROUP, ISSUER, RESOURCE_URL

# The nine tools the demo's postgres-mcp upstream actually advertises.
ALL_TOOLS = [
    "list_schemas",
    "list_objects",
    "get_object_details",
    "explain_query",
    "analyze_workload_indexes",
    "analyze_query_indexes",
    "analyze_db_health",
    "get_top_queries",
    "execute_sql",
]
ANALYST_ALLOWED = ["list_schemas", "execute_sql"]

UPSTREAM = "http://localhost:9000/mcp"

_POLICY = Policy(
    groups={ANALYST_GROUP: ANALYST_ALLOWED, DENIED_GROUP: []},
    destructive=["execute_sql"],
)


def _tools_list_result(names: list[str]) -> dict:
    """A JSON-RPC tools/list result with one entry per name (extra fields kept to
    prove the filter preserves whole tool objects, not just names)."""
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": n,
                    "description": f"the {n} tool",
                    "inputSchema": {"type": "object", "properties": {}},
                }
                for n in names
            ]
        },
    }


def _names_in(body: bytes) -> list[str]:
    doc = json.loads(body)
    return [t["name"] for t in doc["result"]["tools"]]


# --------------------------------------------------------------------------- #
# is_tools_list_request
# --------------------------------------------------------------------------- #


def test_detects_tools_list_request():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    assert is_tools_list_request(body) is True


@pytest.mark.parametrize(
    "method", ["tools/call", "initialize", "ping", "notifications/initialized"]
)
def test_other_methods_are_not_tools_list(method):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}).encode()
    assert is_tools_list_request(body) is False


def test_empty_or_garbage_body_is_not_tools_list():
    assert is_tools_list_request(b"") is False
    assert is_tools_list_request(b"not json") is False


def test_batch_containing_tools_list_is_detected():
    body = json.dumps(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
    ).encode()
    assert is_tools_list_request(body) is True


# --------------------------------------------------------------------------- #
# filter_tools_list_response — JSON
# --------------------------------------------------------------------------- #


def test_json_filters_to_allowed_subset():
    raw = json.dumps(_tools_list_result(ALL_TOOLS)).encode()
    out = filter_tools_list_response(raw, "application/json", ANALYST_ALLOWED)
    assert _names_in(out) == ANALYST_ALLOWED


def test_json_denied_user_sees_no_tools():
    raw = json.dumps(_tools_list_result(ALL_TOOLS)).encode()
    out = filter_tools_list_response(raw, "application/json", set())
    assert _names_in(out) == []


def test_json_preserves_whole_tool_object():
    raw = json.dumps(_tools_list_result(ALL_TOOLS)).encode()
    out = filter_tools_list_response(raw, "application/json", ["execute_sql"])
    tool = json.loads(out)["result"]["tools"][0]
    assert tool["description"] == "the execute_sql tool"
    assert tool["inputSchema"] == {"type": "object", "properties": {}}


def test_json_non_tools_list_message_untouched():
    err = {"jsonrpc": "2.0", "id": 2, "error": {"code": -32601, "message": "nope"}}
    raw = json.dumps(err).encode()
    out = filter_tools_list_response(raw, "application/json", ["execute_sql"])
    assert json.loads(out) == err


def test_unparseable_json_returned_unchanged():
    raw = b"{ not valid json"
    assert filter_tools_list_response(raw, "application/json", ["x"]) == raw


def test_unknown_content_type_returned_unchanged():
    raw = json.dumps(_tools_list_result(ALL_TOOLS)).encode()
    assert filter_tools_list_response(raw, "text/plain", ANALYST_ALLOWED) == raw


def test_tool_entry_without_name_is_dropped():
    doc = {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"description": "nameless"}]}}
    out = filter_tools_list_response(json.dumps(doc).encode(), "application/json", set())
    assert json.loads(out)["result"]["tools"] == []


# --------------------------------------------------------------------------- #
# filter_tools_list_response — SSE
# --------------------------------------------------------------------------- #


def test_sse_filters_and_preserves_framing():
    payload = json.dumps(_tools_list_result(ALL_TOOLS))
    raw = f"event: message\ndata: {payload}\n\n".encode()
    out = filter_tools_list_response(raw, "text/event-stream", ANALYST_ALLOWED)
    text = out.decode()
    assert "event: message" in text  # non-data line preserved
    data_line = next(ln for ln in text.splitlines() if ln.startswith("data:"))
    doc = json.loads(data_line[len("data:") :].strip())
    assert [t["name"] for t in doc["result"]["tools"]] == ANALYST_ALLOWED


def test_sse_crlf_frame_is_handled():
    payload = json.dumps(_tools_list_result(ALL_TOOLS))
    raw = f"event: message\r\ndata: {payload}\r\n\r\n".encode()
    out = filter_tools_list_response(raw, "text/event-stream", ["execute_sql"])
    data_line = next(ln for ln in out.decode().splitlines() if ln.startswith("data:"))
    doc = json.loads(data_line[len("data:") :].strip())
    assert [t["name"] for t in doc["result"]["tools"]] == ["execute_sql"]


def test_sse_non_json_frame_left_intact():
    raw = b": this is a keep-alive comment\n\n"
    assert filter_tools_list_response(raw, "text/event-stream", set()).strip() == raw.strip()


# --------------------------------------------------------------------------- #
# End-to-end through the proxy
# --------------------------------------------------------------------------- #


@pytest.fixture
def client(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "get_validator", lambda: validator)
    monkeypatch.setattr(main, "get_policy", lambda: _POLICY)
    monkeypatch.setattr(main.settings, "auth_enabled", True)
    monkeypatch.setattr(main.settings, "upstream_mcp_url", UPSTREAM)
    monkeypatch.setattr(main.settings, "gateway_resource_url", RESOURCE_URL)
    monkeypatch.setattr(main.settings, "gateway_issuer", ISSUER)
    monkeypatch.setattr(main.settings, "gateway_external_base_url", "")
    monkeypatch.setattr(main.audit.settings, "audit_log_path", str(tmp_path / "audit.log"))
    with TestClient(main.app) as c:
        yield c


def _tools_list_request() -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode()


def test_proxy_filters_tools_list_for_analyst(client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    upstream_body = json.dumps(_tools_list_result(ALL_TOOLS))
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200, content=upstream_body, headers={"content-type": "application/json"}
            )
        )
        resp = client.post(
            "/mcp",
            content=_tools_list_request(),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert _names_in(resp.content) == ANALYST_ALLOWED


def test_proxy_filters_tools_list_to_empty_for_denied_user(client, make_token):
    token = make_token(groups=[DENIED_GROUP])
    upstream_body = json.dumps(_tools_list_result(ALL_TOOLS))
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200, content=upstream_body, headers={"content-type": "application/json"}
            )
        )
        resp = client.post(
            "/mcp",
            content=_tools_list_request(),
            headers={"Authorization": f"Bearer {token}"},
        )
    # A denied user may still *list* (authenticated pass-through) but sees nothing.
    assert resp.status_code == 200
    assert _names_in(resp.content) == []


def test_proxy_tools_list_still_reaches_upstream(client, make_token):
    """Filtering is a response rewrite, not a block — the request is forwarded."""
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200,
                content=json.dumps(_tools_list_result(ALL_TOOLS)),
                headers={"content-type": "application/json"},
            )
        )
        client.post(
            "/mcp",
            content=_tools_list_request(),
            headers={"Authorization": f"Bearer {token}"},
        )
    assert route.call_count == 1
    # Trust boundary still holds on the filtered path: token not forwarded.
    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers}


def test_proxy_does_not_filter_when_auth_disabled(client, make_token, monkeypatch):
    """Phase 0 passthrough: no identity to filter by, so the full list passes."""
    monkeypatch.setattr(main.settings, "auth_enabled", False)
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(
                200,
                content=json.dumps(_tools_list_result(ALL_TOOLS)),
                headers={"content-type": "application/json"},
            )
        )
        resp = client.post("/mcp", content=_tools_list_request())
    assert _names_in(resp.content) == ALL_TOOLS
