"""A request in the MCP 2026-07-28 protocol is logged and still answered as legacy: the
unrecognized 404 is what makes a dual-era client fall back to ``initialize``."""

from __future__ import annotations

import json
import logging

import pytest

MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "claude-code", "version": "2.1.278"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _post(client, token, message, **headers):
    return client.post(
        "/mcp",
        content=json.dumps(message),
        headers={"Authorization": f"Bearer {token}", **headers},
    )


def _modern_lines(caplog):
    return [r.getMessage() for r in caplog.records if "modern protocol request" in r.getMessage()]


def test_server_discover_is_logged_and_still_a_legacy_404(aggregate_client, make_token, caplog):
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {"_meta": MODERN_META},
    }
    token = make_token(azp="agent-app-id")
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        resp = _post(aggregate_client, token, message, **{"MCP-Protocol-Version": "2026-07-28"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == -32000  # unrecognized: the client falls back
    (line,) = _modern_lines(caplog)
    assert "method='server/discover'" in line
    assert "version='2026-07-28'" in line
    assert "client='claude-code'/'2.1.278'" in line
    assert "agent='agent-app-id'" in line
    assert "correlation_id=" in line


def test_modern_meta_on_another_method_is_logged(aggregate_client, make_token, caplog):
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": MODERN_META}}
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        resp = _post(aggregate_client, make_token(), message)
    assert resp.status_code == 404
    (line,) = _modern_lines(caplog)
    assert "method='tools/list'" in line


def test_discover_without_meta_falls_back_to_the_header(aggregate_client, make_token, caplog):
    message = {"jsonrpc": "2.0", "id": 3, "method": "server/discover"}
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        _post(aggregate_client, make_token(), message, **{"MCP-Protocol-Version": "2026-07-28"})
    (line,) = _modern_lines(caplog)
    assert "version='2026-07-28'" in line
    assert "client=-/-" in line


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {"_meta": "junk"}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": ["not", "a", "dict"]},
    ],
)
def test_legacy_requests_are_not_logged(aggregate_client, make_token, caplog, message):
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        _post(aggregate_client, make_token(), message)
    assert _modern_lines(caplog) == []


def test_logged_client_values_cannot_forge_lines(aggregate_client, make_token, caplog):
    meta = dict(MODERN_META)
    meta["io.modelcontextprotocol/clientInfo"] = {"name": "x\nFAKE LINE " + "a" * 200, "version": 7}
    message = {"jsonrpc": "2.0", "id": 7, "method": "server/discover", "params": {"_meta": meta}}
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        _post(aggregate_client, make_token(), message)
    (line,) = _modern_lines(caplog)
    assert "\n" not in line
    assert "a" * 100 not in line
