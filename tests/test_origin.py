"""``Origin`` validation on the MCP routes: an absent header or a configured origin goes
on to authentication; anything else is a 403 before the caller is known."""

from __future__ import annotations

import json
import logging

import pytest

CALL = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


def _refused(resp):
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["code"] == -32600
    assert "id" not in body


def test_no_origin_goes_on_to_authentication(legacy_client):
    assert legacy_client.post("/mcp", content=CALL).status_code == 401


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",
        "file://",
        "https://gateway.example/path",  # an origin has no path
        "https://user@gateway.example",
        "not a url",
        "https://gateway.example:99999",  # port out of range
        "",
    ],
)
def test_unacceptable_origin_is_403_before_auth(gateway_client, policy, tmp_path, origin):
    with gateway_client(
        "single", policy, gateway_external_base_url="https://gateway.example"
    ) as client:
        _refused(client.post("/mcp", content=CALL, headers={"Origin": origin}))
    assert not (tmp_path / "audit.log").exists() or not (tmp_path / "audit.log").read_text()


@pytest.mark.parametrize(
    "origin",
    ["https://gateway.example", "HTTPS://Gateway.Example:443", "https://gateway.example/"],
)
def test_external_base_url_is_an_acceptable_origin(gateway_client, policy, origin):
    with gateway_client(
        "single", policy, gateway_external_base_url="https://gateway.example/"
    ) as client:
        assert client.post("/mcp", content=CALL, headers={"Origin": origin}).status_code == 401


def test_allowed_origins_are_acceptable(gateway_client, policy):
    with gateway_client(
        "single",
        policy,
        allowed_origins=["https://claude.ai", "http://localhost:6274", "http://[::1]:6274"],
    ) as client:
        for origin in ("https://claude.ai", "http://localhost:6274", "http://[::1]:6274"):
            resp = client.post("/mcp", content=CALL, headers={"Origin": origin})
            assert resp.status_code == 401
        _refused(client.post("/mcp", content=CALL, headers={"Origin": "http://localhost:6275"}))


def test_dns_rebinding_matching_host_is_still_refused(legacy_client):
    """The rebinding page's name is in both Origin and Host; the request's own
    Host must never count as an acceptable origin."""
    headers = {"Origin": "http://evil.example:8080", "Host": "evil.example:8080"}
    _refused(legacy_client.post("/mcp", content=CALL, headers=headers))


def test_path_routed_mcp_is_checked_too(aggregate_client):
    _refused(aggregate_client.post("/mcp/postgres", content=CALL, headers={"Origin": "null"}))


def test_healthz_and_discovery_are_not_checked(legacy_client):
    headers = {"Origin": "https://evil.example"}
    assert legacy_client.get("/healthz", headers=headers).status_code == 200
    resp = legacy_client.get("/.well-known/oauth-protected-resource", headers=headers)
    assert resp.status_code == 200


def test_refused_origin_is_logged_truncated(legacy_client, caplog):
    origin = "https://" + "a" * 500 + ".example"
    with caplog.at_level(logging.WARNING, logger="mcp_auth_gateway"):
        _refused(legacy_client.post("/mcp", content=CALL, headers={"Origin": origin}))
    message = next(r.getMessage() for r in caplog.records if "origin refused" in r.getMessage())
    assert "a" * 190 in message
    assert "a" * 300 not in message
