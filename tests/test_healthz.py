"""``/healthz`` reports liveness and mode; upstream addresses stay off an unauthenticated route."""

from __future__ import annotations

from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway.upstreams import Upstream


def test_single_upstream_mode_reports_no_url(monkeypatch):
    monkeypatch.setattr(main.settings, "auth_enabled", False)
    monkeypatch.setattr(main.settings, "upstreams_config_path", "")
    monkeypatch.setattr(main.settings, "upstream_mcp_url", "http://internal-host:9000/mcp")
    with TestClient(main.app) as c:
        resp = c.get("/healthz")
    assert resp.json() == {"status": "ok", "mode": "single"}
    assert "internal-host" not in resp.text


def test_aggregate_mode_reports_no_upstream_urls(monkeypatch):
    monkeypatch.setattr(main.settings, "auth_enabled", False)
    monkeypatch.setattr(main.settings, "upstreams_config_path", "injected")
    app = main.create_app(upstreams=[Upstream("pg", "http://internal-host:9000/mcp")])
    with TestClient(app) as c:
        resp = c.get("/healthz")
    assert resp.json() == {"status": "ok", "mode": "aggregate"}
    assert "internal-host" not in resp.text
