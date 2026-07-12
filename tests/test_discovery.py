"""Protected Resource Metadata + discovery — the MCP auth handshake anchor.

Phase 1.5 (RFC 9728): a cold client discovers how to authenticate against the
gateway via the PRM document and the 401 ``resource_metadata`` pointer.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway.auth import discovery

from .conftest import ISSUER, RESOURCE_URL


@pytest.fixture
def configured(monkeypatch):
    """Resource-server settings configured, auth off so the PRM route can be
    exercised without standing up the validator/policy (REQ-1.5.3)."""
    monkeypatch.setattr(main.settings, "auth_enabled", False)
    monkeypatch.setattr(main.settings, "gateway_resource_url", RESOURCE_URL)
    monkeypatch.setattr(main.settings, "gateway_issuer", ISSUER)
    monkeypatch.setattr(main.settings, "entra_auth_server_metadata_url", "")
    monkeypatch.setattr(main.settings, "scopes_supported", ["access_as_user"])


def test_prm_document_served_unauthenticated(configured):
    with TestClient(main.app) as c:
        resp = c.get(discovery.PRM_WELL_KNOWN_PATH)  # no Authorization header
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["resource"] == RESOURCE_URL
    assert doc["authorization_servers"] == [ISSUER]
    assert "access_as_user" in doc["scopes_supported"]


def test_prm_endpoint_404_when_unconfigured(monkeypatch):
    monkeypatch.setattr(main.settings, "auth_enabled", False)
    monkeypatch.setattr(main.settings, "gateway_resource_url", "")
    with TestClient(main.app) as c:
        resp = c.get(discovery.PRM_WELL_KNOWN_PATH)
    assert resp.status_code == 404


def test_build_prm_requires_resource_url(monkeypatch):
    monkeypatch.setattr(discovery.settings, "gateway_resource_url", "")
    with pytest.raises(RuntimeError):
        discovery.build_prm_document()


def test_auth_server_falls_back_to_issuer(monkeypatch):
    monkeypatch.setattr(discovery.settings, "gateway_resource_url", RESOURCE_URL)
    monkeypatch.setattr(discovery.settings, "entra_auth_server_metadata_url", "")
    monkeypatch.setattr(discovery.settings, "gateway_issuer", ISSUER)
    assert discovery.build_prm_document()["authorization_servers"] == [ISSUER]


def test_resource_metadata_url_uses_external_base(monkeypatch):
    monkeypatch.setattr(discovery.settings, "gateway_external_base_url", "https://gw.example.com")
    url = discovery.resource_metadata_url("http://internal-host/")
    assert url == "https://gw.example.com/.well-known/oauth-protected-resource"


def test_resource_metadata_url_falls_back_to_request_origin(monkeypatch):
    monkeypatch.setattr(discovery.settings, "gateway_external_base_url", "")
    url = discovery.resource_metadata_url("http://testserver/")
    assert url == "http://testserver/.well-known/oauth-protected-resource"
