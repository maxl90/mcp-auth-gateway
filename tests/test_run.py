"""The console entry point hands uvicorn the TLS settings, and nothing TLS-related
without them."""

from __future__ import annotations

import ssl

import uvicorn

from mcp_auth_gateway import main


def _capture(monkeypatch) -> dict:
    calls: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.update(app=app, **kwargs))
    monkeypatch.setattr(main.settings, "gateway_host", "127.0.0.1")
    monkeypatch.setattr(main.settings, "gateway_port", 8765)
    return calls


def test_run_without_tls_passes_only_host_and_port(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(main.settings, "gateway_tls_certfile", "")
    main.run()
    assert calls == {"app": main.app, "host": "127.0.0.1", "port": 8765}


def test_run_with_tls_requires_the_client_cert_when_told_to(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(main.settings, "gateway_tls_certfile", "/certs/gateway.pem")
    monkeypatch.setattr(main.settings, "gateway_tls_keyfile", "/certs/gateway-key.pem")
    monkeypatch.setattr(main.settings, "gateway_tls_ca_certs", "/certs/internal-ca.pem")
    monkeypatch.setattr(main.settings, "gateway_tls_require_client_cert", True)
    main.run()
    assert calls["ssl_certfile"] == "/certs/gateway.pem"
    assert calls["ssl_keyfile"] == "/certs/gateway-key.pem"
    assert calls["ssl_ca_certs"] == "/certs/internal-ca.pem"
    assert calls["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_run_with_tls_but_no_client_cert_requirement(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(main.settings, "gateway_tls_certfile", "/certs/gateway.pem")
    monkeypatch.setattr(main.settings, "gateway_tls_keyfile", "")
    monkeypatch.setattr(main.settings, "gateway_tls_ca_certs", "")
    monkeypatch.setattr(main.settings, "gateway_tls_require_client_cert", False)
    main.run()
    assert calls["ssl_keyfile"] is None and calls["ssl_ca_certs"] is None
    assert calls["ssl_cert_reqs"] == ssl.CERT_NONE
