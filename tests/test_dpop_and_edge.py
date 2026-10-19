"""DPoP (RFC 9449) sender-constrained tokens + edge channel identity.

Covers the resource-server checks of §4.3 (signature by the embedded key,
htm/htu, iat window, ath token hash, jti replay, cnf.jkt binding), the §7.1
scheme rules (a bound token must arrive as ``Authorization: DPoP`` with
exactly one proof), the three DPOP_MODE postures, and the trusted-proxy
edge-identity headers feeding the audit ``channel`` block.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_auth_gateway import main
from mcp_auth_gateway.auth import dpop
from mcp_auth_gateway.auth.policy_resolver import Policy

from .conftest import ANALYST_GROUP, UPSTREAM

HTU = "https://mcp.example.test/mcp"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ec_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict:
    nums = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }


@pytest.fixture
def client_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def make_proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    method: str = "POST",
    htu: str = HTU,
    access_token: str = "the-token",
    jti: str | None = None,
    iat: int | None = None,
    ath: str | None = "auto",
    typ: str = "dpop+jwt",
    alg: str = "ES256",
    jwk: dict | None = None,
) -> str:
    claims: dict = {
        "jti": jti or _b64url(str(time.time_ns()).encode()),
        "htm": method,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
    }
    if ath == "auto":
        claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
    elif ath is not None:
        claims["ath"] = ath
    return jwt.encode(claims, key, algorithm=alg, headers={"typ": typ, "jwk": jwk or _ec_jwk(key)})


def _validate(key, proof, token="the-token", jkt=None, replay=None):
    return dpop.validate_proof(
        proof,
        method="POST",
        accepted_htus={dpop._normalize_htu(HTU)},
        access_token=token,
        cnf_jkt=jkt or dpop.jwk_thumbprint(_ec_jwk(key)),
        replay=replay if replay is not None else dpop.ReplayCache(),
    )


# --- proof validation (§4.3) -------------------------------------------------


def test_valid_proof_returns_bound_thumbprint(client_key):
    jkt = dpop.jwk_thumbprint(_ec_jwk(client_key))
    assert _validate(client_key, make_proof(client_key)) == jkt


def test_wrong_method_rejected(client_key):
    with pytest.raises(dpop.DpopError, match="htm"):
        _validate(client_key, make_proof(client_key, method="GET"))


def test_wrong_htu_rejected(client_key):
    with pytest.raises(dpop.DpopError, match="htu"):
        _validate(client_key, make_proof(client_key, htu="https://elsewhere.test/mcp"))


def test_htu_ignores_query_and_case(client_key):
    proof = make_proof(client_key, htu="HTTPS://MCP.example.test/mcp?x=1#frag")
    assert _validate(client_key, proof)


def test_stale_iat_rejected(client_key, monkeypatch):
    monkeypatch.setattr(dpop.settings, "dpop_iat_window", 300)
    with pytest.raises(dpop.DpopError, match="iat"):
        _validate(client_key, make_proof(client_key, iat=int(time.time()) - 3600))


def test_future_iat_beyond_the_window_rejected(client_key, monkeypatch):
    monkeypatch.setattr(dpop.settings, "dpop_iat_window", 300)
    with pytest.raises(dpop.DpopError, match="iat"):
        _validate(client_key, make_proof(client_key, iat=int(time.time()) + 3600))


def test_ath_must_match_presented_token(client_key):
    proof = make_proof(client_key, access_token="a-different-token")
    with pytest.raises(dpop.DpopError, match="ath"):
        _validate(client_key, proof, token="the-token")


def test_missing_ath_rejected(client_key):
    with pytest.raises(dpop.DpopError, match="ath"):
        _validate(client_key, make_proof(client_key, ath=None))


def test_key_must_match_cnf_binding(client_key):
    thief_key = ec.generate_private_key(ec.SECP256R1())
    # Proof validly signed by the thief's key — but the token is bound to the
    # legitimate client's key. The stolen-token scenario, dead on arrival.
    proof = make_proof(thief_key)
    with pytest.raises(dpop.DpopError, match="cnf.jkt"):
        _validate(client_key, proof, jkt=dpop.jwk_thumbprint(_ec_jwk(client_key)))


def test_replayed_jti_rejected(client_key):
    proof = make_proof(client_key)
    seen = dpop.ReplayCache()
    assert _validate(client_key, proof, replay=seen)
    with pytest.raises(dpop.DpopError, match="replay"):
        _validate(client_key, proof, replay=seen)


def test_a_proof_that_is_not_a_jwt_is_rejected(client_key):
    with pytest.raises(dpop.DpopError, match="not a JWT"):
        _validate(client_key, "not-a-jwt")


def test_a_proof_without_an_embedded_jwk_is_rejected(client_key):
    claims = {"jti": "j1", "htm": "POST", "htu": HTU, "iat": int(time.time())}
    proof = jwt.encode(claims, client_key, algorithm="ES256", headers={"typ": "dpop+jwt"})
    with pytest.raises(dpop.DpopError, match="missing embedded jwk"):
        _validate(client_key, proof)


def test_a_proof_whose_jwk_is_not_a_usable_key_is_rejected(client_key):
    broken = {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
    with pytest.raises(dpop.DpopError, match="not a usable public key"):
        _validate(client_key, make_proof(client_key, jwk=broken))


def test_thumbprint_refuses_an_unknown_kty_or_a_missing_member():
    with pytest.raises(dpop.DpopError, match="unsupported jwk kty"):
        dpop.jwk_thumbprint({"kty": "oct", "k": "c2VjcmV0"})
    with pytest.raises(dpop.DpopError, match="missing required member"):
        dpop.jwk_thumbprint({"kty": "EC", "crv": "P-256", "x": "AA"})


def test_htu_comparison_ignores_query_fragment_case_and_a_trailing_slash():
    assert dpop._normalize_htu("HTTPS://GW.Example/mcp/?x=1#f") == "https://gw.example/mcp"


def test_the_public_url_is_accepted_behind_the_edge(monkeypatch):
    monkeypatch.setattr(dpop.settings, "gateway_external_base_url", "https://public.example/")
    assert dpop.expected_htus("http://10.0.0.5:8080/mcp", "/mcp") == {
        "http://10.0.0.5:8080/mcp",
        "https://public.example/mcp",
    }


def test_a_full_replay_cache_forgets_expired_entries_first_then_the_oldest():
    cache = dpop.ReplayCache(max_entries=2)
    assert cache.check_and_store("expired", ttl=-1)
    assert cache.check_and_store("b", ttl=60)
    assert cache.check_and_store("c", ttl=60)  # full: the expired entry goes
    assert not cache.check_and_store("b", ttl=60)  # still remembered
    assert cache.check_and_store("d", ttl=60)  # full, none expired: the oldest ("b") goes
    assert cache.check_and_store("b", ttl=60)


def test_wrong_typ_rejected(client_key):
    with pytest.raises(dpop.DpopError, match="typ"):
        _validate(client_key, make_proof(client_key, typ="JWT"))


def test_symmetric_alg_rejected(client_key):
    proof = jwt.encode(
        {"jti": "x", "htm": "POST", "htu": HTU, "iat": int(time.time())},
        "shared-secret",
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": _ec_jwk(client_key)},
    )
    with pytest.raises(dpop.DpopError, match="alg"):
        _validate(client_key, proof)


def test_private_key_members_in_jwk_rejected(client_key):
    jwk = _ec_jwk(client_key)
    jwk["d"] = _b64url(b"leaked-private-scalar")
    with pytest.raises(dpop.DpopError, match="private"):
        _validate(client_key, make_proof(client_key, jwk=jwk))


# --- enforcement modes (§7.1) ------------------------------------------------


def _enforce(scheme, token, claims, proofs, monkeypatch=None, mode=None):
    if mode is not None:
        monkeypatch.setattr(dpop.settings, "dpop_mode", mode)
    return dpop.enforce(
        scheme=scheme,
        access_token=token,
        claims=claims,
        proofs=proofs,
        method="POST",
        accepted_htus={dpop._normalize_htu(HTU)},
        replay=dpop.ReplayCache(),
    )


def test_mode_off_ignores_everything(monkeypatch):
    claims = {"cnf": {"jkt": "whatever"}}
    assert _enforce("bearer", "t", claims, ["garbage"], monkeypatch, "off") is None


def test_unbound_token_passes_as_bearer_in_if_present(monkeypatch):
    assert _enforce("bearer", "t", {"oid": "u"}, [], monkeypatch, "if_present") is None


def test_unbound_token_rejected_in_required_mode(monkeypatch):
    with pytest.raises(dpop.DpopError) as exc:
        _enforce("bearer", "t", {"oid": "u"}, [], monkeypatch, "required")
    assert exc.value.error == "invalid_token"


def test_unbound_token_under_the_dpop_scheme_is_rejected(monkeypatch):
    # The DPoP scheme says the token is bound; an unbound one is not read as bearer.
    with pytest.raises(dpop.DpopError, match="not DPoP-bound") as exc:
        _enforce("dpop", "t", {"oid": "u"}, ["any-proof"], monkeypatch, "if_present")
    assert exc.value.error == "invalid_token"


def test_bound_token_under_bearer_scheme_rejected(client_key, monkeypatch):
    claims = {"cnf": {"jkt": dpop.jwk_thumbprint(_ec_jwk(client_key))}}
    proof = make_proof(client_key, access_token="t")
    with pytest.raises(dpop.DpopError, match="scheme"):
        _enforce("bearer", "t", claims, [proof], monkeypatch, "if_present")


def test_bound_token_without_proof_rejected(client_key, monkeypatch):
    claims = {"cnf": {"jkt": dpop.jwk_thumbprint(_ec_jwk(client_key))}}
    with pytest.raises(dpop.DpopError, match="missing"):
        _enforce("dpop", "t", claims, [], monkeypatch, "if_present")


def test_two_proof_headers_rejected(client_key, monkeypatch):
    claims = {"cnf": {"jkt": dpop.jwk_thumbprint(_ec_jwk(client_key))}}
    p = make_proof(client_key, access_token="t")
    with pytest.raises(dpop.DpopError, match="exactly one"):
        _enforce("dpop", "t", claims, [p, p], monkeypatch, "if_present")


# --- end-to-end through the proxy path ---------------------------------------

_POLICY = Policy(groups={ANALYST_GROUP: ["list_schemas"]})


@pytest.fixture
def policy() -> Policy:
    return _POLICY


def _records(tmp_path):
    log = tmp_path / "audit.log"
    if not log.exists():
        return []
    return [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _call_body() -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_schemas"}}
    ).encode()


def test_bound_token_with_proof_forwards_and_audits_jkt(
    legacy_client, make_token, client_key, tmp_path
):
    jkt = dpop.jwk_thumbprint(_ec_jwk(client_key))
    token = make_token(groups=[ANALYST_GROUP], cnf={"jkt": jkt})
    proof = make_proof(client_key, htu="http://testserver/mcp", access_token=token)
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        resp = legacy_client.post(
            "/mcp",
            content=_call_body(),
            headers={"Authorization": f"DPoP {token}", "DPoP": proof},
        )
    assert resp.status_code == 200
    # The proof is terminated with the token: neither reaches the upstream.
    assert {"authorization", "dpop"}.isdisjoint(route.calls.last.request.headers)
    recs = _records(tmp_path)
    assert len(recs) == 1
    assert recs[0]["channel"] == {"dpop_jkt": jkt}


def test_replayed_proof_is_401_with_dpop_challenge(legacy_client, make_token, client_key):
    jkt = dpop.jwk_thumbprint(_ec_jwk(client_key))
    token = make_token(groups=[ANALYST_GROUP], cnf={"jkt": jkt})
    proof = make_proof(client_key, htu="http://testserver/mcp", access_token=token)
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        first = legacy_client.post(
            "/mcp", content=_call_body(), headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )
        replay = legacy_client.post(
            "/mcp", content=_call_body(), headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )
    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.headers["www-authenticate"].startswith("DPoP ")
    assert "replay" in replay.json()["detail"]


def test_unbound_token_under_the_dpop_scheme_is_401_and_not_forwarded(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP])
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp", content=_call_body(), headers={"Authorization": f"DPoP {token}", "DPoP": "x"}
        )
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]
    assert not route.called


def test_stolen_bound_token_as_bearer_is_401(legacy_client, make_token, client_key):
    jkt = dpop.jwk_thumbprint(_ec_jwk(client_key))
    token = make_token(groups=[ANALYST_GROUP], cnf={"jkt": jkt})
    resp = legacy_client.post(
        "/mcp", content=_call_body(), headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 401  # bound token, no possession proof — dead


def test_edge_headers_recorded_only_when_trusted(legacy_client, make_token, tmp_path, monkeypatch):
    token = make_token(groups=[ANALYST_GROUP])
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert-Serial": "01AB",
        "X-Client-Cert-DN": "CN=pilot-customer",
    }
    with respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        monkeypatch.setattr(main.settings, "trust_edge_headers", False)
        legacy_client.post("/mcp", content=_call_body(), headers=headers)
        monkeypatch.setattr(main.settings, "trust_edge_headers", True)
        legacy_client.post("/mcp", content=_call_body(), headers=headers)

    recs = _records(tmp_path)
    assert recs[0]["channel"] is None  # untrusted: spoofable header ignored
    assert recs[1]["channel"] == {
        "edge_client_cert_serial": "01AB",
        "edge_client_cert_dn": "CN=pilot-customer",
    }
