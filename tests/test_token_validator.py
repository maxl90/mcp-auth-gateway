"""Token validation — the AuthN half of the gateway."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.exceptions import PyJWKClientError

from mcp_auth_gateway.auth import token_validator
from mcp_auth_gateway.auth.token_validator import TokenError, TokenValidator

from .conftest import ANALYST_GROUP, AUDIENCE, ISSUER, UPSTREAM, LocalKeyValidator


def test_valid_token_passes(validator, make_token):
    claims = validator.validate(make_token())
    assert claims["aud"] == AUDIENCE
    assert claims["iss"] == ISSUER
    assert ANALYST_GROUP in claims["groups"]


def test_expired_token_rejected(validator, make_token):
    now = int(time.time())
    with pytest.raises(TokenError):
        validator.validate(make_token(iat=now - 7200, exp=now - 3600))


def test_not_yet_valid_token_rejected(validator, make_token):
    with pytest.raises(TokenError):
        validator.validate(make_token(nbf=int(time.time()) + 3600))


def test_wrong_audience_rejected(validator, make_token):
    with pytest.raises(TokenError):
        validator.validate(make_token(aud="some-other-resource"))


def test_array_audience_with_match_passes(validator, make_token):
    """RFC 8707: `aud` may be an array; accept if any entry is the
    gateway's audience, even alongside audiences for other resources."""
    claims = validator.validate(make_token(aud=[AUDIENCE, "another-resource"]))
    assert AUDIENCE in claims["aud"]


def test_missing_audience_rejected(validator, rsa_key):
    """A token with no `aud` claim is rejected (require aud)."""
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "iat": now, "exp": now + 3600, "groups": [ANALYST_GROUP]},
        rsa_key,
        algorithm="RS256",
    )
    with pytest.raises(TokenError):
        validator.validate(token)


def test_wrong_issuer_rejected(validator, make_token):
    with pytest.raises(TokenError):
        validator.validate(make_token(iss="https://evil.example/v2.0"))


def test_validate_token_unsupported_algorithm(validator):
    """HS256 forged with a key the gateway can see is rejected — the alg is not
    on the RS-family allowlist (downgrade defense)."""
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 3600},
        "shared-secret",
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        validator.validate(forged)


def test_unsigned_alg_none_token_rejected(validator):
    unsigned = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 3600, "groups": [ANALYST_GROUP]},
        None,
        algorithm="none",
    )
    with pytest.raises(TokenError):
        validator.validate(unsigned)


def test_token_signed_by_wrong_key_rejected(validator, make_token):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenError):
        validator.validate(make_token(key=other))


def test_validation_needs_the_tenant_settings(monkeypatch):
    for name in ("gateway_jwks_url", "gateway_issuer", "gateway_audience"):
        monkeypatch.setattr(token_validator.settings, name, "")
    with pytest.raises(RuntimeError, match="GATEWAY_JWKS_URL"):
        token_validator.TokenValidator()


# --- the event loop ------------------------------------------------------------


class _SlowJwksValidator(LocalKeyValidator):
    """Every key lookup blocks for ``delay`` seconds, as a cold-cache JWKS fetch does."""

    def __init__(self, public_key, delay: float) -> None:
        self._delay = delay
        self.fetching = threading.Event()
        super().__init__(public_key)

    def _new_client(self):
        local = super()._new_client()

        def fetch(token):
            self.fetching.set()
            time.sleep(self._delay)
            return local.get_signing_key_from_jwt(token)

        return SimpleNamespace(get_signing_key_from_jwt=fetch)


def test_a_slow_jwks_fetch_does_not_stall_other_requests(
    gateway_client, policy, rsa_key, make_token
):
    # Resolving the signing key can block on a JWKS fetch. The gateway keeps
    # answering other requests meanwhile, because the lookup runs on a thread.
    slow = _SlowJwksValidator(rsa_key.public_key(), delay=1.0)
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    with gateway_client("single", policy, validator=slow) as client, respx.mock:
        respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(
                client.post, "/mcp", json=ping, headers={"Authorization": f"Bearer {make_token()}"}
            )
            assert slow.fetching.wait(timeout=5)  # the first request is in the lookup
            start = time.monotonic()
            assert client.get("/healthz").status_code == 200
            waited = time.monotonic() - start
            assert pending.result().status_code == 200
    assert waited < 0.5


# --- JWKS rotation handling ----------------------------------------------------


def _rotation_validator(monkeypatch, resolver):
    monkeypatch.setattr(token_validator.PyJWKClient, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(token_validator.PyJWKClient, "get_signing_key_from_jwt", resolver)
    return token_validator.TokenValidator(
        jwks_url="https://example/keys", issuer=ISSUER, audience=AUDIENCE
    )


def test_rotated_key_triggers_refetch_and_succeeds(monkeypatch, rsa_key, make_token):
    """A key not in the cached JWK set (just rotated) forces one refresh + retry,
    which then resolves — rather than failing until the cache lifespan expires."""

    class _Key:
        key = rsa_key.public_key()

    calls = {"n": 0}

    def resolver(self, token):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PyJWKClientError("no matching key (rotated)")
        return _Key()

    v = _rotation_validator(monkeypatch, resolver)
    claims = v.validate(make_token())
    assert claims["aud"] == AUDIENCE
    assert calls["n"] == 2  # first miss, refetch, second resolves


def test_a_key_lookup_that_fails_outright_is_an_invalid_token(monkeypatch, make_token):
    def resolver(self, token):
        raise ValueError("connection reset")

    v = _rotation_validator(monkeypatch, resolver)
    with pytest.raises(TokenError, match="unable to resolve token signing key"):
        v.validate(make_token())


def test_a_rotation_two_requests_meet_at_once_resolves_for_both(rsa_key, make_token):
    # Both miss the new kid on the stale client before either refreshes. One
    # refreshes; the other is throttled, and must retry on the refreshed client
    # rather than answer 401.
    both_missed = threading.Barrier(2, timeout=5)
    signing_key = SimpleNamespace(key=rsa_key.public_key())
    clients = []

    def stale(token):
        both_missed.wait()
        raise PyJWKClientError("kid not in the cached set")

    class _Rotating(TokenValidator):
        def _new_client(self):
            clients.append(None)
            fetch = stale if len(clients) == 1 else (lambda token: signing_key)
            return SimpleNamespace(get_signing_key_from_jwt=fetch)

    v = _Rotating(jwks_url="https://example/keys", issuer=ISSUER, audience=AUDIENCE)
    token = make_token()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: v.validate(token), range(2)))
    assert [r["aud"] for r in results] == [AUDIENCE, AUDIENCE]
    assert len(clients) == 2  # one refresh between them


def test_jwks_refresh_is_throttled(monkeypatch, make_token):
    """Repeated unresolvable tokens (e.g. a bogus-`kid` flood) must not amplify
    into a JWKS-fetch per request — refresh is rate-limited."""

    def resolver(self, token):
        raise PyJWKClientError("never resolves")

    monkeypatch.setattr(token_validator.settings, "jwks_refresh_min_interval", 10_000)
    v = _rotation_validator(monkeypatch, resolver)

    refreshes = {"n": 0}
    real_new = v._new_client
    monkeypatch.setattr(
        v, "_new_client", lambda: refreshes.__setitem__("n", refreshes["n"] + 1) or real_new()
    )

    with pytest.raises(TokenError):
        v.validate(make_token())
    with pytest.raises(TokenError):
        v.validate(make_token())  # within the interval → throttled
    assert refreshes["n"] == 1  # refreshed once, not twice


def test_kid_naming_a_key_of_another_type_is_invalid_not_a_crash(monkeypatch, make_token):
    """The unverified ``kid`` picks the JWKS key. If it names an EC key while the header
    says RS256, PyJWT raises TypeError, which must still be an invalid token."""

    class _EcKey:
        key = ec.generate_private_key(ec.SECP256R1()).public_key()

    v = _rotation_validator(monkeypatch, lambda self, token: _EcKey())
    with pytest.raises(TokenError):
        v.validate(make_token())
