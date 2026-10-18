"""Token validation — the AuthN half of the gateway."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_auth_gateway.auth.token_validator import TokenError

from .conftest import ANALYST_GROUP, AUDIENCE, ISSUER


def test_valid_token_passes(validator, make_token):
    claims = validator.validate(make_token())
    assert claims["aud"] == AUDIENCE
    assert claims["iss"] == ISSUER
    assert ANALYST_GROUP in claims["groups"]


def test_expired_token_rejected(validator, make_token):
    now = int(time.time())
    with pytest.raises(TokenError):
        validator.validate(make_token(iat=now - 7200, exp=now - 3600))


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


def test_validate_token_unsupported_algorithm(validator, make_token):
    """HS256 forged with a key the gateway can see is rejected — the alg is not
    on the RS-family allowlist (downgrade defense)."""
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 3600},
        "shared-secret",
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        validator.validate(forged)


def test_token_signed_by_wrong_key_rejected(validator, make_token):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenError):
        validator.validate(make_token(key=other))


# --- JWKS rotation handling ----------------------------------------------------


def _rotation_validator(monkeypatch, resolver):
    from mcp_auth_gateway.auth import token_validator as tv

    monkeypatch.setattr(tv.PyJWKClient, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(tv.PyJWKClient, "get_signing_key_from_jwt", resolver)
    return tv.TokenValidator(jwks_url="https://example/keys", issuer=ISSUER, audience=AUDIENCE)


def test_rotated_key_triggers_refetch_and_succeeds(monkeypatch, rsa_key, make_token):
    """A key not in the cached JWK set (just rotated) forces one refresh + retry,
    which then resolves — rather than failing until the cache lifespan expires."""
    from jwt.exceptions import PyJWKClientError

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


def test_jwks_refresh_is_throttled(monkeypatch, make_token):
    """Repeated unresolvable tokens (e.g. a bogus-`kid` flood) must not amplify
    into a JWKS-fetch per request — refresh is rate-limited."""
    from jwt.exceptions import PyJWKClientError

    from mcp_auth_gateway.auth import token_validator as tv

    def resolver(self, token):
        raise PyJWKClientError("never resolves")

    monkeypatch.setattr(tv.settings, "jwks_refresh_min_interval", 10_000)
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
