"""Shared test fixtures.

The token tests need to mint tokens the gateway will accept. We generate an
RSA keypair in-process, sign tokens with the private key, and monkeypatch the
validator's ``PyJWKClient`` to hand back the matching public key — so the full
``jwt.decode`` path (signature, aud, iss, exp, alg allowlist) runs for real
without ever talking to Entra.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://login.microsoftonline.com/test-tenant/v2.0"
AUDIENCE = "test-client-id"
# Phase 1.5: canonical resource URL (Entra Application ID URI form). The token
# aud carries the bare client-id (AUDIENCE); both denote this one resource.
RESOURCE_URL = "api://test-client-id"
ANALYST_GROUP = "11111111-1111-1111-1111-111111111111"
DENIED_GROUP = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_token(rsa_key):
    """Return a factory that mints a signed JWT with overridable claims."""

    def _make(*, alg: str = "RS256", key=None, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-123",
            "oid": "object-id-123",
            "preferred_username": "analyst@example.com",
            "groups": [ANALYST_GROUP],
            "iat": now,
            "exp": now + 3600,
        }
        claims.update(overrides)
        signing_key = key if key is not None else rsa_key
        return jwt.encode(claims, signing_key, algorithm=alg)

    return _make


@pytest.fixture
def validator(rsa_key, monkeypatch):
    """A TokenValidator whose JWKS lookup returns our in-process public key."""
    from mcp_auth_gateway.auth import token_validator as tv

    class _FakeSigningKey:
        key = rsa_key.public_key()

    def _fake_get_signing_key_from_jwt(self, token):  # noqa: ANN001
        return _FakeSigningKey()

    monkeypatch.setattr(
        tv.PyJWKClient, "get_signing_key_from_jwt", _fake_get_signing_key_from_jwt
    )
    # Avoid the constructor's network/config and build directly.
    monkeypatch.setattr(tv.PyJWKClient, "__init__", lambda self, *a, **k: None)
    return tv.TokenValidator(
        jwks_url="https://example/keys", issuer=ISSUER, audience=AUDIENCE
    )
