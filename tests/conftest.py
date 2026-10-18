"""Shared test fixtures.

Tokens are minted with an in-process RSA key and the validator's ``PyJWKClient``
is patched to hand back the matching public key, so the full ``jwt.decode`` path
(signature, aud, iss, exp, alg allowlist) runs for real without Entra. The
``gateway_client`` factory drives the real ASGI app with that validator, a policy,
a temp audit log, and either the single-upstream proxy or aggregation mode;
``legacy_client`` and ``aggregate_client`` are the two ready-made shapes, and a
module overrides ``policy`` (and ``upstreams``) to supply its own.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from mcp_auth_gateway import main
from mcp_auth_gateway import upstreams as upstreams_mod
from mcp_auth_gateway.aggregator import registry as registry_mod
from mcp_auth_gateway.aggregator.registry import InMemorySessionRegistry
from mcp_auth_gateway.audit import writer
from mcp_auth_gateway.auth import enforce
from mcp_auth_gateway.auth.policy_resolver import Policy
from mcp_auth_gateway.upstreams import Upstream

ISSUER = "https://login.microsoftonline.com/test-tenant/v2.0"
AUDIENCE = "test-client-id"
# Canonical resource URL (Entra Application ID URI form). The token aud carries
# the bare client-id (AUDIENCE); both denote this one resource.
RESOURCE_URL = "api://test-client-id"
ANALYST_GROUP = "11111111-1111-1111-1111-111111111111"
DENIED_GROUP = "22222222-2222-2222-2222-222222222222"

# Upstream addresses the respx mocks answer for.
UPSTREAM = "http://localhost:9000/mcp"
PG_URL = "http://pg-upstream:9000/mcp"
GH_URL = "http://gh-upstream:9001/mcp"


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
        claims = {k: v for k, v in claims.items() if v is not None}  # None drops a claim
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

    monkeypatch.setattr(tv.PyJWKClient, "get_signing_key_from_jwt", _fake_get_signing_key_from_jwt)
    # Avoid the constructor's network/config and build directly.
    monkeypatch.setattr(tv.PyJWKClient, "__init__", lambda self, *a, **k: None)
    return tv.TokenValidator(jwks_url="https://example/keys", issuer=ISSUER, audience=AUDIENCE)


@pytest.fixture
def policy() -> Policy:
    """The RBAC policy the gateway fixtures load. A module overrides it with its own."""
    return Policy(groups={ANALYST_GROUP: ["list_schemas"], DENIED_GROUP: []}, destructive=[])


@pytest.fixture
def upstreams() -> list[Upstream]:
    """The upstream list aggregation-mode fixtures inject. A module overrides it."""
    return [Upstream("postgres", PG_URL), Upstream("github", GH_URL)]


@pytest.fixture
def gateway_client(validator, monkeypatch, tmp_path):
    """Factory for a ``TestClient`` over the real app.

    ``gateway_client(mode, policy, **settings)`` yields a client with auth on, the
    in-process validator, ``policy`` loaded, a temp audit log, and either the
    single-upstream proxy (``"single"``, pointed at ``UPSTREAM``) or aggregation
    mode (``"aggregate"``, with ``upstreams`` injected and a fresh session
    registry). Extra keyword arguments override settings.
    """

    @contextlib.contextmanager
    def _make(
        mode: str,
        policy: Policy,
        *,
        upstreams: list[Upstream] | None = None,
        **settings_overrides: object,
    ) -> Iterator[TestClient]:
        monkeypatch.setattr(enforce, "get_validator", lambda: validator)
        monkeypatch.setattr(enforce, "get_policy", lambda: policy)
        values: dict[str, object] = {
            "auth_enabled": True,
            "gateway_resource_url": RESOURCE_URL,
            "gateway_issuer": ISSUER,
            "gateway_external_base_url": "",
            "dpop_mode": "if_present",
            "audit_log_path": str(tmp_path / "audit.log"),
            "upstream_mcp_url": UPSTREAM,
            "upstreams_config_path": "injected" if mode == "aggregate" else "",
        }
        values.update(settings_overrides)
        for name, value in values.items():
            monkeypatch.setattr(main.settings, name, value)
        if mode == "aggregate":
            monkeypatch.setattr(upstreams_mod, "_upstreams", upstreams)
            monkeypatch.setattr(registry_mod, "_registry", InMemorySessionRegistry())
        writer._chain["path"] = None  # a fresh chain for the temp log
        writer._chain["last_hash"] = None
        with TestClient(main.app) as c:
            yield c

    return _make


@pytest.fixture
def legacy_client(gateway_client, policy):
    """The single-upstream proxy with the module's policy."""
    with gateway_client("single", policy) as c:
        yield c


@pytest.fixture
def aggregate_client(gateway_client, policy, upstreams):
    """Aggregation mode with the module's policy and upstreams."""
    with gateway_client("aggregate", policy, upstreams=upstreams) as c:
        yield c
