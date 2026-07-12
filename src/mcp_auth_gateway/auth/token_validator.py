"""Entra ID token validation.

Validates the caller's OAuth 2.1 access token against the tenant's JWKS
endpoint and returns its claims. The token is verified *locally* — the gateway
fetches Entra's public signing keys and checks the signature, issuer, audience,
and expiry itself. The token is never sent anywhere (the trust boundary).

Phase 1.5 hardens the audience/issuer rules further (RFC 8707/9207); this module
already does the core RS256-family JWKS validation those build on.
"""

from __future__ import annotations

import logging
import time

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from ..config import settings

logger = logging.getLogger("mcp_auth_gateway.auth")

# Asymmetric algorithms only. HMAC (HS*) and ``none`` are deliberately absent:
# a token presenting any of them is rejected because its ``alg`` is not on this
# allowlist — the standard JWT downgrade/confused-key defense.
_ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512"]


class TokenError(Exception):
    """Token failed validation. Carries the OAuth ``error`` code + description
    the proxy surfaces in the ``WWW-Authenticate`` header on its 401."""

    def __init__(self, description: str, error: str = "invalid_token") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


class TokenValidator:
    """Wraps a cached ``PyJWKClient``. One instance per process — ``PyJWKClient``
    caches the fetched JWK set (``lifespan`` seconds), so only the first
    validation in each window hits Entra.

    **Key rotation:** Entra rotates signing keys periodically. Within the cache
    lifespan a token signed by a freshly-rotated key would fail resolution
    ("no matching key") until the cache expires. To pick up a rotation
    immediately, a resolution miss triggers **one throttled forced refresh** of
    the JWK set and a retry. The refresh is rate-limited
    (``jwks_refresh_min_interval``) so a flood of tokens with bogus ``kid`` values
    can't turn this into a JWKS-fetch amplification/DoS.
    """

    def __init__(
        self,
        jwks_url: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        self._jwks_url = jwks_url or settings.gateway_jwks_url
        self._issuer = issuer or settings.gateway_issuer
        self._audience = audience or settings.gateway_audience
        if not (self._jwks_url and self._issuer and self._audience):
            raise RuntimeError(
                "Token validation requires GATEWAY_JWKS_URL, GATEWAY_ISSUER, and "
                "GATEWAY_AUDIENCE to be set (see .env.generated from provisioning)."
            )
        self._jwk_client = self._new_client()
        # -inf, not 0.0: time.monotonic() counts from host boot, so with 0.0 a
        # freshly booted host (uptime < jwks_refresh_min_interval) would wrongly
        # throttle the FIRST rotation refresh. -inf guarantees the first forced
        # refresh is always allowed.
        self._last_refresh = float("-inf")

    def _new_client(self) -> PyJWKClient:
        # cache_jwk_set + lifespan: hold the fetched set briefly to avoid a
        # per-request round trip to Entra; a rotation mid-lifespan is handled by
        # the forced refresh in validate().
        return PyJWKClient(
            self._jwks_url,
            cache_jwk_set=True,
            lifespan=settings.jwks_cache_lifespan,
        )

    def _refresh_jwks(self) -> bool:
        """Force a fresh JWKS fetch by dropping the cache — but no more often than
        ``jwks_refresh_min_interval`` seconds. Returns True if it refreshed."""
        now = time.monotonic()
        if now - self._last_refresh < settings.jwks_refresh_min_interval:
            return False
        self._last_refresh = now
        self._jwk_client = self._new_client()  # a new client re-fetches on next use
        return True

    def validate(self, token: str) -> dict:
        """Return the verified claims, or raise :class:`TokenError`."""
        # The description below flows into the client-facing WWW-Authenticate
        # challenge, so it stays generic — raw exception text (which can name
        # the JWKS URL or internal network errors) goes to the server log only.
        _KEY_ERROR = "unable to resolve token signing key"
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
        except PyJWKClientError as exc:
            # Possibly a rotated key not yet in our cached set — force one
            # throttled refresh and retry before giving up.
            if self._refresh_jwks():
                try:
                    signing_key = self._jwk_client.get_signing_key_from_jwt(token)
                except Exception as exc2:  # noqa: BLE001 — any failure → invalid_token
                    logger.warning("signing key resolution failed after refresh: %s", exc2)
                    raise TokenError(_KEY_ERROR) from exc2
            else:
                logger.warning("signing key resolution failed (refresh throttled): %s", exc)
                raise TokenError(_KEY_ERROR) from exc
        except Exception as exc:  # network, malformed token, etc.
            logger.warning("signing key resolution failed: %s", exc)
            raise TokenError(_KEY_ERROR) from exc

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=_ALLOWED_ALGORITHMS,
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("token expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenError("token audience does not match this gateway") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenError("token issuer is not the configured tenant") from exc
        except jwt.InvalidTokenError as exc:  # signature, alg, missing claim, etc.
            raise TokenError(f"invalid token: {exc}") from exc

        return claims


_validator: TokenValidator | None = None


def get_validator() -> TokenValidator:
    """Lazily build the process-wide validator (defers the JWKS-config check
    until auth is actually needed, so Phase 0 passthrough still imports clean)."""
    global _validator
    if _validator is None:
        _validator = TokenValidator()
    return _validator
