"""Entra ID access-token validation.

The token is verified locally against the tenant's JWKS: signature, issuer,
audience and expiry. It is never sent anywhere else. A key-resolution miss
forces one throttled JWKS refresh, so a rotated signing key is picked up at
once without letting bogus ``kid`` floods turn into a fetch storm.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import cast

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from ..config import settings
from .claims import Claims

logger = logging.getLogger("mcp_auth_gateway.auth")

# Asymmetric algorithms only. HMAC (HS*) and ``none`` are deliberately absent:
# a token presenting any of them is rejected because its ``alg`` is not on this
# allowlist — the standard JWT downgrade/confused-key defense.
_ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512"]

# Client-facing: it flows into the WWW-Authenticate challenge, so it names nothing
# internal. Raw exception text goes to the server log only.
_KEY_RESOLUTION_ERROR = "unable to resolve token signing key"


class TokenError(Exception):
    """Token failed validation. Carries the OAuth ``error`` code + description
    the proxy surfaces in the ``WWW-Authenticate`` header on its 401."""

    def __init__(self, description: str, error: str = "invalid_token") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


class TokenValidator:
    """One per app, around a cached ``PyJWKClient``.

    Within the cache lifespan a token signed by a freshly rotated key would fail to
    resolve, so a miss triggers one forced refresh and a retry, rate-limited by
    ``jwks_refresh_min_interval``.

    :meth:`validate` blocks while the JWK set is fetched, so a caller on an event
    loop runs it on a worker thread. It is safe to call from several at once:
    PyJWKClient (2.14 and later) fetches under a lock and cools down between
    forced refreshes, and the refresh here takes a lock of its own.
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
        # -inf so the first forced refresh is never throttled on a freshly booted host.
        self._last_refresh = float("-inf")
        self._refresh_lock = threading.Lock()

    def _new_client(self) -> PyJWKClient:
        return PyJWKClient(
            self._jwks_url,
            cache_jwk_set=True,
            lifespan=settings.jwks_cache_lifespan,
        )

    def _refresh_jwks(self) -> bool:
        """Drop the cached JWK set, at most once per ``jwks_refresh_min_interval``."""
        with self._refresh_lock:
            now = time.monotonic()
            if now - self._last_refresh < settings.jwks_refresh_min_interval:
                return False
            self._last_refresh = now
            self._jwk_client = self._new_client()  # a new client re-fetches on next use
            return True

    def validate(self, token: str) -> Claims:
        """Return the verified claims, or raise :class:`TokenError`."""
        client = self._jwk_client
        try:
            signing_key = client.get_signing_key_from_jwt(token)
        except PyJWKClientError as exc:
            # Possibly a rotated key not yet cached: one throttled refresh, then retry.
            # A refresh another validation made since the miss counts as this one's.
            if self._refresh_jwks() or self._jwk_client is not client:
                try:
                    signing_key = self._jwk_client.get_signing_key_from_jwt(token)
                except Exception as exc2:  # any failure → invalid_token
                    logger.warning("signing key resolution failed after refresh: %s", exc2)
                    raise TokenError(_KEY_RESOLUTION_ERROR) from exc2
            else:
                logger.warning("signing key resolution failed (refresh throttled): %s", exc)
                raise TokenError(_KEY_RESOLUTION_ERROR) from exc
        except Exception as exc:  # network, malformed token, etc.
            logger.warning("signing key resolution failed: %s", exc)
            raise TokenError(_KEY_RESOLUTION_ERROR) from exc

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
        except (jwt.PyJWTError, TypeError) as exc:
            # The unverified kid named a JWKS key of another type than the token's alg;
            # PyJWT raises TypeError or InvalidKeyError for that, not InvalidTokenError.
            logger.warning("signing key does not fit the token's alg: %s", exc)
            raise TokenError("token signing key does not match its algorithm") from exc

        # Signed by the tenant and checked for iss, aud and exp; ``Claims`` types the rest.
        return cast(Claims, claims)
