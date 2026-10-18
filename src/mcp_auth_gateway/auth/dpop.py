"""DPoP (RFC 9449): proof-of-possession for sender-constrained access tokens.

The authorization server binds a token to the client's key by putting the key's
JWK thumbprint in ``cnf.jkt``; the client proves possession on every request with
a ``DPoP`` header, a short JWT signed by that key over the method and URI.
``DPOP_MODE`` is ``off``, ``if_present`` (bound tokens must prove; bearer tokens
still work) or ``required``. No server nonces (§8): the ``iat`` window and the
``jti`` replay cache bound a proof's lifetime instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import urlsplit

import jwt as pyjwt

from ..config import settings

# Asymmetric only — a proof signed with a shared secret proves nothing about
# key possession. Same downgrade defense as the access-token validator.
_ALLOWED_ALGS = ["ES256", "ES384", "RS256", "RS384", "PS256", "PS384"]

# RFC 7638 required members per key type, in lexicographic order.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}

# JWK members that reveal private-key material; a proof jwk carrying any of
# these is malformed (§4.2) and rejected outright.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


class DpopError(Exception):
    """Proof failed validation. ``error`` is the OAuth error code carried on
    the 401 challenge (``invalid_dpop_proof`` unless stated otherwise)."""

    def __init__(self, description: str, error: str = "invalid_dpop_proof") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: SHA-256 over the canonical JSON of the key-type's
    required members, base64url without padding."""
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty", ""))
    if members is None:
        raise DpopError(f"unsupported jwk kty: {jwk.get('kty')!r}")
    try:
        canonical = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":"))
    except KeyError as exc:
        raise DpopError(f"jwk missing required member {exc}") from exc
    return _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def _normalize_htu(url: str) -> str:
    """Comparison form of an ``htu`` (§4.3): no query/fragment, casefolded scheme and host."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def expected_htus(request_url: str, path: str) -> set[str]:
    """The acceptable ``htu`` values for this request: the URL as the gateway
    saw it, plus the same path on ``GATEWAY_EXTERNAL_BASE_URL`` when set —
    behind the edge proxy the client signs the *public* URL."""
    accepted = {_normalize_htu(request_url)}
    base = settings.gateway_external_base_url.rstrip("/")
    if base:
        accepted.add(_normalize_htu(f"{base}{path}"))
    return accepted


class _ReplayCache:
    """Seen ``jti`` values within the acceptance window. In-memory and size-capped,
    so a proof flood cannot grow it without bound; when full, expired entries go
    first, then the oldest."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}  # jti -> expiry (monotonic)

    def check_and_store(self, jti: str, ttl: float) -> bool:
        """False if ``jti`` was already presented (replay); True otherwise."""
        now = time.monotonic()
        if len(self._seen) >= self.max_entries:
            for key, exp in list(self._seen.items()):
                if exp <= now:
                    del self._seen[key]
            while len(self._seen) >= self.max_entries:
                self._seen.pop(next(iter(self._seen)))
        entry = self._seen.get(jti)
        if entry is not None and entry > now:
            return False
        self._seen[jti] = now + ttl
        return True


_replay = _ReplayCache()


def _parse_header(proof: str) -> tuple[str, dict, object]:
    """The proof's ``alg``, its embedded public ``jwk``, and the key object, after
    the header checks: ``typ``, an allowlisted ``alg``, no private-key members."""
    try:
        header = pyjwt.get_unverified_header(proof)
    except pyjwt.InvalidTokenError as exc:
        raise DpopError(f"proof is not a JWT: {exc}") from exc

    if header.get("typ") != "dpop+jwt":
        raise DpopError(f"proof typ must be dpop+jwt, got {header.get('typ')!r}")
    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise DpopError(f"proof alg {alg!r} not allowed")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DpopError("proof header missing embedded jwk")
    if _PRIVATE_JWK_MEMBERS & set(jwk):
        raise DpopError("proof jwk contains private-key members")

    try:
        key = pyjwt.PyJWK(dict(jwk, alg=alg)).key
    except Exception as exc:  # noqa: BLE001 — any unusable key → invalid proof
        raise DpopError(f"proof jwk is not a usable public key: {exc}") from exc
    return alg, jwk, key


def _verify_claims(proof: str, key: object, alg: str) -> dict:
    """The proof's claims once its signature verifies under its own embedded key."""
    try:
        return pyjwt.decode(
            proof,
            key,
            algorithms=[alg],
            options={"require": ["jti", "htm", "htu", "iat"]},
        )
    except pyjwt.InvalidTokenError as exc:
        raise DpopError(f"proof signature/claims invalid: {exc}") from exc


def _check_binding(claims: dict, method: str, accepted_htus: set[str], access_token: str) -> None:
    """The proof names this request (``htm``, ``htu``), is fresh (``iat``), and covers
    the presented token (``ath``)."""
    if claims["htm"] != method.upper():
        raise DpopError(f"proof htm {claims['htm']!r} does not match request method")
    if _normalize_htu(str(claims["htu"])) not in accepted_htus:
        raise DpopError("proof htu does not match this request URI")

    window = settings.dpop_iat_window
    iat = claims["iat"]
    if not isinstance(iat, (int, float)) or abs(time.time() - iat) > window:
        raise DpopError(f"proof iat outside the ±{window}s acceptance window")

    # §4.3 item 12: when presented to a protected resource with an access
    # token, the proof MUST carry ath = b64url(sha256(token)).
    expected_ath = _b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    if claims.get("ath") != expected_ath:
        raise DpopError("proof ath does not match the presented access token")


def validate_proof(
    proof: str,
    *,
    method: str,
    accepted_htus: set[str],
    access_token: str,
    cnf_jkt: str,
) -> str:
    """Validate one DPoP proof against the request + bound token; return the
    proof key's thumbprint (== ``cnf_jkt``) on success, raise DpopError else."""
    alg, jwk, key = _parse_header(proof)
    claims = _verify_claims(proof, key, alg)
    _check_binding(claims, method, accepted_htus, access_token)

    thumbprint = jwk_thumbprint(jwk)
    if thumbprint != cnf_jkt:
        raise DpopError("proof key does not match the token's cnf.jkt binding")

    # Replay goes last, so a proof rejected above never consumes its jti.
    if not _replay.check_and_store(str(claims["jti"]), ttl=settings.dpop_iat_window * 2):
        raise DpopError("proof jti already used (replay)")

    return thumbprint


def enforce(
    *,
    scheme: str,
    access_token: str,
    claims: dict,
    proofs: list[str],
    method: str,
    accepted_htus: set[str],
) -> str | None:
    """Apply ``DPOP_MODE`` to one authenticated request.

    Returns the bound key's thumbprint for the audit record, or ``None`` when the
    token is unbound and bearer use is allowed. Raises :class:`DpopError` otherwise.
    """
    mode = settings.dpop_mode
    if mode == "off":
        return None

    cnf = claims.get("cnf")
    cnf_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None

    if not cnf_jkt:
        if mode == "required":
            raise DpopError(
                "access token is not DPoP-bound (no cnf.jkt) and DPOP_MODE=required",
                error="invalid_token",
            )
        return None

    # The token is sender-constrained: §7.1 — it must be presented under the
    # DPoP scheme with exactly one valid proof. A bound token under Bearer is
    # exactly the stolen-token replay DPoP exists to stop.
    if scheme != "dpop":
        raise DpopError(
            "DPoP-bound token must use the 'Authorization: DPoP' scheme",
            error="invalid_token",
        )
    if len(proofs) != 1:
        raise DpopError(
            "exactly one DPoP header is required" if proofs else "missing DPoP proof header"
        )
    return validate_proof(
        proofs[0],
        method=method,
        accepted_htus=accepted_htus,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
    )
