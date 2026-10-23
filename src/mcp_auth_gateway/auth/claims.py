"""The access-token claims the gateway reads.

The validator proves the token is Entra's and checks ``iss``, ``aud`` and ``exp``;
nothing after it reads those three. The claims here are typed as Entra issues
them, and nothing enforces those types at runtime, so code that depends on a
claim's shape still checks it.
"""

from __future__ import annotations

from typing import TypedDict


class Confirmation(TypedDict, total=False):
    """``cnf`` (RFC 7800): the key a DPoP-bound token is bound to."""

    jkt: str


class Claims(TypedDict, total=False):
    """A validated access token's payload, limited to the claims the gateway reads."""

    tid: str
    # The human: object id, username (v2, then v1) and subject.
    oid: str
    preferred_username: str
    upn: str
    sub: str
    # The acting app (v2, then v1), and "app" on an app-only token.
    azp: str
    appid: str
    app_displayname: str
    idtyp: str
    groups: list[str]
    # Present instead of ``groups`` when the user is in too many groups (overage).
    _claim_names: dict[str, str]
    # Authentication contexts satisfied; Entra sends a list, a string is tolerated.
    acrs: list[str] | str
    auth_time: int
    cnf: Confirmation


def principal(claims: Claims | None) -> str | None:
    """Who the caller is: the human's ``oid``, else ``sub``, else the app's ``azp``."""
    if not claims:
        return None
    return claims.get("oid") or claims.get("sub") or claims.get("azp")
