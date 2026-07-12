"""Step-up auth: does an already-validated token carry a fresh, strong assertion?

A destructive tool (ADR 006) requires the caller to have satisfied an Entra
**authentication context** — surfaced in the token's ``acrs`` claim (an array
of satisfied context ids) — recently enough. This module is the pure decision:
given claims and a :class:`StepUpRequirement`, is step-up satisfied?

It is deliberately a pure function over already-verified claims (the signature/
issuer/audience/expiry checks happened in ``token_validator``). No I/O, no
Entra round-trip — the actual second factor happens between the client and
Entra, off the gateway's data path (the trust boundary). Same unit-testable
shape as the RBAC and ``tools/list``-filter helpers.

Freshness is measured from ``auth_time`` (the time the user authenticated),
which Entra includes when an authentication context is requested. If a token
claims the context but carries no ``auth_time``, we **fail closed** — we cannot
prove freshness, so we re-challenge.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .policy_resolver import StepUpRequirement


@dataclass(frozen=True)
class StepUpResult:
    satisfied: bool
    reason: str  # short machine-ish reason, for the audit record


def _acrs(claims: dict) -> list[str]:
    """The satisfied authentication-context ids. Entra uses ``acrs`` (array);
    tolerate a scalar ``acrs`` just in case a token carries the string form."""
    raw = claims.get("acrs")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [c for c in raw if isinstance(c, str)]
    return []


def evaluate(
    claims: dict, requirement: StepUpRequirement, *, now: float | None = None
) -> StepUpResult:
    """Decide whether ``claims`` satisfy ``requirement``.

    Satisfied iff the required context id is present in ``acrs`` **and** the
    authentication is fresh (``now - auth_time <= max_age``). Missing context,
    missing/invalid ``auth_time``, or stale auth all fail closed.
    """
    if requirement.require_acr not in _acrs(claims):
        return StepUpResult(False, "auth_context_missing")

    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, (int, float)) or isinstance(auth_time, bool):
        # Context claimed but no provable auth time — cannot confirm freshness.
        return StepUpResult(False, "auth_time_missing")

    current = time.time() if now is None else now
    age = current - float(auth_time)
    if age > requirement.max_age:
        return StepUpResult(False, "auth_stale")
    # A wildly future auth_time is nonsensical (clock skew tolerance is small);
    # a small negative age is fine, a large one is suspect — but don't reject on
    # ordinary skew. Only the staleness bound is load-bearing here.
    return StepUpResult(True, "satisfied")
