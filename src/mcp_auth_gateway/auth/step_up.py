"""Step-up: does an already-validated token carry a fresh, strong authentication?

A destructive tool requires an Entra authentication context, surfaced in the
token's ``acrs`` claim, satisfied within ``max_age`` seconds of ``auth_time``.
This is a pure decision over verified claims; the second factor itself happens
between the client and Entra, off the gateway's data path. A token that claims
the context without an ``auth_time`` fails closed: freshness cannot be proven.
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
    """The satisfied authentication-context ids; Entra sends an array, a scalar is tolerated."""
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

    Satisfied only if the context id is in ``acrs`` and ``now - auth_time <= max_age``;
    a missing context, a missing or invalid ``auth_time``, and stale auth all fail closed.
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
    # Only the staleness bound is load-bearing; a negative age (clock skew) is not rejected.
    return StepUpResult(True, "satisfied")
