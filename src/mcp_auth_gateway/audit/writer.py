"""Audit record construction, integrity chaining, and sinks.

A record captures *who* — distinguishing the **acting agent** (the app/agent
identity) from the **human principal** it acted on behalf of (the attribution
problem: agents run under user credentials, so naive logs blame the human) —
*what* tool, on *which* upstream, *when*, the *outcome*, and a *correlation id*.
It records **structural** metadata about the arguments (which tables/columns a
query touched, argument keys) but **never the argument values**: redaction is
default and there is no flag to disable it.

Each record is **hash-chained** to the previous one (``integrity.prev_hash`` /
``integrity.record_hash``): deleting or editing any past record breaks the chain
and is detectable by ``audit.verify`` — tamper-evident, GRC-grade evidence. The
chain assumes a single writer process (the gateway is single-process async);
multi-replica aggregation would chain per-replica.

The schema is **locked** (``SCHEMA_VERSION``, currently 1.2) for stable SIEM
ingestion — renaming or removing fields post-launch forces early adopters to
rewrite queries; 1.x changes are strictly additive.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from ..config import settings

# Bump only on a breaking field change; additive fields keep 1.x.
# 1.1 (additive): `manifest` (tool-definition hash pinning + drift) and
#   `arguments.conformance` (inputSchema conformance telemetry).
# 1.2 (additive): `channel` — transport-layer identity: the edge proxy's
#   client-cert serial/DN (mTLS network identity) and the DPoP key thumbprint
#   (token binding). Network identity + token identity = the two-factor audit
#   trail (ADR 008).
SCHEMA_VERSION = "1.2"

# allowed / denied — Phase 1 authz outcomes.
# degraded — Phase 3: an upstream was unavailable while serving an aggregated
#   request (partial catalog); this record keeps that from being silent.
# step_up_required — Phase 2 (ADR 006): a destructive call was RBAC-permitted but
#   lacked a fresh, strong auth assertion — challenged, not forwarded.
# manifest_drift — backlog item 10: an observed tool manifest differs from the
#   pinned baseline (possible rug-pull/poisoning). Evidence only, never a gate.
Outcome = Literal["allowed", "denied", "degraded", "step_up_required", "manifest_drift"]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _actor(claims: dict | None) -> dict:
    """Split the token's identity into the acting **agent** and the **human**
    it acted on behalf of — the attribution problem, made explicit.

    - Agent (the app/client making the call): Entra puts the client id in ``azp``
      (v2) or ``appid`` (v1); an optional display name in ``app_displayname``.
    - Human principal: ``oid`` (stable per user/tenant), ``preferred_username`` /
      ``upn``, and ``sub`` (pairwise per-app).

    Either side may be absent: an app-only token (no user) yields
    ``on_behalf_of: null``; a token with no client claim yields ``agent: null``.
    ``idtyp`` (``app`` | ``user``) disambiguates when present.
    """
    if not claims:
        return {"agent": None, "on_behalf_of": None}

    app_id = claims.get("azp") or claims.get("appid")
    agent = None
    if app_id:
        agent = {"app_id": app_id, "name": claims.get("app_displayname")}

    # An app-only token authenticates no user. Entra marks these idtyp=app; as a
    # fallback, an app-only token carries no oid/upn distinct from the app.
    idtyp = claims.get("idtyp")
    has_user = bool(claims.get("oid") or claims.get("preferred_username") or claims.get("upn"))
    on_behalf_of = None
    if idtyp != "app" and has_user:
        on_behalf_of = {
            "oid": claims.get("oid"),
            "username": claims.get("preferred_username") or claims.get("upn"),
            "sub": claims.get("sub"),
        }
    return {"agent": agent, "on_behalf_of": on_behalf_of}


def build_record(
    *,
    outcome: Outcome,
    tool: str | None,
    correlation_id: str,
    claims: dict | None = None,
    reason: str | None = None,
    upstream: str | None = None,
    structure: dict | None = None,
    manifest: dict | None = None,
    conformance: dict | None = None,
    channel: dict | None = None,
) -> dict:
    """Build the audit record **content** (everything except the integrity
    chain, which ``write`` adds). Argument *values* are intentionally absent —
    only ``structure`` and ``conformance`` (both value-free) are carried."""
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": _now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": (claims or {}).get("tid"),
        "actor": _actor(claims),
        # Transport-layer identity (v1.2): edge mTLS cert serial/DN + DPoP key
        # thumbprint, when present. None on records with no channel evidence.
        "channel": channel,
        "tool": tool,
        "upstream": upstream,
        "outcome": outcome,
        "reason": reason,
        # Pinned tool-definition hash: {"sha256"} on tool calls (what the agent
        # saw); + {"previous_sha256"} on manifest_drift records. None elsewhere.
        "manifest": manifest,
        "arguments": {
            "redacted": True,  # explicit: raw values are never recorded
            "structure": structure,  # value-free metadata (tables/columns/keys) or None
            # inputSchema conformance verdict (value-free violations) or None.
            "conformance": conformance,
        },
    }


# --- integrity chain -------------------------------------------------------

GENESIS = "0" * 64  # prev_hash of the first record in a chain
_GENESIS = GENESIS  # deprecated alias, kept for back-compat


def compute_hash(content: dict, prev_hash: str | None) -> str:
    """Deterministic SHA-256 over the record content + the previous hash.

    ``content`` is the record **without** its ``integrity`` block. Canonical
    JSON (sorted keys) makes the hash reproducible for verification."""
    payload = {"prev_hash": prev_hash or GENESIS, "record": content}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Per-process chain state, keyed by the log path so a path change (tests, config
# swap) re-seeds cleanly rather than chaining across unrelated logs.
_chain: dict[str, str | None] = {"path": None, "last_hash": None}


def _seed_last_hash(path: Path) -> str | None:
    """On first write to a path, continue the existing chain by reading the last
    record's ``record_hash`` from the log tail (so a restart doesn't fork the
    chain). Missing/empty/corrupt tail → genesis (``None``)."""
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)["integrity"]["record_hash"]
        except (ValueError, KeyError, TypeError):
            return None  # corrupt tail — start a fresh link rather than crash
    return None


def _next(content: dict, path: Path) -> dict:
    """Attach the integrity block, advancing the per-path chain."""
    key = str(path)
    if _chain["path"] != key:
        _chain["path"] = key
        _chain["last_hash"] = _seed_last_hash(path)
    prev = _chain["last_hash"]
    record_hash = compute_hash(content, prev)
    _chain["last_hash"] = record_hash
    return {**content, "integrity": {"prev_hash": prev or GENESIS, "record_hash": record_hash}}


def write(content: dict) -> dict:
    """Chain ``content``, emit it as one JSON line to stdout and the log file,
    and return the chained record (with its integrity block)."""
    path = Path(settings.audit_log_path)
    chained = _next(content, path)
    line = json.dumps(chained, separators=(",", ":"), ensure_ascii=False)
    print(line, file=sys.stdout, flush=True)
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:  # never let an audit-sink failure drop the request
        print(
            json.dumps({"audit_error": str(exc), "path": str(path)}),
            file=sys.stderr,
            flush=True,
        )
    return chained


def record(
    *,
    outcome: Outcome,
    tool: str | None,
    correlation_id: str,
    claims: dict | None = None,
    reason: str | None = None,
    upstream: str | None = None,
    structure: dict | None = None,
    manifest: dict | None = None,
    conformance: dict | None = None,
    channel: dict | None = None,
) -> dict:
    """Build and write in one call; returns the chained record."""
    return write(
        build_record(
            outcome=outcome,
            tool=tool,
            correlation_id=correlation_id,
            claims=claims,
            reason=reason,
            upstream=upstream,
            structure=structure,
            manifest=manifest,
            conformance=conformance,
            channel=channel,
        )
    )
