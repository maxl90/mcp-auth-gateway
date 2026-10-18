"""Audit record construction, hash chaining, and the local sinks.

A record names the acting agent and the human it acted on behalf of, the tool,
the upstream, the outcome, and a correlation id. It carries structural metadata
about the arguments but never their values; there is no switch for that. Each
record is hash-chained to the previous one, so an edit or deletion is detectable
by ``audit.verify``. The schema is locked at ``SCHEMA_VERSION``: 1.x changes are
additive only, because SIEM queries depend on the field names.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from ..config import settings

# Bump only on a breaking field change; additive fields keep 1.x.
# 1.1 added `manifest` (tool-definition hash pinning + drift) and
#   `arguments.conformance` (inputSchema conformance telemetry).
# 1.2 added `channel`: the edge proxy's client-cert serial/DN and the DPoP key
#   thumbprint, so a record carries network identity and token identity.
SCHEMA_VERSION = "1.2"

# degraded: an upstream was unavailable while serving an aggregated request, so
#   the catalog was partial; the record keeps that from being silent.
# step_up_required: a destructive call was permitted by RBAC but lacked a fresh,
#   strong authentication; it was challenged, not forwarded.
# manifest_drift: an observed tool manifest differs from the pinned baseline
#   (possible rug-pull or poisoning). Evidence only, never a gate.
Outcome = Literal["allowed", "denied", "degraded", "step_up_required", "manifest_drift"]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _actor(claims: dict | None) -> dict:
    """The acting agent (``azp``/``appid``) and the human it acted for (``oid``, username, ``sub``);
    either may be ``None``, and an app-only token (``idtyp: app``) has no human."""
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


@dataclass(frozen=True)
class AuditEvent:
    """What one audit record attests.

    ``structure``, ``manifest``, ``conformance`` and ``channel`` are the
    value-free evidence stamps; argument values are never part of an event.
    """

    outcome: Outcome
    tool: str | None
    correlation_id: str
    claims: dict | None = None
    reason: str | None = None
    upstream: str | None = None
    structure: dict | None = None
    manifest: dict | None = None
    conformance: dict | None = None
    channel: dict | None = None


def build_record(event: AuditEvent) -> dict:
    """Build the audit record **content** (everything except the integrity
    chain, which ``write`` adds). Argument *values* are intentionally absent —
    only ``structure`` and ``conformance`` (both value-free) are carried."""
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": _now_iso(),
        "correlation_id": event.correlation_id,
        "tenant_id": (event.claims or {}).get("tid"),
        "actor": _actor(event.claims),
        # Transport-layer identity (v1.2): edge mTLS cert serial/DN + DPoP key
        # thumbprint, when present. None on records with no channel evidence.
        "channel": event.channel,
        "tool": event.tool,
        "upstream": event.upstream,
        "outcome": event.outcome,
        "reason": event.reason,
        # Pinned tool-definition hash: {"sha256"} on tool calls (what the agent
        # saw); + {"previous_sha256"} on manifest_drift records. None elsewhere.
        "manifest": event.manifest,
        "arguments": {
            "redacted": True,
            "structure": event.structure,
            "conformance": event.conformance,
        },
    }


# --- integrity chain -------------------------------------------------------

GENESIS = "0" * 64  # prev_hash of the first record in a chain


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
    """The last record's hash, so a restart continues the chain rather than forking it;
    ``None`` (genesis) when the log is missing, empty, or its tail is corrupt."""
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


def record(event: AuditEvent) -> dict:
    """Build and write in one call; returns the chained record."""
    return write(build_record(event))
