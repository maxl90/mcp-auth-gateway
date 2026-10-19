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
import logging
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

from ..auth.claims import Claims

logger = logging.getLogger("mcp_auth_gateway.audit")

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


class Agent(TypedDict):
    app_id: str
    name: str | None


class OnBehalfOf(TypedDict):
    oid: str | None
    username: str | None
    sub: str | None


class Actor(TypedDict):
    agent: Agent | None
    on_behalf_of: OnBehalfOf | None


class Channel(TypedDict, total=False):
    """Transport-layer identity: the edge proxy's client cert and the DPoP key."""

    edge_client_cert_serial: str | None
    edge_client_cert_dn: str | None
    dpop_jkt: str


class ManifestStamp(TypedDict):
    """The pinned tool-definition hash; a drift record also carries the old one."""

    sha256: str
    previous_sha256: NotRequired[str | None]


class Arguments(TypedDict):
    """What a record says about the call's arguments. Never their values."""

    redacted: Literal[True]
    structure: dict[str, Any] | None
    conformance: dict[str, Any] | None


class RecordContent(TypedDict):
    """A record before chaining: everything the hash covers."""

    schema_version: str
    ts: str
    correlation_id: str
    tenant_id: str | None
    actor: Actor
    channel: Channel | None
    tool: str | None
    upstream: str | None
    outcome: Outcome
    reason: str | None
    manifest: ManifestStamp | None
    arguments: Arguments


class Integrity(TypedDict):
    prev_hash: str
    record_hash: str


class AuditRecord(RecordContent):
    """A record as written to the log, chained to the one before it."""

    integrity: Integrity


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _actor(claims: Claims | None) -> Actor:
    """The acting agent (``azp``/``appid``) and the human it acted for (``oid``, username, ``sub``);
    either may be ``None``, and an app-only token (``idtyp: app``) has no human."""
    if not claims:
        return {"agent": None, "on_behalf_of": None}

    app_id = claims.get("azp") or claims.get("appid")
    agent: Agent | None = None
    if app_id:
        agent = {"app_id": app_id, "name": claims.get("app_displayname")}

    # An app-only token authenticates no user. Entra marks these idtyp=app; as a
    # fallback, an app-only token carries no oid/upn distinct from the app.
    idtyp = claims.get("idtyp")
    has_user = bool(claims.get("oid") or claims.get("preferred_username") or claims.get("upn"))
    on_behalf_of: OnBehalfOf | None = None
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
    claims: Claims | None = None
    reason: str | None = None
    upstream: str | None = None
    structure: dict[str, Any] | None = None
    manifest: ManifestStamp | None = None
    conformance: dict[str, Any] | None = None
    channel: Channel | None = None


def build_record(event: AuditEvent) -> RecordContent:
    """Build the audit record **content** (everything except the integrity
    chain, which :meth:`AuditLog.write` adds). Argument *values* are intentionally absent —
    only ``structure`` and ``conformance`` (both value-free) are carried."""
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": _now_iso(),
        "correlation_id": event.correlation_id,
        "tenant_id": event.claims.get("tid") if event.claims else None,
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


def compute_hash(content: Mapping[str, object], prev_hash: str | None) -> str:
    """Deterministic SHA-256 over the record content + the previous hash.

    ``content`` is the record **without** its ``integrity`` block. Canonical
    JSON (sorted keys) makes the hash reproducible for verification."""
    payload = {"prev_hash": prev_hash or GENESIS, "record": content}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
            record_hash = json.loads(line)["integrity"]["record_hash"]
        except (ValueError, KeyError, TypeError):
            return None  # corrupt tail — start a fresh link rather than crash
        return record_hash if isinstance(record_hash, str) else None
    return None


class AuditLog:
    """The hash-chained log at ``path``, one per gateway process.

    The chain head is read from the log's last record on the first write, so a
    restart continues the chain rather than forking it. Two at once on one path
    would each chain from their own head, and fork it.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._last_hash: str | None = None
        self._seeded = False

    def _next(self, content: RecordContent) -> AuditRecord:
        """Attach the integrity block, advancing the chain."""
        if not self._seeded:
            self._last_hash = _seed_last_hash(self.path)
            self._seeded = True
        prev = self._last_hash
        record_hash = compute_hash(content, prev)
        self._last_hash = record_hash
        return {**content, "integrity": {"prev_hash": prev or GENESIS, "record_hash": record_hash}}

    def write(self, content: RecordContent) -> AuditRecord:
        """Chain ``content``, emit it as one JSON line to stdout and the log file,
        and return the chained record (with its integrity block)."""
        chained = self._next(content)
        line = json.dumps(chained, separators=(",", ":"), ensure_ascii=False)
        print(line, file=sys.stdout, flush=True)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:  # never let an audit-sink failure drop the request
            logger.error("audit log write failed: %s (%s)", self.path, exc)
        return chained

    def record(self, event: AuditEvent) -> AuditRecord:
        """Build and write in one call; returns the chained record."""
        return self.write(build_record(event))
