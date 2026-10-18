"""Tool-manifest pinning and drift evidence.

A poisoned tool description, or an upstream quietly changing what a tool claims
to do, is a forensics question: what did the definition say when the agent acted?
The gateway pins a SHA-256 of each tool's ``name`` + ``description`` +
``inputSchema`` the first time it sees the tool (it cannot attest to anything
earlier), persists the baseline to a file of tool metadata only, and on a later
change writes a ``manifest_drift`` record with both hashes. Evidence, never a gate.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from ..config import settings
from ..naming import namespace_tool
from . import writer as audit

# Baseline file format version — the file is a cache/pin store, not the locked
# audit schema; bump freely if the shape must change (old files just re-pin).
BASELINE_VERSION = "1"


def manifest_hash(tool: dict) -> str:
    """SHA-256 over the trust-relevant fields: ``name``, ``description``, ``inputSchema``.

    Cosmetic catalog fields (``title``, annotations) can change without a drift
    event. Canonical JSON (sorted keys) keeps the hash stable across processes.
    """
    content = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Per-process store, keyed by baseline path so a path change (tests, config
# swap) re-seeds cleanly — same pattern as the audit writer's chain state.
_store: dict = {"path": None, "tools": {}}


def _load(path: Path) -> dict[str, dict]:
    """The baseline file's tools, or ``{}`` for a missing or unreadable file (tools re-pin)."""
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    tools = doc.get("tools") if isinstance(doc, dict) else None
    return tools if isinstance(tools, dict) else {}


def _save(path: Path, tools: dict[str, dict]) -> None:
    """Persist the baseline; a sink failure is logged to stderr and never fails the request."""
    try:
        path.write_text(
            json.dumps({"version": BASELINE_VERSION, "tools": tools}, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        print(
            json.dumps({"manifest_baseline_error": str(exc), "path": str(path)}),
            file=sys.stderr,
            flush=True,
        )


def _tools(path: Path) -> dict[str, dict]:
    key = str(path)
    if _store["path"] != key:
        _store["path"] = key
        _store["tools"] = _load(path)
    return _store["tools"]


def observe_catalog(
    upstream: str | None,
    tools: list[dict],
    *,
    correlation_id: str,
    claims: dict | None = None,
) -> None:
    """Pin or compare every tool in an observed ``tools/list`` catalog.

    ``upstream`` namespaces the keys to match the wire and policy names; ``None``
    keys by the bare tool name. A changed manifest writes a ``manifest_drift``
    record attributed to the caller whose request surfaced it.
    """
    path = Path(settings.manifest_baseline_path)
    baseline = _tools(path)
    changed = False
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        wire = namespace_tool(upstream, tool["name"]) if upstream else tool["name"]
        digest = manifest_hash(tool)
        entry = baseline.get(wire)
        if entry is not None and entry.get("sha256") == digest:
            continue
        if entry is not None:
            audit.record(
                audit.AuditEvent(
                    outcome="manifest_drift",
                    tool=wire,
                    correlation_id=correlation_id,
                    claims=claims,
                    reason="tool manifest changed since the pinned baseline",
                    upstream=upstream,
                    manifest={"sha256": digest, "previous_sha256": entry.get("sha256")},
                )
            )
        baseline[wire] = {"sha256": digest, "inputSchema": tool.get("inputSchema")}
        changed = True
    if changed:
        _save(path, baseline)


def stamp_for(wire_tool: str) -> dict | None:
    """The ``manifest`` block for a ``tools/call`` audit record: the pinned hash
    of the definition current when the call transited. ``None`` until the tool
    has been observed in a catalog."""
    entry = _tools(Path(settings.manifest_baseline_path)).get(wire_tool)
    if not isinstance(entry, dict) or not entry.get("sha256"):
        return None
    return {"sha256": entry["sha256"]}


def input_schema_for(wire_tool: str) -> dict | None:
    """The pinned ``inputSchema`` for a tool, for conformance telemetry.
    ``None`` when the tool is unobserved or declared no (object) schema."""
    entry = _tools(Path(settings.manifest_baseline_path)).get(wire_tool)
    schema = entry.get("inputSchema") if isinstance(entry, dict) else None
    return schema if isinstance(schema, dict) else None
