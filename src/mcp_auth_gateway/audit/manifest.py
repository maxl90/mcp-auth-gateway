"""Tool-manifest hash pinning + drift evidence (backlog item 10).

A poisoned tool description or a rug-pull (an upstream silently changing what a
tool claims to do) is a *forensics* problem: "what did the tool definition say
at the moment the agent acted?" To answer it, the gateway pins a SHA-256 of
each tool's trust-relevant manifest fields (``name`` + ``description`` +
``inputSchema``) the first time it observes the tool, persists the baseline to
a file (ADR 004: state in files, never a database), and on every later
observation:

- **unchanged** → nothing;
- **changed** → a first-class ``manifest_drift`` audit record carrying the old
  and new hashes, and the baseline advances to the new manifest.

Every ``tools/call`` audit record is stamped with the pinned manifest hash
(``manifest.sha256``) so the log attests which tool definition was current when
the call transited. **Detection and attestation only — there is deliberately no
blocking path** (ADR 007: enforcement is platform territory; a drift event is
evidence, not a gate).

The baseline file stores tool *metadata* only (names, descriptions, schemas) —
never tokens, arguments, or customer data — so it sits inside the trust
boundary trivially. First observation of a tool adopts it silently as baseline:
the gateway cannot attest to what an upstream served before the gateway existed.

When signed tool manifests land in the MCP spec (extension #2913), signature
verification results become one more field on this same record shape.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from ..config import settings
from ..upstreams import namespace_tool
from . import writer as audit

# Baseline file format version — the file is a cache/pin store, not the locked
# audit schema; bump freely if the shape must change (old files just re-pin).
BASELINE_VERSION = "1"
_BASELINE_VERSION = BASELINE_VERSION  # deprecated alias, kept for back-compat


def manifest_hash(tool: dict) -> str:
    """Deterministic SHA-256 over the trust-relevant manifest fields.

    Only ``name``/``description``/``inputSchema`` participate: they are what an
    agent reasons over. Cosmetic catalog fields (``title``, annotations) can
    churn without a drift event. Canonical JSON (sorted keys) makes the hash
    reproducible across processes and restarts.
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
    """Read the baseline file; any problem yields an empty baseline (tools
    re-pin on next observation) rather than a crash."""
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    tools = doc.get("tools") if isinstance(doc, dict) else None
    return tools if isinstance(tools, dict) else {}


def _save(path: Path, tools: dict[str, dict]) -> None:
    """Persist the baseline. A sink failure must never drop the request —
    log to stderr and carry on with the in-memory baseline (same posture as
    the audit writer's file sink)."""
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
    """Pin/compare every tool in an observed ``tools/list`` catalog.

    ``upstream`` namespaces the pin keys (aggregation/path-routed modes) so the
    keys match the wire/policy names the audit records use; ``None`` keys by the
    bare tool name (legacy single-upstream mode). A changed manifest emits a
    ``manifest_drift`` audit record attributed to the caller whose request
    surfaced the change.
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
                outcome="manifest_drift",
                tool=wire,
                correlation_id=correlation_id,
                claims=claims,
                reason="tool manifest changed since the pinned baseline",
                upstream=upstream,
                manifest={"sha256": digest, "previous_sha256": entry.get("sha256")},
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
