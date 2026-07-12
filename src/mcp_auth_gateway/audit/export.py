"""Export the audit log to SIEM-friendly shapes.

The on-disk record is nested (``actor.agent``, ``arguments.structure``,
``integrity``) for human/analytic use. Two export shapes are offered:

- **sentinel** (default) — flat PascalCase columns matching Microsoft Sentinel
  custom-table / DCR conventions. These column names are part of the locked
  schema contract (see ``docs/architecture/audit-schema.md``) — renaming them
  breaks downstream KQL.
- **ocsf** — OCSF *API Activity* (class_uid 6003) events for OCSF-native
  pipelines (Amazon Security Lake, Splunk/Elastic OCSF ingestion). Gateway
  evidence with no OCSF attribute (manifest hashes, conformance verdicts,
  structural metadata, the integrity chain) rides in ``unmapped``, per OCSF
  convention — nothing is dropped.

CLI (installed as ``mcp-auth-gateway-export-audit``)::

    mcp-auth-gateway-export-audit [in_path] [out_path] [--format sentinel|ocsf]
    # in_path defaults to AUDIT_LOG_PATH; out_path defaults to stdout
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from ..config import settings


def _join(values: object) -> str | None:
    """Join a list of identifiers into a comma-separated string (Sentinel columns
    are scalar-friendly); pass through None."""
    if isinstance(values, list):
        return ",".join(str(v) for v in values)
    return None


def flatten_record(rec: dict) -> dict:
    """Map a nested v1.0 audit record to a flat SIEM row. Missing nested pieces
    become nulls, never errors — an old/partial record still exports."""
    actor = rec.get("actor") or {}
    agent = actor.get("agent") or {}
    human = actor.get("on_behalf_of") or {}
    arguments = rec.get("arguments") or {}
    structure = arguments.get("structure") or {}
    conformance = arguments.get("conformance") or {}
    manifest = rec.get("manifest") or {}
    channel = rec.get("channel") or {}
    integrity = rec.get("integrity") or {}

    return {
        "TimeGenerated": rec.get("ts"),
        "SchemaVersion": rec.get("schema_version"),
        "CorrelationId": rec.get("correlation_id"),
        "TenantId": rec.get("tenant_id"),
        # Attribution — the whole point: agent vs. the human it acted for.
        "AgentAppId": agent.get("app_id"),
        "AgentName": agent.get("name"),
        "OnBehalfOfOid": human.get("oid"),
        "OnBehalfOfUsername": human.get("username"),
        "OnBehalfOfSub": human.get("sub"),
        # Action.
        "Tool": rec.get("tool"),
        "Upstream": rec.get("upstream"),
        "Outcome": rec.get("outcome"),
        "Reason": rec.get("reason"),
        # Value-free argument structure.
        "ArgKind": structure.get("kind"),
        "StatementTypes": _join(structure.get("statement_types")),
        "ArgTables": _join(structure.get("tables")),
        "ArgColumns": _join(structure.get("columns")),
        "ArgPiiColumns": _join(structure.get("pii_columns")),
        "TouchesPii": structure.get("touches_pii"),
        "ArgKeys": _join(structure.get("arg_keys")),
        "ArgsRedacted": arguments.get("redacted", True),
        # Manifest pinning (schema 1.1): the tool-definition hash the agent saw;
        # PreviousSha256 is set only on manifest_drift records.
        "ManifestSha256": manifest.get("sha256"),
        "ManifestPreviousSha256": manifest.get("previous_sha256"),
        # Transport channel identity (schema 1.2): edge mTLS cert + DPoP key.
        "EdgeClientCertSerial": channel.get("edge_client_cert_serial"),
        "EdgeClientCertDn": channel.get("edge_client_cert_dn"),
        "DpopJkt": channel.get("dpop_jkt"),
        # inputSchema conformance telemetry (schema 1.1). Null when untracked.
        "SchemaConformant": conformance.get("schema_conformant"),
        "SchemaViolationKeywords": _join(
            [v.get("keyword") for v in conformance.get("violations") or [] if isinstance(v, dict)]
        )
        or None,
        # Tamper-evidence.
        "RecordHash": integrity.get("record_hash"),
        "PrevHash": integrity.get("prev_hash"),
    }


# --- OCSF (API Activity, class_uid 6003) -------------------------------------

# Audit outcome → OCSF status_id/status. Failure here means "the API activity
# did not proceed" (denied/challenged/degraded), not a gateway error.
_OCSF_STATUS = {
    "allowed": (1, "Success"),
    "denied": (2, "Failure"),
    "step_up_required": (2, "Failure"),
    "degraded": (2, "Failure"),
    "manifest_drift": (99, "Other"),  # an observation, not a request outcome
}


def _epoch_ms(ts: object) -> int | None:
    if not isinstance(ts, str):
        return None
    try:
        return int(datetime.fromisoformat(ts).timestamp() * 1000)
    except ValueError:
        return None


def flatten_record_ocsf(rec: dict) -> dict:
    """Map a nested audit record to an OCSF *API Activity* event.

    An MCP ``tools/call`` has no CRUD semantics OCSF can name, so
    ``activity_id`` is Other(99) with the tool in ``api.operation``. The
    attribution split maps cleanly: the agent is the OCSF ``actor`` app, the
    human is ``actor.user``. Everything OCSF has no attribute for is carried
    verbatim under ``unmapped`` — the evidence survives the format.
    """
    actor = rec.get("actor") or {}
    agent = actor.get("agent") or {}
    human = actor.get("on_behalf_of") or {}
    arguments = rec.get("arguments") or {}
    status_id, status = _OCSF_STATUS.get(rec.get("outcome"), (0, "Unknown"))

    return {
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 99,
        "activity_name": "Other",
        "type_uid": 600399,
        "time": _epoch_ms(rec.get("ts")),
        "severity_id": 1,
        "severity": "Informational",
        "status_id": status_id,
        "status": status,
        "status_detail": rec.get("reason"),
        "actor": {
            "app_name": agent.get("name") or agent.get("app_id"),
            "app_uid": agent.get("app_id"),
            "user": {"uid": human.get("oid"), "name": human.get("username")},
        },
        "api": {
            "operation": rec.get("tool"),
            "service": {"name": rec.get("upstream")},
        },
        "metadata": {
            "version": "1.1.0",  # OCSF schema version targeted
            "correlation_uid": rec.get("correlation_id"),
            "product": {"name": "mcp-auth-gateway", "vendor_name": "AIIG"},
        },
        "unmapped": {
            "schema_version": rec.get("schema_version"),
            "tenant_id": rec.get("tenant_id"),
            "outcome": rec.get("outcome"),
            "manifest": rec.get("manifest"),
            "channel": rec.get("channel"),
            "arguments_redacted": arguments.get("redacted", True),
            "arguments_structure": arguments.get("structure"),
            "arguments_conformance": arguments.get("conformance"),
            "integrity": rec.get("integrity"),
        },
    }


_FORMATS = {"sentinel": flatten_record, "ocsf": flatten_record_ocsf}


def export_lines(in_path: str | Path, fmt: str = "sentinel"):
    """Yield flattened JSON-Line strings for each record in the log."""
    mapper = _FORMATS[fmt]
    p = Path(in_path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue  # skip a corrupt line rather than abort the export
        yield json.dumps(mapper(rec), separators=(",", ":"), ensure_ascii=False)


def main() -> None:
    """Console entry point."""
    ap = argparse.ArgumentParser(description="Export the audit log to a SIEM shape")
    ap.add_argument("in_path", nargs="?", default=settings.audit_log_path)
    ap.add_argument("out_path", nargs="?", default=None)
    ap.add_argument("--format", choices=sorted(_FORMATS), default="sentinel")
    args = ap.parse_args()

    lines = export_lines(args.in_path, args.format)
    if args.out_path:
        with Path(args.out_path).open("w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        print(f"exported {args.format} audit rows → {args.out_path}")
    else:
        for line in lines:
            print(line)


if __name__ == "__main__":
    main()
