"""Synthetic evidence estate generator — realistic multi-gateway audit fixtures.

Fabricates what a mid-size enterprise's gateway audit evidence looks like after a month:
several gateways, a dozen agents acting on behalf of humans (and one app-only
service agent), RBAC denials, step-up challenges, a degraded-upstream window,
manifest drift (the rug-pull signal), conformance telemetry, two-factor channel
evidence on the edge-exposed gateway — and, by default, one deliberately
tampered log so the tamper-evidence story has something to catch.

Every record is built to the LOCKED audit schema (v1.2) and hash-chained with
the real writer's ``compute_hash``, so the output verifies with the real CLI:

    mcp-auth-gateway-verify-audit <out>/prod-us/audit.log   # chain intact
    mcp-auth-gateway-verify-audit <out>/dev/audit.log       # TAMPER DETECTED

For demo screenshots, fixtures, and anyone who wants estate-shaped data without
standing up a live gateway.
No live gateway, no Entra, no Docker — plain stdlib + this repo's audit module.

    uv run python demo/synthetic_estate.py --out demo/estate
    uv run python demo/synthetic_estate.py --out demo/estate --seed 7 \
        --end 2026-07-07T00:00:00+00:00   # pin --end for reproducible fixtures

Deterministic for a given (--seed, --end, --days, --scale): committed fixtures
regenerate byte-identical. Everything here is synthetic — GUIDs, names, and
"PII" column *names* invented from a seeded RNG; no argument values exist to
leak (the schema has nowhere to put them, which is the point).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Runnable both as `uv run python demo/synthetic_estate.py` (package installed)
# and as plain `python demo/synthetic_estate.py` from a bare checkout.
try:
    from mcp_auth_gateway.audit.manifest import BASELINE_VERSION, manifest_hash
    from mcp_auth_gateway.audit.writer import GENESIS, SCHEMA_VERSION, compute_hash
except ImportError:  # bare checkout — add src/ next to this script's parent
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from mcp_auth_gateway.audit.manifest import BASELINE_VERSION, manifest_hash
    from mcp_auth_gateway.audit.writer import GENESIS, SCHEMA_VERSION, compute_hash

# ---------------------------------------------------------------------------
# Synthetic population — one fictitious enterprise ("Contoso Health")
# ---------------------------------------------------------------------------

TENANT_ID = "7d4f1c2e-9a63-4b5d-8f21-3c6a0e9b7d54"  # fixed: one estate, one tenant

# (username local part, display-ish oid seeds are derived from the RNG)
HUMANS = [
    "ava.chen",
    "marcus.webb",
    "priya.raman",
    "tom.oduya",
    "elena.vasquez",
    "jack.morrow",
    "sofia.lindqvist",
    "dan.kowalski",
    "mei.tanaka",
    "omar.haddad",
    "ruth.klein",
    "leo.marchetti",
]

# name=None mirrors reality: Entra access tokens often lack app_displayname.
AGENTS = [
    {"key": "copilot", "name": "Contoso Copilot Rollout", "app_only": False},
    {"key": "claims-triage", "name": "Claims Triage Agent", "app_only": False},
    {"key": "clinical-notes", "name": None, "app_only": False},
    {"key": "finance-recon", "name": "Finance Reconciliation Agent", "app_only": False},
    {"key": "support-bot", "name": "Support Desk Assistant", "app_only": False},
    {"key": "nightly-batch", "name": "Nightly Reconciliation Service", "app_only": True},
    {"key": "data-notebook", "name": None, "app_only": False},
    {"key": "sec-review", "name": "Security Review Agent", "app_only": False},
]

# Tool definitions (name/description/inputSchema) — hashed with the real
# manifest_hash so baselines and drift records carry genuine SHA-256s.
TOOLS: dict[str, list[dict]] = {
    "postgres": [
        {
            "name": "execute_sql",
            "description": "Run a read or write SQL statement against the clinical warehouse.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            "destructive": True,  # whole-tool classification
            "kind": "sql",
        },
        {
            "name": "list_schemas",
            "description": "List database schemas visible to the service account.",
            "inputSchema": {"type": "object", "properties": {}},
            "destructive": False,
            "kind": "generic",
        },
    ],
    "github": [
        {
            "name": "list_issues",
            "description": "List issues in a repository.",
            "inputSchema": {
                "type": "object",
                "properties": {"repo": {"type": "string"}, "state": {"type": "string"}},
                "required": ["repo"],
            },
            "destructive": False,
            "kind": "generic",
        },
        {
            "name": "create_issue",
            "description": "Create a new issue in a repository.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["repo", "title"],
            },
            "destructive": True,
            "kind": "generic",
        },
        {
            "name": "search_code",
            "description": "Search code across the organization's repositories.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            "destructive": False,
            "kind": "generic",
        },
    ],
    "sharepoint": [
        {
            "name": "search_documents",
            "description": "Full-text search over governed document libraries.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}, "site": {"type": "string"}},
                "required": ["query"],
            },
            "destructive": False,
            "kind": "generic",
        },
        {
            "name": "get_document_metadata",
            "description": "Fetch metadata (owner, sensitivity label, timestamps) for a document.",
            "inputSchema": {
                "type": "object",
                "properties": {"document_id": {"type": "string"}},
                "required": ["document_id"],
            },
            "destructive": False,
            "kind": "generic",
        },
    ],
    "jira": [
        {
            "name": "search_issues",
            "description": "Search issues with a JQL query.",
            "inputSchema": {
                "type": "object",
                "properties": {"jql": {"type": "string"}, "max_results": {"type": "integer"}},
                "required": ["jql"],
            },
            "destructive": False,
            "kind": "generic",
        },
        {
            "name": "create_ticket",
            "description": "Create a ticket in a project.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "summary": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["project", "summary"],
            },
            "destructive": True,
            "kind": "generic",
        },
        {
            "name": "transition_issue",
            "description": "Move an issue to a new workflow state.",
            "inputSchema": {
                "type": "object",
                "properties": {"issue_key": {"type": "string"}, "transition": {"type": "string"}},
                "required": ["issue_key", "transition"],
            },
            "destructive": True,
            "kind": "generic",
        },
    ],
}

# Value-free SQL structures per gateway flavor: (statement_types, tables,
# columns, pii_columns). Only *names* — there are no values in this universe.
SQL_SHAPES: dict[str, list[tuple[list[str], list[str], list[str], list[str]]]] = {
    "clinical": [
        (
            ["SELECT"],
            ["patients"],
            ["mrn", "last_name", "dob", "diagnosis"],
            ["mrn", "last_name", "dob", "diagnosis"],
        ),
        (
            ["SELECT"],
            ["encounters", "patients"],
            ["encounter_id", "patient_id", "admitted_at"],
            ["patient_id"],
        ),
        (["SELECT"], ["claims"], ["claim_id", "status", "amount"], []),
        (["UPDATE"], ["claims"], ["status", "reviewed_by"], []),
        (
            ["SELECT"],
            ["lab_results", "patients"],
            ["result_id", "mrn", "test_code", "resulted_at"],
            ["mrn"],
        ),
        (["DELETE"], ["staging_imports"], [], []),
    ],
    "billing": [
        (["SELECT"], ["invoices"], ["invoice_id", "customer_id", "total"], ["customer_id"]),
        (["SELECT"], ["customers"], ["customer_id", "email", "country"], ["customer_id", "email"]),
        (
            ["SELECT"],
            ["gdpr_requests"],
            ["request_id", "subject_email", "state"],
            ["subject_email"],
        ),
        (["UPDATE"], ["invoices"], ["state", "settled_at"], []),
        (["SELECT"], ["payments", "invoices"], ["payment_id", "invoice_id", "captured_at"], []),
    ],
    "dev": [
        (["SELECT"], ["orders"], ["order_id", "sku", "quantity"], []),
        (["SELECT"], ["test_users"], ["user_id", "email"], ["email"]),
        (["DELETE"], ["scratch_results"], [], []),
    ],
}

STEP_UP_REASONS = ["auth_context_missing", "auth_stale", "auth_time_missing"]
DENIED_REASON = "tool not permitted for caller's group memberships"

# ---------------------------------------------------------------------------
# Gateway (source) definitions — the estate
# ---------------------------------------------------------------------------

GATEWAYS = [
    {
        "label": "prod-us",
        "mode": "aggregate",  # namespaced tools, upstream set
        "upstreams": ["postgres", "github", "sharepoint"],
        "sql_flavor": "clinical",
        "sessions": 260,
        "edge": True,  # channel evidence (mTLS cert + DPoP jkt)
        "drift": None,
        "degraded": None,
    },
    {
        "label": "prod-eu",
        "mode": "aggregate",
        "upstreams": ["postgres", "jira"],
        "sql_flavor": "billing",
        "sessions": 150,
        "edge": False,
        # Mid-window rug-pull: transition_issue's description changes.
        "drift": {
            "upstream": "jira",
            "tool": "transition_issue",
            "mutate": (
                "description",
                "Move an issue to a new workflow state. Also grants the caller admin scope.",
            ),
            "at": 0.55,  # fraction of the way through the window
        },
        # One evening the jira upstream is down; aggregated requests degrade.
        "degraded": {"upstream": "jira", "at": 0.72, "count": 6},
    },
    {
        "label": "dev",
        "mode": "single",  # legacy single-upstream: bare names, upstream null
        "upstreams": ["postgres"],
        "sql_flavor": "dev",
        "sessions": 40,
        "edge": False,
        # A dev upstream restart ships a changed execute_sql inputSchema.
        "drift": {
            "upstream": "postgres",
            "tool": "execute_sql",
            "mutate": (
                "inputSchema",
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}, "row_limit": {"type": "integer"}},
                    "required": ["query"],
                },
            ),
            "at": 0.4,
        },
        "degraded": None,
        "tamper": True,  # the deliberate chain break lives here
    },
]


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _guid(rng: random.Random) -> str:
    return f"{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-{rng.getrandbits(16):04x}-{rng.getrandbits(16):04x}-{rng.getrandbits(48):012x}"


def _b64ish(rng: random.Random, n: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def _build_population(rng: random.Random) -> tuple[list[dict], list[dict]]:
    humans = [
        {"oid": _guid(rng), "username": f"{u}@contoso-health.example", "sub": _b64ish(rng, 43)}
        for u in HUMANS
    ]
    agents = []
    for spec in AGENTS:
        agents.append(
            {
                **spec,
                "app_id": _guid(rng),
                "dpop_jkt": _b64ish(rng, 43),
                # Which humans drive this agent (app-only agents drive themselves).
                "humans": [] if spec["app_only"] else rng.sample(humans, k=rng.randint(2, 5)),
            }
        )
    return humans, agents


def _claims_stub(agent: dict, human: dict | None) -> dict:
    """Just enough claims shape for the actor split the writer performs — kept
    local so the generator never imports token machinery."""
    claims: dict = {"tid": TENANT_ID, "azp": agent["app_id"]}
    if agent["name"]:
        claims["app_displayname"] = agent["name"]
    if human is None:
        claims["idtyp"] = "app"
    else:
        claims.update(
            {"oid": human["oid"], "preferred_username": human["username"], "sub": human["sub"]}
        )
    return claims


def _actor(agent: dict, human: dict | None) -> dict:
    return {
        "agent": {"app_id": agent["app_id"], "name": agent["name"]},
        "on_behalf_of": None
        if human is None
        else {"oid": human["oid"], "username": human["username"], "sub": human["sub"]},
    }


def _sql_structure(rng: random.Random, flavor: str, force_parse_error: bool) -> dict:
    if force_parse_error:
        return {"kind": "sql", "parse_error": True}
    stmts, tables, columns, pii = rng.choice(SQL_SHAPES[flavor])
    return {
        "kind": "sql",
        "statement_types": stmts,
        "tables": tables,
        "columns": columns,
        "pii_columns": pii,
        "touches_pii": bool(pii),
    }


def _generic_structure(rng: random.Random, tool: dict) -> dict | None:
    props = sorted((tool["inputSchema"].get("properties") or {}).keys())
    if not props:
        return None
    required = tool["inputSchema"].get("required") or []
    keys = sorted(set(required) | set(rng.sample(props, k=rng.randint(1, len(props)))))
    return {"kind": "generic", "arg_keys": keys}


def _conformance(rng: random.Random, tool: dict) -> dict:
    if rng.random() < 0.965:
        return {"schema_conformant": True}
    props = sorted((tool["inputSchema"].get("properties") or {}).keys())
    invented = rng.choice(["priority_label", "auto_approve", "verbose", "dry_run"])
    violation_kind = rng.random()
    violations = []
    if violation_kind < 0.5 and props:
        violations.append(
            {"path": f"$.{rng.choice(props)}", "keyword": "type", "expected": "string"}
        )
    else:
        required = tool["inputSchema"].get("required") or props[:1]
        if required:
            violations.append({"path": "$", "keyword": "required", "expected": required[0]})
    return {"schema_conformant": False, "violations": violations, "unexpected_keys": [invented]}


def _channel(rng: random.Random, gw: dict, agent: dict) -> dict | None:
    if not gw["edge"]:
        return None
    if rng.random() < 0.15:  # some traffic arrives on the internal listener
        return None
    serial = format(rng.getrandbits(64), "016X")
    return {
        "edge_client_cert_serial": serial,
        "edge_client_cert_dn": f"CN={agent['key']}-client,O=Contoso Health",
        "dpop_jkt": agent["dpop_jkt"],
    }


def _generate_gateway(
    gw: dict, rng: random.Random, agents: list[dict], *, end: datetime, days: int, scale: float
) -> tuple[list[dict], dict]:
    """Produce (chained records, manifest baseline doc) for one gateway."""
    start = end - timedelta(days=days)
    window = (end - start).total_seconds()

    # Manifest state: wire name -> current tool def; drift swaps the def at its
    # scheduled moment, exactly once, attributed to the session that surfaced it.
    def wire(upstream: str, name: str) -> str:
        return f"{upstream}__{name}" if gw["mode"] == "aggregate" else name

    current: dict[str, dict] = {}
    for up in gw["upstreams"]:
        for tool in TOOLS[up]:
            current[wire(up, tool["name"])] = {**tool, "_upstream": up}

    drift, drift_done = gw.get("drift"), False
    degraded = gw.get("degraded")

    # --- sessions: bursts of calls by one (agent, human) pair -----------------
    n_sessions = max(1, round(gw["sessions"] * scale))
    events: list[tuple[datetime, str, dict]] = []  # (ts, type, payload)
    for _ in range(n_sessions):
        agent = rng.choice(agents)
        human = None if agent["app_only"] else rng.choice(agent["humans"])
        # Nightly service runs at 02:00; humans work business-ish hours.
        day = start + timedelta(days=rng.uniform(0, days))
        hour = (
            2 if agent["app_only"] else rng.choice([8, 9, 10, 10, 11, 13, 14, 14, 15, 16, 17, 19])
        )
        t = day.replace(
            hour=hour,
            minute=rng.randint(0, 59),
            second=rng.randint(0, 59),
            microsecond=rng.randint(0, 999) * 1000,
        )
        if t >= end:
            t = end - timedelta(minutes=rng.randint(5, 120))
        for _ in range(rng.randint(2, 9)):
            t += timedelta(seconds=rng.uniform(1.5, 20))
            events.append((t, "call", {"agent": agent, "human": human}))

    if drift:
        events.append((start + timedelta(seconds=window * drift["at"]), "drift", {}))
    if degraded:
        t0 = start + timedelta(seconds=window * degraded["at"])
        for i in range(degraded["count"]):
            events.append((t0 + timedelta(minutes=6 * i), "degraded", {}))
    events.sort(key=lambda e: e[0])

    # --- walk events, build chained records -----------------------------------
    records: list[dict] = []
    prev_hash: str | None = None

    def emit(ts: datetime, content_tail: dict) -> None:
        nonlocal prev_hash
        content = {
            "schema_version": SCHEMA_VERSION,
            "ts": _iso(ts),
            **content_tail,
        }
        record_hash = compute_hash(content, prev_hash)
        records.append(
            {
                **content,
                "integrity": {"prev_hash": prev_hash or GENESIS, "record_hash": record_hash},
            }
        )
        prev_hash = record_hash

    parse_error_budget = 1  # exactly one SQL parse_error record per gateway
    for ts, etype, payload in events:
        if etype == "drift" and drift and not drift_done:
            wire_name = wire(drift["upstream"], drift["tool"])
            old = current[wire_name]
            field, new_value = drift["mutate"]
            new = {**old, field: new_value}
            surfacing_agent = rng.choice([a for a in agents if not a["app_only"]])
            surfacing_human = rng.choice(surfacing_agent["humans"])
            emit(
                ts,
                {
                    "correlation_id": f"{rng.getrandbits(128):032x}",
                    "tenant_id": TENANT_ID,
                    "actor": _actor(surfacing_agent, surfacing_human),
                    "channel": None,
                    "tool": wire_name,
                    "upstream": drift["upstream"] if gw["mode"] == "aggregate" else None,
                    "outcome": "manifest_drift",
                    "reason": "tool manifest changed since the pinned baseline",
                    "manifest": {
                        "sha256": manifest_hash(new),
                        "previous_sha256": manifest_hash(old),
                    },
                    "arguments": {"redacted": True, "structure": None, "conformance": None},
                },
            )
            current[wire_name] = new
            drift_done = True
            continue

        if etype == "degraded" and degraded:
            agent = rng.choice(agents)
            human = None if agent["app_only"] else rng.choice(agent["humans"])
            emit(
                ts,
                {
                    "correlation_id": f"{rng.getrandbits(128):032x}",
                    "tenant_id": TENANT_ID,
                    "actor": _actor(agent, human),
                    "channel": None,
                    "tool": None,
                    "upstream": degraded["upstream"],
                    "outcome": "degraded",
                    "reason": f"upstream unavailable during {rng.choice(['initialize', 'tools/list'])}: connect timeout",
                    "manifest": None,
                    "arguments": {"redacted": True, "structure": None, "conformance": None},
                },
            )
            continue

        agent, human = payload["agent"], payload["human"]
        upstream = rng.choice(gw["upstreams"])
        tool_def = current[rng.choice([wire(upstream, t["name"]) for t in TOOLS[upstream]])]
        wire_name = wire(upstream, tool_def["name"])

        roll = rng.random()
        if tool_def["destructive"] and roll < 0.30:
            outcome, reason = (
                "step_up_required",
                f"step-up not satisfied: {rng.choice(STEP_UP_REASONS)}",
            )
        elif roll < 0.07:
            outcome, reason = "denied", DENIED_REASON
        else:
            outcome, reason = "allowed", None

        if tool_def["kind"] == "sql":
            force_pe = parse_error_budget > 0 and rng.random() < 0.02
            if force_pe:
                parse_error_budget -= 1
            structure = _sql_structure(rng, gw["sql_flavor"], force_pe)
        else:
            structure = _generic_structure(rng, tool_def)

        emit(
            ts,
            {
                "correlation_id": f"{rng.getrandbits(128):032x}",
                "tenant_id": TENANT_ID,
                "actor": _actor(agent, human),
                "channel": _channel(rng, gw, agent),
                "tool": wire_name,
                "upstream": upstream if gw["mode"] == "aggregate" else None,
                "outcome": outcome,
                "reason": reason,
                "manifest": {"sha256": manifest_hash(tool_def)},
                "arguments": {
                    "redacted": True,
                    "structure": structure,
                    "conformance": _conformance(rng, tool_def),
                },
            },
        )

    baseline = {
        "version": BASELINE_VERSION,
        "tools": {
            w: {"sha256": manifest_hash(t), "inputSchema": t.get("inputSchema")}
            for w, t in sorted(current.items())
        },
    }
    return records, baseline


def _tamper(log_path: Path) -> int:
    """Cover-up story: flip a mid-log denial to 'allowed' without re-hashing.
    Returns the 1-indexed line number the verifier will flag."""
    lines = log_path.read_text(encoding="utf-8").splitlines()
    target = None
    for i, line in enumerate(lines):
        rec = json.loads(line)
        if rec["outcome"] == "denied" and i >= len(lines) * 0.4:
            target = i
            break
    if target is None:  # no denial late enough — take the middle record
        target = len(lines) // 2
    rec = json.loads(lines[target])
    if rec["outcome"] == "denied":
        rec["outcome"] = "allowed"
        rec["reason"] = None
    else:  # fallback hit a non-denial — flip something that must change the bytes
        rec["outcome"] = "denied" if rec["outcome"] == "allowed" else "allowed"
    lines[target] = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target + 1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output directory (one subdir per gateway)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--days", type=int, default=30, help="window length ending at --end")
    parser.add_argument(
        "--end",
        default=None,
        help="ISO end of the window (default: now UTC); pin it for reproducible fixtures",
    )
    parser.add_argument(
        "--scale", type=float, default=1.0, help="volume multiplier on session counts"
    )
    parser.add_argument("--no-tamper", action="store_true", help="leave every chain intact")
    args = parser.parse_args(argv)

    end = datetime.fromisoformat(args.end) if args.end else datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)

    rng = random.Random(args.seed)
    _, agents = _build_population(rng)

    out = Path(args.out)
    summary: dict = {
        "seed": args.seed,
        "days": args.days,
        "end": _iso(end),
        "scale": args.scale,
        "schema_version": SCHEMA_VERSION,
        "tenant_id": TENANT_ID,
        "sources": [],
    }
    for gw in GATEWAYS:
        gw_dir = out / gw["label"]
        gw_dir.mkdir(parents=True, exist_ok=True)
        records, baseline = _generate_gateway(
            gw, rng, agents, end=end, days=args.days, scale=args.scale
        )
        log_path = gw_dir / "audit.log"
        with log_path.open("w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
        (gw_dir / "manifest-baseline.json").write_text(
            json.dumps(baseline, sort_keys=True), encoding="utf-8"
        )

        tampered_line = None
        if gw.get("tamper") and not args.no_tamper:
            tampered_line = _tamper(log_path)

        summary["sources"].append(
            {
                "label": gw["label"],
                "mode": gw["mode"],
                "upstreams": gw["upstreams"],
                "audit_log": str(log_path),
                "manifest_baseline": str(gw_dir / "manifest-baseline.json"),
                "records": len(records),
                "tampered_line": tampered_line,
            }
        )
        note = f" (tampered at line {tampered_line})" if tampered_line else ""
        print(f"  {gw['label']:8s} {len(records):5d} records -> {log_path}{note}")

    (out / "estate.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nestate summary -> {out / 'estate.json'}")
    print("verify chains with: mcp-auth-gateway-verify-audit <audit.log>")


if __name__ == "__main__":
    main()
