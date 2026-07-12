"""Narrated end-to-end evidence demo — the pivot's story in ~90 seconds.

Drives real governed traffic through the gateway, then surfaces the **evidence**
that is the product thesis (ADR 007): every agent action attributed to an agent
acting on behalf of a human, structural (value-free) metadata of what it touched,
a tamper-evident trail, and a framework-mapped evidence report.

Beats:
  1. Sign in (Entra) and open one aggregated session over all upstreams.
  2. An allowed, non-destructive call            -> logged + attributed.
  3. A denied call (tool outside the policy)     -> blocked, logged.
  4. A destructive SQL call touching PII         -> step-up challenged (RFC 9470),
     but still logged with which PII columns it would have touched.
  5. Surface the evidence: the attributed, hash-chained audit records; verify the
     chain; generate the NIST AI RMF evidence report.

The token and the SQL values never leave the gateway — visible in the evidence,
which carries structure (tables/columns) but no values.

Requires the local stack up (docker compose ... aggregate) and, for the evidence
beat, the gateway container reachable via `docker exec`
(GATEWAY_CONTAINER, default mcp-auth-gateway-demo-gateway-1). If docker isn't
available the script prints the commands to run instead.

  uv run --extra demo python demo/evidence_demo.py
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import uuid

import client  # reuse env-loading, login, config
import httpx

for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8")

CONTAINER = os.environ.get("GATEWAY_CONTAINER", "mcp-auth-gateway-demo-gateway-1")
AUDIT_PATH = os.environ.get("GATEWAY_CONTAINER_AUDIT", "/app/audit.log")


def _beat(n: int, title: str) -> None:
    print(f"\n{'='*70}\n[{n}] {title}\n{'='*70}")


def _call(headers: dict, name: str, arguments: dict) -> httpx.Response:
    return httpx.post(
        client.GATEWAY_URL,
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


def _docker(*args: str) -> str | None:
    """Run a command in the gateway container; None if docker/exec unavailable."""
    try:
        out = subprocess.run(
            ["docker", "exec", CONTAINER, *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 and not out.stdout:
        return None
    return out.stdout


def main() -> None:
    print("\nAIIG — Agent Attribution & Audit-Evidence demo")
    token = client._login()

    _beat(1, "One aggregated session over every governed upstream")
    H = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}
    init = httpx.post(client.GATEWAY_URL, headers=H, json={
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    H["Mcp-Session-Id"] = init.headers["mcp-session-id"]
    httpx.post(client.GATEWAY_URL, headers=H,
               json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools = httpx.post(client.GATEWAY_URL, headers=H,
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
    names = [t["name"] for t in tools["result"]["tools"]]
    print(f"  merged, RBAC-filtered catalog: {len(names)} tools across upstreams")
    print("  e.g.", ", ".join(names[:4]), "...")

    _beat(2, "An allowed, non-destructive call — logged and attributed")
    r = _call(H, "postgres__list_schemas", {})
    print(f"  postgres__list_schemas -> HTTP {r.status_code} (allowed)")

    _beat(3, "A tool outside the policy — blocked, and logged")
    r = _call(H, "postgres__pg_superpower", {})
    print(f"  postgres__pg_superpower -> HTTP {r.status_code} (denied, never forwarded)")

    _beat(4, "A destructive SQL call touching PII — step-up challenged, still logged")
    r = _call(H, "postgres__execute_sql",
              {"sql": "DELETE FROM patients WHERE ssn = '123-45-6789'"})
    print(f"  postgres__execute_sql -> HTTP {r.status_code} (step-up required, RFC 9470)")
    print("  the SSN value stays at the gateway — watch it be ABSENT from the evidence below")
    httpx.request("DELETE", client.GATEWAY_URL, headers=H)

    _beat(5, "The evidence: attributed, structured, tamper-evident, framework-mapped")
    tail = _docker("sh", "-c", f"tail -n 3 {AUDIT_PATH}")
    if tail is None:
        print("  (docker exec unavailable — run these against the gateway host:)")
        print(f"    tail -n 3 {AUDIT_PATH}")
        print(f"    mcp-auth-gateway-verify-audit {AUDIT_PATH}")
        print(f"    mcp-auth-gateway-evidence-report {AUDIT_PATH} nist-ai-rmf")
        return

    for line in tail.strip().splitlines():
        rec = json.loads(line)
        actor = rec.get("actor", {})
        agent = (actor.get("agent") or {}).get("app_id")
        human = (actor.get("on_behalf_of") or {}).get("username")
        struct = (rec.get("arguments") or {}).get("structure") or {}
        print(f"\n  - {rec['tool']}  [{rec['outcome']}]")
        print(f"      agent {agent}  on behalf of  {human}")
        if struct.get("kind") == "sql":
            print(f"      touched tables={struct.get('tables')} pii_columns={struct.get('pii_columns')}")
        print(f"      hash {rec['integrity']['record_hash'][:16]}...  (chained)")

    if "123-45-6789" in tail:
        print("\n  !! SSN value leaked into the evidence — trust boundary broken")
    else:
        print("\n  ✓ the SSN value appears NOWHERE in the evidence (values never leave the gateway)")

    print("\n  Verifying the tamper-evident chain:")
    verify = _docker("mcp-auth-gateway-verify-audit", AUDIT_PATH)
    print("   ", (verify or "").strip() or "(verify unavailable)")

    print("\n  NIST AI RMF evidence report:")
    report = _docker("mcp-auth-gateway-evidence-report", AUDIT_PATH, "nist-ai-rmf")
    if report:
        # Print just the control-coverage summary lines to keep the demo tight.
        for line in report.splitlines():
            if line.startswith("| **") or "controls fully attested" in line:
                print("   ", line)


if __name__ == "__main__":
    main()
