# mcp-auth-gateway

A governed reverse proxy for MCP servers: put **enterprise identity in front of
your MCP tools**, and get **attributed, tamper-evident audit evidence** of what
your agents did — **without your data leaving the network**.

The gateway runs inside your network, in front of one or more MCP servers. It
validates every caller's OAuth 2.1 token locally, maps their identity to the
tools they may use, forwards only authorized calls, and records a structured
evidence trail of every invocation. **User tokens and raw tool-call arguments
never leave your network** — only the upstream MCP server and your own audit
sink ever see them. There is no SaaS in the request path.

---

## The trust boundary

This is the whole design. The user's `Authorization` token is validated *at the
gateway* against your IdP's JWKS endpoint and then **stripped** — it is never
forwarded upstream. Each upstream MCP server reaches its resource (a database,
GitHub, etc.) with its **own service identity**. Per-user attribution comes from
the audit log, not from a propagated credential.

The audit records carry *who / which agent / on whose behalf / what tool / what
it touched / when / outcome* — but **never the argument values**. A neutral
evidence layer is more credible precisely because it demonstrably cannot see the
underlying data, which is what lets regulated teams (FedRAMP / HIPAA / PCI) adopt
it without a procurement fight.

---

## What it does (all live)

- **Validates Entra ID OAuth 2.1 tokens** locally against the tenant JWKS
  endpoint — signature, issuer, audience, expiry (RS256/384/512 only; `none`/HMAC
  rejected). No valid token, no entry (`401`). Handles JWKS **key rotation**
  (throttled refresh-on-miss).
- **Terminates the token at the gateway** — validated, then stripped; never
  forwarded upstream.
- **Tool-level RBAC** — maps Entra group memberships to an allowed tool set via a
  human-editable `policy.yaml`. A disallowed `tools/call` is `403`, never
  forwarded.
- **`tools/list` filtering** — callers only *see* the tools they can invoke
  (content-type aware: JSON and SSE).
- **Step-up auth on destructive tools** (RFC 9470) — high-impact tools require a
  fresh, stronger authentication (an Entra authentication context in the token);
  otherwise the call is challenged on both an HTTP `WWW-Authenticate` header and a
  JSON-RPC error, and is not forwarded.
- **DPoP sender-constrained tokens** (RFC 9449) — when the authorization server
  binds a token to a client key pair (`cnf.jkt`), the gateway demands a valid
  proof-of-possession on every request, so a stolen token is useless without the
  private key. `DPOP_MODE` is `off` / `if_present` (default: enforce binding the
  moment the AS provides it) / `required`. See
  `src/mcp_auth_gateway/auth/dpop.py`.
- **On-prem mTLS internet edge** — an nginx DMZ reverse-proxy overlay
  (`docker-compose.edge.yml` + `infra/edge/`) that hard-fails mTLS at the edge
  and makes a second mTLS hop to the gateway, so only the proxy can open a
  gateway connection. Includes CRL-based client-cert revocation
  (`infra/edge/revoke-cert.sh`) and cert-expiry monitoring
  (`infra/edge/check-cert-expiry.sh`). The edge client-cert identity and DPoP
  key thumbprint land in each audit record's `channel` block.
- **Multi-upstream aggregation** — front many MCP servers as **one virtual MCP
  server**: a merged, RBAC-filtered, namespaced (`upstream__tool`) catalog, with
  each call routed to its owning upstream. Partial-failure tolerant; sessions
  reconnect transparently on upstream expiry.
- **Evidence-grade audit** — every invocation produces a structured record that:
  - **attributes** the acting **agent** (the app/agent identity) distinctly from
    the **human** it acted on behalf of (the attribution problem: agents run
    under user credentials, so naive logs blame the human);
  - carries **value-free structural metadata** — which tables/columns a SQL call
    touched and whether a PII-shaped column was involved, or the argument keys of
    any other tool — **never the values**;
  - is **hash-chained** and therefore **tamper-evident**.
- **OAuth 2.1 resource-server discovery** — Protected Resource Metadata at
  `/.well-known/oauth-protected-resource` and `resource_metadata` challenge
  pointers (RFC 8707/9207/9728).

The audit record schema is locked at v1.2 (attribution, structural arguments,
integrity chain, SIEM export columns). Changes within 1.x are strictly
additive: v1.1 added tool-manifest drift detection and inputSchema conformance
telemetry; v1.2 added the `channel` block (edge mTLS client-cert identity +
DPoP key thumbprint).

---

## Quickstart — see it run in one command (no identity provider)

Requires Docker. This brings up the gateway + a sample MCP server + a seeded
Postgres with **auth turned off**, so you can watch the proxy work with zero
setup:

```sh
docker compose -f docker-compose.quickstart.yml up --build
```

Then, in another shell, do the MCP handshake and call a tool (no token needed in
this mode):

```sh
# initialize -> you get an Mcp-Session-Id back
curl -s -i -X POST http://localhost:8080/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

> **This is the "does it run?" on-ramp, not the governed mode.**
> `AUTH_ENABLED=false` makes the gateway a plain pass-through — no identity, no
> RBAC. For the real story (identity, RBAC, evidence), use the governed demo
> below.

---

## The governed demo (Entra ID)

Requires Docker, [`uv`](https://docs.astral.sh/uv/), and a **dev** Entra tenant.

```sh
# 1. Provision a dev/personal tenant (one time): creates an app, two security
#    groups, two test users. Writes .env.generated (tenant/client/issuer/audience/
#    jwks) and policy.generated.yaml (group -> allowed tools).
pwsh infra/provision-entra.ps1

# 2. Bring up the governed stack: gateway :8080 -> mcp-upstream :9000 -> Postgres.
docker compose up -d --build

# 3. Call a tool as the *allowed* (analyst) user — device-code login, then a
#    real SELECT against PII-shaped data succeeds:
uv run --extra demo python demo/client.py

# 4. Run again as the *denied* (readonly) user — the same call is 403, and the
#    request never reaches the database:
GATEWAY_LOGIN_HINT=<readonly-upn> uv run --extra demo python demo/client.py

# 5. See the evidence — structured, attributed, redacted audit lines:
docker compose logs gateway
```

An unauthenticated request is refused before it goes anywhere, and points a cold
client at discovery:

```sh
curl -i -X POST http://localhost:8080/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_sql"}}'
# -> 401; WWW-Authenticate: Bearer realm="mcp", resource_metadata="…/.well-known/oauth-protected-resource"
```

---

## Multiple upstreams: one governed front door

The same gateway governs *any* MCP server. Point it at more than one and it
becomes a single virtual MCP server over all of them — one merged, per-user
catalog, each call routed to its owner, one identity/RBAC/audit pass.

```sh
# GitHub as a second upstream (its own service PAT stays in-network; the user
# token still terminates at the gateway):
docker compose -f docker-compose.yml -f docker-compose.github.yml up -d --build

# Both Postgres AND GitHub aggregated behind one /mcp endpoint:
docker compose -f docker-compose.yml -f docker-compose.github.yml -f docker-compose.aggregate.yml up -d --build
uv run --extra demo python demo/list_tools.py   # merged, RBAC-filtered catalog (postgres__*, github__*)
```

Tool names are namespaced `upstream__tool`, governed by one policy file. See
`upstreams.example.yaml` and `policy.aggregate.example.yaml`.

---

## The evidence

Every governed call is logged as an attributed, hash-chained record (schema
v1.2). Four CLIs turn that log into evidence:

```sh
# Verify the audit trail hasn't been tampered with (walks the hash chain):
mcp-auth-gateway-verify-audit audit.log

# Flatten the log for SIEM ingestion (Microsoft Sentinel column shape by
# default; --format ocsf emits OCSF API Activity [class 6003] events instead):
mcp-auth-gateway-export-audit audit.log > audit.siem.jsonl
mcp-auth-gateway-export-audit audit.log audit.ocsf.jsonl --format ocsf

# Generate a GRC-framework-mapped evidence report (nist-ai-rmf, eu-ai-act, soc2):
mcp-auth-gateway-evidence-report audit.log nist-ai-rmf report.md

# Build a single auditor-verifiable ZIP: the full hash-chained log, evidence
# reports for all three frameworks (time-windowable via --from/--to),
# Sentinel + OCSF exports, and a SHA-256 pack manifest (optionally
# Ed25519-signed). --verify re-checks everything and exit-codes the result.
mcp-auth-gateway-attestation-pack audit.log pack.zip
mcp-auth-gateway-attestation-pack --verify pack.zip
```

For the whole story end to end — allowed / denied / step-up traffic, then the
attribution, the tamper-evident chain, and the framework report — run the
narrated demo against the aggregate stack:

```sh
uv run --extra demo python demo/evidence_demo.py
```

No live gateway handy? `demo/synthetic_estate.py` fabricates a realistic
multi-gateway audit estate — 3 gateways, ~2.5K records with denials, step-up
challenges, manifest drift, channel evidence, and one deliberate chain break so
the tamper detection has something to catch. Deterministic for a given seed,
and the output verifies with the real CLIs:

```sh
uv run python demo/synthetic_estate.py --out demo/estate
mcp-auth-gateway-verify-audit demo/estate/prod-us/audit.log   # chain intact
mcp-auth-gateway-verify-audit demo/estate/dev/audit.log       # tamper detected
```

---

## Configuration & development

- `AUTH_ENABLED=false` runs the pass-through (quickstart) mode; the default is
  governed.
- `.env.example` documents the gateway + upstream environment; `policy.example.yaml`
  documents the RBAC map.
- To iterate on gateway code without rebuilding the image, run just the upstream
  in Docker and the gateway on the host:
  ```sh
  docker compose up -d mcp-upstream
  uv run mcp-auth-gateway     # or: uv run uvicorn mcp_auth_gateway.main:app --port 8080
  ```
- Tests need no live tenant (JWKS is mocked with an in-process key; upstreams are
  `respx`-mocked):
  ```sh
  uv run pytest -q
  uv run ruff check .
  ```

---

## Status

The gateway is a **reference implementation** of identity-governed, evidence-
producing MCP access. Auth, RBAC, `tools/list` filtering, step-up, DPoP,
multi-upstream aggregation, the mTLS edge overlay, and the evidence pipeline
(attribution, tamper-evidence, structural metadata, SIEM/OCSF export,
framework-mapped reporting, attestation packaging) are all implemented,
tested, and demoable end to end.

## License

[MIT](LICENSE). Free and forkable, forever.
