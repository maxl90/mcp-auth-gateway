# mcp-auth-gateway

An OAuth 2.1 reverse proxy for MCP servers: validates Entra ID tokens, enforces
tool-level RBAC, and writes a hash-chained, argument-free audit log.

```
client (agent)                  mcp-auth-gateway                            upstream MCP server(s)
--------------                  ----------------                            ----------------------
POST /mcp ------------------->  1. validate the token against the IdP's JWKS
Authorization: Bearer <jwt>     2. tools/call? RBAC, then step-up, then DPoP
                                3. write the audit record (no argument values)
                                4. strip Authorization, forward ---------->  the server reaches its
                                                                             resource with its OWN
          <-------------------  5. tools/list answers filtered <----------  credential
                                   to the caller's permitted tools
```

The token is validated at the gateway and never forwarded; each upstream reaches
its resource with its own service identity. The audit record carries who (the
agent and the human it acted for), which tool, which tables or columns a query
touched, and the outcome, but never the argument values.

## Quickstart

Requires Docker. One command brings up the gateway, a sample MCP server, and a
seeded Postgres with authentication turned off:

```sh
docker compose -f docker-compose.quickstart.yml up --build
```

In another shell, do the MCP handshake (no token needed in this mode):

```sh
curl -s -i -X POST http://localhost:8080/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

What you just saw is pass-through mode: `AUTH_ENABLED=false`, no identity, no
RBAC. The governed mode below is the gateway as intended.

## Governed mode

Requires Docker, [`uv`](https://docs.astral.sh/uv/), and a development Entra tenant.

```sh
# 1. Provision a dev tenant once: an app, two security groups, two test users.
#    Writes .env.generated (issuer, audience, JWKS) and policy.generated.yaml.
pwsh infra/provision-entra.ps1

# 2. Bring up the governed stack: gateway :8080 -> mcp-upstream :9000 -> Postgres.
docker compose up -d --build

# 3. Call a tool as the allowed (analyst) user: device-code login, then a SELECT.
uv run --extra demo python demo/client.py

# 4. The same call as the denied (readonly) user is 403 and never reaches the database.
GATEWAY_LOGIN_HINT=<readonly-upn> uv run --extra demo python demo/client.py

# 5. The evidence: structured, attributed, redacted audit lines.
docker compose logs gateway
```

An unauthenticated request is refused before it goes anywhere and points a cold
client at discovery:

```sh
curl -i -X POST http://localhost:8080/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_sql"}}'
# -> 401; WWW-Authenticate: Bearer realm="mcp", resource_metadata=".../.well-known/oauth-protected-resource"
```

## Features

| Feature | Standard | Settings | Code |
|---|---|---|---|
| Token validation against the tenant JWKS (RS256/384/512 only, key rotation), then termination: the token is never forwarded | OAuth 2.1 | `GATEWAY_ISSUER`, `GATEWAY_AUDIENCE`, `GATEWAY_JWKS_URL` | `auth/token_validator.py`, `proxy.py` |
| Protected Resource Metadata and the `resource_metadata` pointer on every 401 | RFC 9728, 8707, 9207 | `GATEWAY_RESOURCE_URL`, `GATEWAY_EXTERNAL_BASE_URL` | `auth/discovery.py` |
| Tool-level RBAC: Entra groups to allowed tools; a disallowed `tools/call` is 403 and not forwarded | | `POLICY_PATH` | `auth/policy_resolver.py`, `auth/enforce.py` |
| `tools/list` filtered to the caller's tools (JSON and SSE bodies) | | `POLICY_PATH` | `tools_filter.py` |
| Step-up: destructive tools need a fresh Entra authentication context or get a challenge | RFC 9470 | `STEP_UP_DEFAULT_ACR`, `STEP_UP_MAX_AGE` | `auth/step_up.py` |
| DPoP: a key-bound token must prove possession on every request | RFC 9449 | `DPOP_MODE`, `DPOP_IAT_WINDOW` | `auth/dpop.py` |
| Aggregation: many MCP servers behind one `/mcp` with a merged, namespaced (`upstream__tool`) catalog and per-call routing | | `UPSTREAMS_CONFIG_PATH` | `aggregator/` |
| Audit log: hash-chained records with the agent/human split, value-free argument structure, tool-manifest drift, and schema conformance | | `AUDIT_LOG_PATH`, `MANIFEST_BASELINE_PATH` | `audit/` |
| Evidence CLIs: chain verification, Sentinel and OCSF export, framework reports, signed attestation packs | OCSF 1.1 | | `audit/verify.py`, `audit/export.py`, `evidence/` |
| mTLS edge overlay: an nginx DMZ proxy with a second mTLS hop to the gateway; the client-cert identity lands in the audit `channel` block | | `TRUST_EDGE_HEADERS`, `GATEWAY_TLS_*` | `deploy/compose/docker-compose.edge.yml`, `infra/edge/` |

## Configuration

Settings come from environment variables or a `.env` file; each env var is the
field name in upper case.

| Setting | Default | Meaning |
|---|---|---|
| `UPSTREAM_MCP_URL` | `http://localhost:9000/mcp` | The upstream MCP server's Streamable HTTP endpoint in single-upstream mode. |
| `UPSTREAMS_CONFIG_PATH` | empty | Path to an `upstreams.yaml`; setting it switches to aggregation mode. |
| `MAX_UPSTREAM_RESPONSE_BYTES` | `10485760` | Cap on any upstream response the gateway buffers (the `tools/list` filter and aggregator RPCs); streaming passthrough is unaffected. `0` disables it. |
| `FORWARD_ATTRIBUTION_HEADERS` | `false` | In aggregation mode, send `X-MCP-Gateway-Correlation-Id` and `X-MCP-Gateway-On-Behalf-Of` with each `tools/call`. Audit metadata only; a backend must never authorize on them. |
| `GATEWAY_HOST`, `GATEWAY_PORT` | `0.0.0.0`, `8080` | Where the gateway listens. |
| `AUTH_ENABLED` | `true` | **Warning:** `false` forwards every request unauthenticated. The quickstart's pass-through mode. |
| `GATEWAY_ISSUER` | empty | Entra issuer, `https://login.microsoftonline.com/<tenant>/v2.0`. Required when auth is on. |
| `GATEWAY_AUDIENCE` | empty | Expected `aud`: the app (client) id for v2 access tokens. Required when auth is on. |
| `GATEWAY_JWKS_URL` | empty | The tenant's signing keys, `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`. Required when auth is on. |
| `JWKS_CACHE_LIFESPAN` | `300` | Seconds the fetched key set is cached. |
| `JWKS_REFRESH_MIN_INTERVAL` | `60` | A key-resolution miss forces one refresh and retry, but no more often than this, so bogus `kid` floods cannot become a JWKS fetch storm. |
| `GATEWAY_RESOURCE_URL` | empty | Canonical resource identifier in Protected Resource Metadata (Entra: `api://<client-id>`). Required when auth is on; the gateway refuses to start without it. |
| `GATEWAY_EXTERNAL_BASE_URL` | empty | Public `scheme://host[:port]` for the `resource_metadata` pointer behind a reverse proxy, also accepted as a DPoP `htu` base. Empty derives it from the request. |
| `SCOPES_SUPPORTED` | `["access_as_user"]` | Scopes advertised in the PRM document (a JSON list in the environment). |
| `ENTRA_AUTH_SERVER_METADATA_URL` | empty | Issuer identifier published in PRM `authorization_servers`; empty falls back to `GATEWAY_ISSUER`. |
| `POLICY_PATH` | `policy.generated.yaml` | Group-id to allowed-tools map; `examples/policy.example.yaml` documents the shape. |
| `AUDIT_LOG_PATH` | `audit.log` | Append-only JSONL audit log; records also go to stdout. |
| `MANIFEST_BASELINE_PATH` | `manifest-baseline.json` | Pinned per-tool SHA-256 of `name` + `description` + `inputSchema`, persisted so drift survives a restart. Tool metadata only. |
| `STEP_UP_DEFAULT_ACR` | `c1` | Entra authentication-context id a destructive tool requires in `acrs`, unless the policy names its own `require_acr`. The strength behind it is a Conditional Access policy in Entra. |
| `STEP_UP_MAX_AGE` | `300` | Seconds since `auth_time` within which that authentication counts as fresh. |
| `DPOP_MODE` | `if_present` | `off` ignores proofs; `if_present` requires a valid proof for any token carrying `cnf.jkt` and lets unbound tokens work as bearer tokens; `required` also rejects tokens without `cnf.jkt`. |
| `DPOP_IAT_WINDOW` | `300` | Acceptance window for a proof's `iat`, seconds both ways; the `jti` replay cache keeps entries for twice this. |
| `TRUST_EDGE_HEADERS` | `false` | **Warning:** enable only when nothing but the edge proxy can reach the gateway. Records the proxy's `X-Client-Cert-Serial` / `X-Client-Cert-DN` in the audit `channel` block; a directly reachable gateway would let callers spoof edge identity. |
| `GATEWAY_TLS_CERTFILE`, `GATEWAY_TLS_KEYFILE` | empty | Serve TLS from the gateway itself (the inner hop of the edge pattern). Applies to the `mcp-auth-gateway` console script; the container image's default command runs uvicorn directly, so the edge overlay passes `--ssl-*` flags instead. |
| `GATEWAY_TLS_CA_CERTS`, `GATEWAY_TLS_REQUIRE_CLIENT_CERT` | empty, `false` | With `require_client_cert`, only holders of a certificate from this CA (the edge proxy) can open a connection. |

## Run modes

**Single upstream.** `UPSTREAM_MCP_URL` names one MCP server and `/mcp` proxies
to it: every request is authenticated, a `tools/call` is authorized, a
`tools/list` answer is filtered, everything else streams through.
`docker compose up -d --build` is this mode with the Postgres upstream.

**Path-routed.** With `UPSTREAMS_CONFIG_PATH` set, `/mcp/<name>` is a stateless
proxy to the upstream of that name. Wire tool names are the upstream's own; RBAC
and audit prefix them, so one namespaced policy file governs every route.

**Aggregated.** With the same config, `/mcp` is one virtual MCP server over every
upstream: the gateway answers `initialize`, opens a session to each upstream,
merges the catalogs under `upstream__tool` names, and routes each call to its
owner. A dead upstream degrades the catalog (audited) while a call to it fails.

```sh
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.github.yml \
  -f deploy/compose/docker-compose.aggregate.yml up -d --build
uv run --extra demo python demo/list_tools.py   # the merged, filtered catalog
```

See `examples/upstreams.example.yaml` and `examples/policy.aggregate.example.yaml`.

## Evidence

Every governed call is logged as an attributed, hash-chained record. The schema
is locked at 1.2; 1.x changes are additive, so SIEM queries keep working.

```sh
# Verify the audit trail hasn't been tampered with (walks the hash chain):
mcp-auth-gateway-verify-audit audit.log

# Flatten the log for SIEM ingestion (Microsoft Sentinel column shape by
# default; --format ocsf emits OCSF API Activity [class 6003] events instead):
mcp-auth-gateway-export-audit audit.log > audit.siem.jsonl
mcp-auth-gateway-export-audit audit.log audit.ocsf.jsonl --format ocsf

# Generate a framework-mapped evidence report (nist-ai-rmf, eu-ai-act, soc2):
mcp-auth-gateway-evidence-report audit.log nist-ai-rmf report.md

# Build a single auditor-verifiable ZIP: the full hash-chained log, evidence
# reports for all three frameworks (time-windowable via --from/--to),
# Sentinel + OCSF exports, and a SHA-256 pack manifest (optionally
# Ed25519-signed). --verify re-checks everything and exit-codes the result;
# --public-key pins the signer (without it the key embedded in the pack is trusted).
mcp-auth-gateway-attestation-pack audit.log pack.zip --signing-key signing.pem
mcp-auth-gateway-attestation-pack --verify pack.zip --public-key <hex>
```

`demo/evidence_demo.py` drives allowed, denied and step-up traffic through the
aggregated stack and then shows the evidence. `demo/synthetic_estate.py`
fabricates a multi-gateway audit estate, with one deliberate chain break, for
trying the CLIs without a live gateway.

## Limitations

- Single process. The DPoP replay cache, aggregation sessions and the audit
  chain live in memory or per process; run one worker. Replicas would each keep
  their own.
- No DPoP server nonce (RFC 9449 §8); the `iat` window and the `jti` cache bound
  a proof's lifetime instead.
- No session binding in single-upstream mode: `Mcp-Session-Id` is forwarded as
  received, so one caller could act inside another's upstream session. Each
  call is still RBAC-checked.
- `tools/list` filtering is visibility, not enforcement; `tools/call` RBAC is the
  control. A response the filter cannot parse passes through unchanged.
- Tested against Entra ID only. Another OAuth 2.1 issuer should work through the
  issuer and JWKS settings, but has not been exercised.
- No shared state or high availability. The audit sink is a local file; export
  it to a SIEM for retention.
- An attestation pack's signature is checked against the pack's own embedded key
  unless `--public-key` pins the signer.

## Development

```sh
uv sync --extra dev
uv run pytest -q                                  # no tenant: in-process RSA key, respx upstreams
uv run ruff check . && uv run ruff format --check .
uv run python tools/config_viewer.py              # local dashboard over .env, policies, audit.log
docker compose up -d mcp-upstream && uv run mcp-auth-gateway   # gateway on the host, upstream in Docker
```

The gateway can be exercised end to end without Entra or Docker: one small
`http.server` script serves a fake Streamable HTTP MCP upstream, a JWKS endpoint,
and a token mint signed by the same in-process RSA key. Point the gateway at it
(`AUTH_ENABLED=true`, `GATEWAY_JWKS_URL=http://127.0.0.1:9701/keys`, an issuer,
audience and resource URL that match the minted tokens, a policy file naming the
fake tools), drive `initialize`, `tools/list` and `tools/call` with the token,
then read `audit.log` and run the CLIs. Restart the gateway mid-run to see the
chain continue from the log tail and the manifest baseline survive. The full
recipe, with the Windows gotchas, is `.claude/skills/verify/SKILL.md`.

## Security and license

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
[MIT](LICENSE).
