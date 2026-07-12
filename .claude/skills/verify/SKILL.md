---
name: verify
description: Live-verify a gateway change end-to-end on Windows without Entra or Docker — fake upstream + local JWKS + minted tokens, real gateway process, drive over HTTP.
---

# Live-verify the gateway (no Entra, no Docker)

The gateway's surface is HTTP. Real token validation, RBAC, step-up, audit,
and aggregation all run locally if you stand up (1) a fake MCP upstream and
(2) a local JWKS endpoint the gateway is pointed at, then mint your own RS256
tokens. No tenant, no containers.

## Harness (one script serves upstream + JWKS + token mint)

A ~100-line `http.server` script (run it with the repo venv's python — it needs
`pyjwt[crypto]`, already installed) on port 9701 serving:

- `GET /keys` — JWKS: `jwt.algorithms.RSAAlgorithm.to_jwk(pub)` + `kid`/`alg`/`use`.
- `GET /token` — RS256 token signed by the same in-process key, `headers={"kid": ...}`,
  claims: `iss`/`aud` matching the gateway env below, `exp`, `groups` matching the
  policy file, plus `azp`/`app_displayname`/`oid`/`preferred_username`/`tid` so
  attribution fields populate.
- `POST /mcp` — minimal Streamable HTTP MCP server (`application/json` replies):
  `initialize` → result + `Mcp-Session-Id` header; `notifications/*` → 202;
  `tools/list` → tools read from a **state JSON file** (mutate it mid-flight to
  simulate manifest drift/rug-pulls); `tools/call` → canned ok result.

## Gateway launch

```powershell
$env:AUTH_ENABLED="true"
$env:GATEWAY_ISSUER="https://fake-issuer.live-verify"     # = token iss
$env:GATEWAY_AUDIENCE="live-verify-client"                # = token aud
$env:GATEWAY_JWKS_URL="http://127.0.0.1:9701/keys"
$env:GATEWAY_RESOURCE_URL="api://live-verify-client"
$env:UPSTREAMS_CONFIG_PATH="...\upstreams.yaml"           # aggregation mode
$env:POLICY_PATH="...\policy.yaml"                        # groups: {<gid>: {allow: [demo__tool]}}
$env:AUDIT_LOG_PATH="...\audit.log"
$env:MANIFEST_BASELINE_PATH="...\manifest-baseline.json"
$env:GATEWAY_HOST="127.0.0.1"; $env:GATEWAY_PORT="9702"
Start-Process .venv\Scripts\mcp-auth-gateway.exe   # inherits $env:
```

Run from a scratch dir so the repo's `.env` isn't picked up (pydantic-settings
reads `.env` relative to CWD). Probe `GET /healthz` → `"mode": "aggregate"`.

## Drive + observe

Drive with a small httpx script: fetch `/token`, `initialize` (capture
`mcp-session-id`), `notifications/initialized`, then `tools/list` /
`tools/call` with the token. Evidence = `audit.log` records (JSONL), the
baseline file, and the CLIs:

```
.venv\Scripts\mcp-auth-gateway-verify-audit.exe <audit.log>   # chain intact?
.venv\Scripts\mcp-auth-gateway-export-audit.exe <audit.log>   # SIEM columns
```

## Gotchas (all hit for real)

- **PowerShell 5.1 mangles JSON in native args** — never pass JSON bodies as
  script arguments; put actions/payloads in files.
- **BOM**: PS 5.1 `Set-Content -Encoding utf8` writes a BOM that breaks
  `json.loads` in the harness. Write JSON files via
  `[IO.File]::WriteAllText($p, $s, (New-Object System.Text.UTF8Encoding($false)))`.
- Restart tests: `Stop-Process -Name mcp-auth-gateway -Force`, mutate state,
  relaunch with the same env — the audit chain must continue (seeded from the
  log tail) and the manifest baseline must survive (file-persisted).
- The upstream client requires `initialize` to return a JSON-RPC message with
  an `id` and accepts 202-no-body for notifications; content-type must be
  `application/json` (or SSE).

## Flows worth driving

- 401 with no token; 403 for a tool outside the policy allow-list.
- `tools/call` before any `tools/list` (aggregation namespace fallback path).
- `tools/list` → per-tool pins in the baseline file; mutate state file →
  `manifest_drift` record; mutate while gateway is DOWN → drift still caught
  after restart.
- Non-conformant `tools/call` args (invented field, wrong type) → forwarded
  (log-never-reject) with `arguments.conformance` populated; grep the audit
  log for the argument values to confirm zero leakage.
