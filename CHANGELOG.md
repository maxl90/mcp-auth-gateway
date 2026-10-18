# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-18

The pre-public cleanup. The repository is laid out for readers (`deploy/`,
`examples/`, `tools/`), the code is split along its seams, prose that cited
planning documents outside the repository is gone, and the README is written for
someone who has never seen the project. Tests went from 194 to 231, with a
coverage floor and a format check in CI.

### Added

- **Attribution headers to upstreams** (`FORWARD_ATTRIBUTION_HEADERS`, off by
  default). In aggregation mode each `tools/call` sent upstream can carry
  `X-MCP-Gateway-Correlation-Id` (the audit record's `correlation_id`) and
  `X-MCP-Gateway-On-Behalf-Of` (the human's `oid`; omitted for app-only tokens),
  so a backend's own change log can name the gateway record that asked. They are
  audit metadata, never an authorization input; no token and no argument is
  forwarded; neither `initialize` nor `tools/list` carries them.
- `mcp-auth-gateway-attestation-pack --verify PACK --public-key HEX` pins the
  signer. Without the pin the check uses the key embedded in the pack itself and
  the CLI says so; `VERIFY.md` in every signed pack tells the auditor to pin.
- The aggregator's session registry bounds live sessions: at most 16 per
  principal and an idle TTL of 3600 seconds, evicted (and torn down upstream)
  on the next `initialize`.
- A README settings table documents every setting, its default, and the reasoning
  behind it, including that the `GATEWAY_TLS_*` settings apply to the console
  script and not to the image's default command.
- CI runs three jobs: lint (`uv lock --check`, `ruff check`, `ruff format
  --check`), test (pytest with `--cov-fail-under=87`), and `docker build .`.
- `.gitattributes` pins LF line endings (CRLF for PowerShell), so the edge shell
  scripts run from any checkout.

### Changed

- Repository layout: compose overlays live in `deploy/compose/`, the demo upstream
  images in `deploy/upstreams/`, the seed SQL in `deploy/db/`, the example policy
  and upstream files in `examples/`, and the config viewer is
  `tools/config_viewer.py`. `OVERVIEW.md` is folded into the README.
- `main.py` is the app, boot checks and routes; the enforcement pipeline is
  `auth/enforce.py`, single-upstream forwarding is `proxy.py`, and the aggregated
  entry point lives with its handler. `jsonrpc`, `http_util`, `naming` and
  `audit/log` hold the parsers and helpers that were previously duplicated.
- `/healthz` returns `{"status": "ok", "mode": "single" | "aggregate"}` and no
  longer lists upstream URLs on an unauthenticated route.
- Aggregator error bodies for a failed upstream call are generic (`upstream
  'name' failed`) with an `X-Correlation-Id`; the failure detail is logged under
  that id.
- `DPOP_MODE` is validated when settings load; a bad value refuses to start
  instead of answering every request with a server error.
- One version source: `serverInfo`, `clientInfo` and the attestation manifest
  report the installed package version. The OCSF export's `product.vendor_name`
  is `mcp-auth-gateway`.
- Python API: `audit.writer.record` and `build_record` take an `AuditEvent`;
  `evidence.attestation.build_pack` takes a `PackOptions`;
  `aggregator.upstream_client.rpc` and `call_tool` take an `UpstreamRequest`;
  `verify-audit` and `evidence-report` parse arguments with argparse (same
  positional shape).

### Fixed

- **Parallel calls on one session shared a single answer.** In aggregation mode
  every request to an upstream carried JSON-RPC id `1`. A stateful upstream keys
  each pending response by its request id, so when a client sent several
  `tools/call` requests at once to one upstream, the last to arrive received the
  first result and the rest received nothing until they timed out. Each upstream
  session now numbers its requests, the caller's own id is restored on the way
  back, and a response carrying another request's id is refused. The collision
  was within one client session only.
- **Upstream control RPCs had no read timeout.** The upstream client accepted a
  timeout and never applied it to the request, so a hung upstream hung the
  caller's `initialize` or `tools/list` on the pooled client, which has no read
  bound. The timeout now rides on each request.
- A `tools/call` whose `params` is not a JSON object no longer fails inside the
  gateway; the unnamed tool is denied like any unknown tool.
- Aggregated session ownership binds to the human's `oid`, else `sub`, else the
  app's `azp`. Two app-only tokens (no `oid`) could previously drive each other's
  session.

### Removed

- Dead code: two unused "deprecated alias" names, `SessionRegistry.sessions_for_oid`,
  `UpstreamSession.alive`, and `Policy.is_destructive`.

## [0.1.0] - 2026-07-12

First versioned snapshot of the reference implementation. Everything below is
implemented, tested, and demoable end to end.

### Added

- **OAuth 2.1 resource server** — local validation of Entra ID tokens against
  the tenant JWKS (signature, issuer, audience, expiry; key-rotation aware),
  with token **termination at the gateway**: the user token is never forwarded
  upstream. Protected Resource Metadata discovery (RFC 8707/9207/9728).
- **Tool-level RBAC** — Entra group memberships map to allowed tool sets via
  `policy.yaml`; disallowed `tools/call` is `403` and never forwarded.
- **`tools/list` filtering** — callers only see the tools they can invoke
  (JSON and SSE responses).
- **Step-up authentication** (RFC 9470) — destructive tools require a fresh,
  stronger authentication assertion or the call is challenged, not forwarded.
- **DPoP sender-constrained tokens** (RFC 9449) — proof-of-possession
  enforcement with `DPOP_MODE` = `off` / `if_present` / `required`.
- **Multi-upstream aggregation** — many MCP servers behind one virtual MCP
  endpoint: merged, RBAC-filtered, namespaced (`upstream__tool`) catalog with
  per-call routing and partial-failure tolerance.
- **Hash-chained audit log** — tamper-evident, structured records with the
  agent/human attribution split (acting agent vs. the human principal it acted
  on behalf of) and value-free structural argument metadata.
- **Evidence CLIs** — `verify-audit` (chain verification), `export-audit`
  (Microsoft Sentinel flattening + OCSF API Activity via `--format ocsf`),
  `evidence-report` (NIST AI RMF, EU AI Act, SOC 2), and `attestation-pack`
  (one-command auditor-verifiable ZIP with SHA-256 manifest and optional
  Ed25519 signature, re-checkable via `--verify`).
- **On-prem mTLS internet edge** — nginx DMZ reverse-proxy overlay
  (`deploy/compose/docker-compose.edge.yml` + `infra/edge/`) with hard-fail edge mTLS, a
  second mTLS hop to the gateway, CRL-based revocation, and cert-expiry
  monitoring.
- **Synthetic estate demo** (`demo/synthetic_estate.py`) — deterministic
  multi-gateway audit fixtures (~2.5K records across 3 gateways, including one
  deliberate chain break) for demos without a live gateway.

### Notes

- **Audit schema history**: v1.0 locked at launch → v1.1 added tool-manifest
  drift detection and inputSchema conformance telemetry → v1.2 added the
  `channel` block (edge mTLS client-cert identity + DPoP key thumbprint).
  All 1.x changes are strictly additive.
- **MCP protocol**: targets `2025-06-18` when connecting upstream; accepts
  `2025-03-26` / `2025-06-18` / `2025-11-25` from clients.
