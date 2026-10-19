# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-10-19

An audit fix: an `allowed` record now means the call was forwarded.

### Fixed

- **An `allowed` record could stand for a call that was never forwarded.** The
  schema defines `allowed` as a forwarded call, but the record was written at the
  policy decision. In aggregation mode a call the gateway then refused anyway (on
  an expired or evicted session, in a batch, to an upstream down since
  `initialize`, or naming an unknown tool) still left one, so after a restart each
  client's first call was recorded twice. `allowed` is now written as the call is
  forwarded; denials and step-up challenges are still recorded where they are
  decided. Python API: `enforce.Admitted.record_allowed()` writes them, and
  `aggregator.handler.handle_post` takes the admitted caller.

## [0.3.0] - 2026-10-19

The second review pass and the quality work after it. More of the caller's
request stops at the gateway, a subpath can no longer leave the upstream
endpoint, and request bodies are capped. The gateway's state is built at startup
instead of in module globals, token claims and audit records are typed under a
`mypy --strict` gate, and token validation no longer blocks the event loop. The
evidence tools take logs, records and packs of the wrong shape. Tests went from
231 to 351, coverage from 90% to 99%, and CI runs on Python 3.12 and 3.13.

### Added

- The evidence report bundle (and so each attestation pack's report) carries the
  counts it already computed but dropped: records naming an agent and records
  naming a human, records with a schema verdict and how many were non-conformant,
  and `coverage.chain_detail`, which says where a broken chain breaks.

### Changed

- The aggregator's 405 for an unsupported method sends `Allow: POST, DELETE`. It
  listed `GET`, which is itself a 405.
- Audit-log and manifest-baseline write failures are logged as errors on the
  `mcp_auth_gateway.audit` logger instead of printed to stderr as a JSON line. A
  failed aggregated upstream call is logged at error, as the proxy already did.
- Python API: `Policy(groups, destructive)` takes the parsed
  `{tool: StepUpRequirement}` mapping; the bare-list form is gone. The policy YAML
  still accepts either form.
- Python API: the gateway's state is built when the app starts instead of on first
  use in module globals. `main.create_app(validator=, policy=, upstreams=)` builds
  an app (`main.app` is the default one), and handlers reach its state through
  `state.of(request)`. `get_validator`, `get_policy`, `get_upstreams`,
  `get_upstream` and `get_registry` are gone. Writing records is `AuditLog.write`
  and `AuditLog.record`, and pinning is `ManifestBaseline.observe_catalog`,
  `stamp_for` and `input_schema_for`. `dpop.validate_proof` and `dpop.enforce`
  take the `ReplayCache` to use, and `enforce.enforce` returns the admitted caller,
  whose `allowed_tools()` replaces `enforce.allowed_tools`. `AUTH_ENABLED` is read
  once, at startup.
- Token claims and audit records are typed (`auth.claims.Claims`,
  `audit.writer.AuditRecord`). CI type-checks `src` with `mypy --strict`, and the
  test coverage floor is 95% (it was 87%). The tests run on Python 3.12 and 3.13.
- PyJWT 2.14 or later is required (it was 2.9). Validation now runs on worker
  threads and relies on the JWKS client's lock and refresh cooldown, which 2.14
  added. Before it, every unknown `kid` re-fetched the JWK set, past the gateway's
  own throttle, so a flood of tokens with made-up kids meant one fetch per token.

### Security

- **More of the caller's request stops at the gateway.** Only `Authorization` was
  stripped before forwarding; the `DPoP` proof, cookies, and the client's own
  `Forwarded`, `X-Forwarded-*`, `X-Real-IP` and `X-Client-Cert-*` headers reached
  the upstream as sent. They are now dropped, so an upstream never sees the
  caller's credentials or forwarding values the caller chose.
- **A subpath can no longer leave the upstream endpoint.** The route receives the
  path percent-decoded, so `POST /mcp/..%2Fadmin` reached `/admin` on the upstream
  host. Each `/mcp/<subpath>` segment must now be letters, digits, `-`, `.`, `_` or
  `~` and not a dot segment, or the request is a 404. That also refuses a
  double-encoded `..`, `;` path parameters, backslashes and control characters.
- **Request bodies are capped.** The body is read before the token is checked, and
  it had no limit, so an unauthenticated client could make the gateway hold an
  arbitrarily large body in memory. `MAX_UPSTREAM_RESPONSE_BYTES` now caps request
  bodies too (413 past it); `0` still disables the cap.
- **A full DPoP replay cache checked a `jti` only after making room.** A replay of
  the oldest remembered `jti` was evicted and then accepted as new. Filling the
  cache takes valid proofs, which only the key holder can sign; a remembered `jti`
  is now refused before anything is evicted.
- **An unbound token under the `DPoP` scheme is refused.** With DPoP on, a token
  without `cnf.jkt` sent as `Authorization: DPoP <token>` was read as a bearer
  token and its `DPoP` header never checked. It is now a 401 `invalid_token`; the
  same token still works under `Bearer`, and `DPOP_MODE=off` is unchanged.

### Fixed

- **An upstream timeout was a 500.** The proxy caught only `httpx.ConnectError`,
  and a connect timeout, read timeout or reset is not one. Any transport failure
  is now the 502 `upstream_unreachable` it was meant to be, and an upstream that
  drops a `tools/list` response mid-body is a 502 `upstream_response_incomplete`.
- **A token whose `kid` named a non-RSA key was a 500.** PyJWT raises `TypeError`
  when the key type does not fit the `alg`; it is now a 401 `invalid_token`.
- **A malformed `tools/list` result took down the merged catalog.** An upstream
  whose `result` was not an object with a `tools` list made the aggregated
  `tools/list` a 500. That upstream is now left out and audited as `degraded`, like
  any other failed upstream.
- **A policy whose `allow` is not a list of tool names now refuses to start.**
  `allow: execute_sql` was split into one "tool" per character.
- **Group overage is named in the denial.** When Entra replaces `groups` with a
  `_claim_names` pointer, the caller is still denied, and the audit reason now says
  why. A `groups` claim that is not a list grants nothing.
- Single-upstream responses carried the upstream's `date` and `server` headers next to
  the gateway's own, so clients saw two of each. The proxy now drops the upstream's copies;
  every other response header, including `Mcp-Session-Id`, still passes through.
- **A slow JWKS endpoint stalled the whole gateway.** The signing-key lookup fetched
  the JWK set with a blocking call on the event loop, so while a cold cache, a
  rotated key or a slow endpoint was being fetched, every other request waited:
  `/healthz` took 2.6 s behind a 3 s fetch. Validation now runs on a worker thread,
  and `/healthz` answers in milliseconds meanwhile.
- **The evidence tools crashed on a log line that is JSON but not an object.** A
  line such as `[1]` was passed on as a record. `verify-audit` now names it as the
  first bad line, the exporters and the report skip it, and an attestation pack
  still builds and says the chain is broken. A pack whose `pack-manifest.json` is
  not an object, or whose `files`, `signature` or `chain` has the wrong type, fails
  verification with the problem named instead of crashing the verifier. A record
  that chain-verifies but whose nested fields have the wrong type (an `actor` of
  `"x"`, `arguments` of `5`) crashed the exporters, the report and the pack build;
  such a field now reads as absent.
- A log whose last record's `record_hash` is not a string starts a new chain, as
  any other corrupt tail does, instead of chaining to that value.
- An attestation signing key that is not Ed25519 is refused by name; the build
  failed with "format is invalid with this key".
- The proxy drops the headers a message's `Connection` field names, in both
  directions, as RFC 9110 §7.6.1 requires. Only its fixed hop-by-hop set was
  dropped before.

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
