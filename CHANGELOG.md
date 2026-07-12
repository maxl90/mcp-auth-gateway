# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  (`docker-compose.edge.yml` + `infra/edge/`) with hard-fail edge mTLS, a
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
