# mcp-auth-gateway — Overview

A governed reverse proxy that sits in front of your MCP servers and produces
**attributed, tamper-evident audit evidence** of everything your agents do —
identity-checked, policy-filtered, and **without your data ever leaving the
network**. It is a reference implementation of the agent attribution and
audit-evidence layer for enterprise AI agents.

---

## The core idea

- Runs **inside your network**, in front of one or many MCP servers.
- Validates each caller's identity, forwards only authorized calls, and records
  a structured evidence trail of every tool invocation.
- **User tokens and raw tool-call arguments never leave your network.** Only the
  upstream MCP server and your own audit sink see them. No SaaS in the request
  path — nothing for a compliance review to veto.
- Answers the question no single platform answers: *which agent did what, on
  whose behalf, on what data — in a form an auditor accepts.*

---

## What it does

**Identity & access**
- Validates **Entra ID OAuth 2.1 tokens** locally against the tenant JWKS
  (signature / issuer / audience / expiry; RS-family only, `none`/HMAC rejected).
- **Terminates the token at the gateway** — validated, then stripped; never
  forwarded upstream. Each upstream reaches its resource with its **own service
  identity**.
- **Tool-level RBAC** — maps identity (Entra groups) to an allowed tool set via a
  human-editable policy file; disallowed calls are blocked and never forwarded.
- **`tools/list` filtering** — callers only *see* the tools they can invoke.
- **Step-up auth on destructive tools** (RFC 9470) — high-impact actions require a
  fresh, stronger authentication; otherwise the call is challenged, not forwarded.
- Handles **JWKS key rotation** transparently.

**Multi-upstream aggregation**
- Fronts many MCP servers as **one virtual MCP server**: a single merged,
  RBAC-filtered, namespaced catalog, with each call routed to its owning upstream.
- Tolerant of partial upstream failure; reconnects dropped upstream sessions
  transparently.

**Audit evidence (the differentiator)**
- Every invocation produces a structured record that:
  - **Attributes the acting agent distinctly from the human** it acted on behalf
    of — solving the attribution problem (agents run under user credentials, so
    naive logs blame the human).
  - Captures **value-free structural metadata** — which tables/columns a query
    touched and whether PII-shaped data was involved, or a tool's argument keys —
    **never the argument values**.
  - Is **hash-chained and tamper-evident** — any edit or deletion is detectable.
- Ships CLIs to **verify** the trail's integrity, **export** it in a SIEM-ready
  shape (Microsoft Sentinel), and generate a **GRC-framework-mapped evidence
  report** (NIST AI RMF starter, extensible to other frameworks).

---

## Architecture at a glance

- **Data plane only.** The gateway is the enforcement + evidence sensor; it holds
  no database. State lives in memory (connection pools, policy, sessions) or in
  the append-only audit log. Restart costs zero re-authentication.
- **Upstreams keep their own identity.** Per-user attribution comes from the audit
  log, not a propagated credential.
- **Trust boundary is the design.** Only redacted, signed audit metadata could
  ever leave the boundary — never tokens, never arguments, never data.

---

## Run modes

- **Quickstart** — one command, no identity provider, auth off: see the proxy run
  from a clean checkout.
- **Governed** — with a dev Entra tenant: full identity + RBAC + evidence.
- **Aggregated** — multiple upstreams behind one governed endpoint.
- A narrated end-to-end demo drives allowed / denied / step-up traffic and then
  surfaces the attribution, tamper-evidence, and framework report.

---

## Scope

- **Is:** an open-source (MIT) reference implementation of identity-governed,
  evidence-producing MCP access — deployable, testable, demoable end to end.
- **Complements** platform identity products (Entra Agent ID, Okta for AI Agents)
  as the neutral cross-vendor evidence layer above them — not a competitor to
  their enforcement.
- **Is not:** a hosted SaaS, a control plane, or a data store. Cross-platform
  aggregation, an attribution graph, and managed attestations are a separate layer.

---

## Status

Identity/auth, RBAC, `tools/list` filtering, step-up, multi-upstream aggregation,
and the full evidence pipeline (attribution, structural metadata, tamper-evidence,
SIEM export, framework-mapped reporting) are **implemented, tested, and verified
end to end**. Deliberately deferred until real load or a customer needs them:
upstream-session pooling and multi-replica HA. See `README.md` to run it.
