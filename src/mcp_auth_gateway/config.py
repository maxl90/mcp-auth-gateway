"""Typed configuration for the gateway.

Values come from environment variables or a local ``.env`` file (never
committed — see ``.env.example``). Field names map to env vars
case-insensitively, so ``upstream_mcp_url`` reads ``UPSTREAM_MCP_URL``.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # The upstream MCP server's Streamable HTTP endpoint. The gateway forwards
    # requests here. For the Phase 0 demo this is the containerized
    # crystaldba/postgres-mcp behind mcp-proxy.
    upstream_mcp_url: str = "http://localhost:9000/mcp"

    # Max bytes the gateway will buffer from a single upstream response before
    # aborting. Guards the buffered paths — the aggregator's control/call RPCs
    # and the legacy tools/list filter both fully read + parse a response, so a
    # malicious or compromised upstream returning a multi-GB body could OOM the
    # shared process and drop every user's session. tools/list catalogs and tool
    # results are small; 10 MiB is generous. The plain streaming passthrough is
    # unaffected (it never buffers). 0 disables the cap.
    max_upstream_response_bytes: int = 10 * 1024 * 1024

    # --- Multi-upstream aggregation (Phase 3, ADR 005) ---
    # Path to upstreams.yaml (see upstreams.example.yaml). Setting this switches
    # the gateway into aggregation mode: /mcp becomes one stateful virtual MCP
    # server over every listed upstream (tool names namespaced <upstream>__<tool>,
    # policy keys likewise), and /mcp/<name> path-routes to a single upstream.
    # Unset (default) = legacy single-upstream proxy via UPSTREAM_MCP_URL.
    upstreams_config_path: str = ""

    # Where the gateway itself listens.
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080

    # --- Entra auth (Phase 1) ---
    # Populated by infra/provision-entra.ps1 into .env.generated. Field names map
    # to the GATEWAY_* env vars there (e.g. gateway_issuer <- GATEWAY_ISSUER).
    gateway_issuer: str = ""  # https://login.microsoftonline.com/<tenant>/v2.0
    gateway_audience: str = ""  # v2 access-token aud = the app (client) id
    gateway_jwks_url: str = ""  # tenant JWKS (discovery/v2.0/keys)

    # JWKS caching + rotation (Phase 4). The signing-key set is cached this many
    # seconds to avoid a per-request fetch; a resolution miss (e.g. a rotated key
    # not yet cached) forces one refresh and retry, but no more often than
    # jwks_refresh_min_interval — so bogus-`kid` floods can't amplify into a
    # JWKS-fetch DoS.
    jwks_cache_lifespan: int = 300
    jwks_refresh_min_interval: int = 60

    # When false, the gateway is the Phase 0 passthrough (no auth) — useful for
    # local plumbing checks. Production/demo runs with auth on.
    auth_enabled: bool = True

    # --- RBAC + audit (Phase 1) ---
    # Group-id -> allowed-tools map. provision-entra.ps1 emits policy.generated.yaml
    # with the real group object ids; policy.example.yaml documents the shape.
    policy_path: str = "policy.generated.yaml"
    # Append-only audit log (one JSON record per tool invocation). Also stdout.
    audit_log_path: str = "audit.log"

    # Tool-manifest pin baseline (backlog item 10): per-tool SHA-256 of
    # name+description+inputSchema, persisted so a manifest change across a
    # gateway restart still raises a manifest_drift audit record. Holds tool
    # metadata only — never tokens, arguments, or data.
    manifest_baseline_path: str = "manifest-baseline.json"

    # --- Step-up auth (Phase 2, ADR 006) ---
    # A tools/call for a `destructive` tool must carry a fresh, strong auth
    # assertion — an Entra authentication context id in the token's `acrs` claim,
    # authenticated within `step_up_max_age` seconds. Missing/stale → the gateway
    # returns an RFC 9470 challenge and does NOT forward. The default context id
    # applies to destructive entries that don't name their own `require_acr`;
    # the required strength (MFA / phishing-resistant / compliant device) is a
    # Conditional Access policy the customer owns in Entra, not gateway config.
    step_up_default_acr: str = "c1"
    step_up_max_age: int = 300  # seconds; freshness window for the strong auth

    # --- DPoP sender-constrained tokens (RFC 9449; ADR 008) ---
    # off        — proofs ignored.
    # if_present — (default) a token carrying cnf.jkt MUST present a valid,
    #              bound DPoP proof under the DPoP auth scheme; unbound tokens
    #              keep working as bearer tokens. Right posture while the AS
    #              (Entra today) doesn't broadly issue DPoP-bound tokens.
    # required   — additionally reject tokens with no cnf.jkt at all.
    dpop_mode: str = "if_present"
    # Acceptance window (seconds) for the proof's iat, both directions; the
    # jti replay cache holds entries for twice this.
    dpop_iat_window: int = 300

    # --- Internet edge (on-prem DMZ proxy; ADR 008) ---
    # Trust the X-Client-Cert-Serial / X-Client-Cert-DN headers set by the edge
    # reverse proxy and record them in the audit channel block. Enable ONLY
    # when the gateway is reachable exclusively by the proxy (mTLS listener or
    # network isolation) — a directly reachable gateway would let callers spoof
    # edge identity.
    trust_edge_headers: bool = False

    # Serve the gateway itself over TLS (the proxy→gateway inner hop). All
    # empty = plain HTTP (compose-internal / localhost deploys). With
    # require_client_cert, only holders of certs from the internal CA (i.e.
    # the edge proxy) can even open a connection.
    gateway_tls_certfile: str = ""
    gateway_tls_keyfile: str = ""
    gateway_tls_ca_certs: str = ""
    gateway_tls_require_client_cert: bool = False

    # --- MCP authorization spec alignment (Phase 1.5; RFC 8707/9207/9728) ---
    # Canonical resource identifier for THIS gateway, published as the PRM
    # `resource` field (RFC 9728). For Entra this is the Application ID URI
    # (api://<client-id>). Note the token's `aud` claim carries the bare
    # client-id GUID (gateway_audience) for v2 access tokens; both denote this
    # one resource. Required when auth is on — no safe default (REQ-1.5.1/1.5.6).
    gateway_resource_url: str = ""

    # Absolute external base URL (scheme://host[:port]) used to build the
    # `resource_metadata` pointer in 401 challenges when the gateway runs behind
    # a reverse proxy. Empty → derive the origin from the incoming request.
    gateway_external_base_url: str = ""

    # Scopes advertised in the PRM `scopes_supported`. Entra exposes
    # `access_as_user` (see provision-entra.ps1); the spec's MCP.Tools.* names
    # are illustrative of a future scope-based model. Set via JSON if overriding
    # in the environment, e.g. SCOPES_SUPPORTED='["access_as_user"]'.
    scopes_supported: list[str] = ["access_as_user"]

    # Authorization-server issuer identifier published in PRM
    # `authorization_servers` (RFC 9728 wants issuer identifiers, not metadata
    # URLs; clients derive the metadata URL from it). Empty → fall back to
    # gateway_issuer, which for Entra is the correct issuer identifier.
    entra_auth_server_metadata_url: str = ""


settings = Settings()
