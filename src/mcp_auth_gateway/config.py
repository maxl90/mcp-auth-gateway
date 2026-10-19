"""Typed configuration for the gateway.

Values come from environment variables or a local ``.env`` file (never
committed; see ``.env.example``). Field names map to env vars
case-insensitively, so ``upstream_mcp_url`` reads ``UPSTREAM_MCP_URL``. The
README's configuration table explains each setting.
"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # The upstream MCP server's Streamable HTTP endpoint (single-upstream mode).
    upstream_mcp_url: str = "http://localhost:9000/mcp"
    # Cap on any body the gateway buffers: every request body (read before authentication)
    # and the upstream responses it parses (tools/list filtering, aggregator RPCs). 0 disables.
    max_upstream_response_bytes: int = 10 * 1024 * 1024

    # Path to upstreams.yaml; setting it switches the gateway into aggregation mode.
    upstreams_config_path: str = ""
    # Attribution headers on aggregated tools/call: audit metadata, never an authorization input.
    forward_attribution_headers: bool = False

    # Where the gateway itself listens.
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080

    # Entra token validation: issuer, v2 audience (the app client id), and the tenant JWKS.
    gateway_issuer: str = ""
    gateway_audience: str = ""
    gateway_jwks_url: str = ""
    # JWKS cache lifetime, and the minimum gap between forced refreshes on a key miss.
    jwks_cache_lifespan: int = 300
    jwks_refresh_min_interval: int = 60
    # False makes the gateway an unauthenticated passthrough (the quickstart).
    auth_enabled: bool = True

    # Group-id -> allowed-tools policy file (see examples/policy.example.yaml).
    policy_path: str = "policy.generated.yaml"
    # Append-only audit log; records also go to stdout.
    audit_log_path: str = "audit.log"
    # Pinned tool-manifest hashes, persisted so drift survives a restart (tool metadata only).
    manifest_baseline_path: str = "manifest-baseline.json"

    # Step-up: the Entra authentication-context id destructive tools require, and its freshness.
    step_up_default_acr: str = "c1"
    step_up_max_age: int = 300

    # DPoP: off, if_present (bound tokens must prove possession), or required.
    dpop_mode: Literal["off", "if_present", "required"] = "if_present"
    # Acceptance window for a proof's iat, seconds both ways; replays are kept twice as long.
    dpop_iat_window: int = 300

    # Trust the X-Client-Cert-Serial / X-Client-Cert-DN headers set by the edge
    # reverse proxy and record them in the audit channel block. Enable ONLY
    # when the gateway is reachable exclusively by the proxy (mTLS listener or
    # network isolation) — a directly reachable gateway would let callers spoof
    # edge identity.
    trust_edge_headers: bool = False

    # Serve TLS from the gateway; require_client_cert admits only certs from gateway_tls_ca_certs.
    gateway_tls_certfile: str = ""
    gateway_tls_keyfile: str = ""
    gateway_tls_ca_certs: str = ""
    gateway_tls_require_client_cert: bool = False

    # Canonical resource identifier (Entra: api://<client-id>); required when auth is on.
    gateway_resource_url: str = ""
    # External base URL for 401 resource_metadata pointers behind a proxy; empty = request origin.
    gateway_external_base_url: str = ""
    # Scopes advertised in the PRM document (JSON list in the environment).
    scopes_supported: list[str] = ["access_as_user"]
    # Authorization-server issuer for PRM authorization_servers; empty = gateway_issuer.
    entra_auth_server_metadata_url: str = ""


settings = Settings()
