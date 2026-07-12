# infra/edge — On-Prem Internet Edge (mTLS DMZ)

The DMZ reverse-proxy layer that exposes the gateway to the internet (ADR 008 /
the internet-exposure spec). **This is an overlay on the gateway's compose
stack, not a standalone project** — `docker-compose.edge.yml` (repo root)
reaches into the gateway service (re-binds its port, mounts certs, injects the
uvicorn `--ssl-*` flags), so it only works layered:

```bash
bash infra/edge/gen-certs.sh
docker compose -f docker-compose.quickstart.yml -f docker-compose.edge.yml up -d --build
uv run python scripts/smoke_edge.py     # should print ALL PASS
```

Governed mode: swap the quickstart base for `docker-compose.yml` and see the
runbook (`docs/ops/runbooks/edge-exposure.md` in the docs repo).

## The chain

```
client ──HTTPS+mTLS (client-ca cert)──▶ nginx edge (:8443)
                                            │ inner mTLS (internal-ca certs)
                                            ▼
                                        gateway (TLS, requires internal-ca client cert)
```

Nothing without a client-ca cert gets past nginx; nothing but nginx (holder of
the only internal-ca client cert) can open a gateway connection. The gateway
then independently enforces Entra OAuth + DPoP.

## Files

| File | Role |
|---|---|
| `nginx.conf` | Edge config: TLS 1.3, hard-fail mTLS, CRL enforcement (`ssl_crl`), rate limit keyed on cert serial, SSE-safe proxying, forwards `X-Client-Cert-Serial`/`-DN` for the audit `channel` block |
| `gen-certs.sh` | Generates the throwaway test PKI (below) + the client-CA database + an empty CRL. Re-run to reset everything |
| `revoke-cert.sh` | Revokes a client cert + regenerates `client-ca.crl`; reload nginx to enforce. Half the kill switch (the other half: revoke the Entra app grant) |
| `check-cert-expiry.sh` | Expiry warnings for every cert **and the CRL's nextUpdate** (an expired CRL rejects ALL client certs). Exit 1 inside the warn window — cron it at 30/14/7 days |
| `certs/` | Generated, gitignored. Never commit; regenerate at will |

## The three CAs (test PKI)

| CA | Signs | Trusted by |
|---|---|---|
| `public-ca` | `edge-public` (nginx's public TLS leaf) | Clients (they pin this CA's SPKI hash — `public-ca.pin`) |
| `client-ca` | Customer/agent client certs (`customer-pilot`, …) — issued via the CA database in `client-ca-db/` so they're revocable | nginx (`ssl_client_certificate` + `ssl_crl`) |
| `internal-ca` | `gateway` (its TLS leaf) + `proxy-client` (nginx's client cert for the inner hop) | The gateway (`--ssl-ca-certs`) and nginx (`proxy_ssl_trusted_certificate`) |

In production: `public-ca` is replaced by Let's Encrypt/DigiCert; `client-ca`
by a real private CA (step-ca/SCEP) issuing short-lived per-customer certs;
`internal-ca` stays yours.

## Gateway-side settings this overlay depends on

Defined in `src/mcp_auth_gateway/config.py`, documented in the docs repo's
gateway-configuration guide:

- `GATEWAY_TLS_CERTFILE/KEYFILE/CA_CERTS` + `GATEWAY_TLS_REQUIRE_CLIENT_CERT`
  (the overlay passes the uvicorn `--ssl-*` equivalents to the container)
- `TRUST_EDGE_HEADERS` — records the forwarded cert identity in the audit
  `channel` block; only safe because the mTLS listener means nothing but the
  proxy can reach the gateway
- `DPOP_MODE` / `DPOP_IAT_WINDOW` — sender-constrained tokens (RFC 9449)
- `GATEWAY_EXTERNAL_BASE_URL` — so DPoP `htu` matches the public URL

## Revocation drill

```bash
bash infra/edge/revoke-cert.sh infra/edge/certs/customer-pilot.pem
docker compose -f docker-compose.quickstart.yml -f docker-compose.edge.yml exec edge nginx -s reload
uv run python scripts/smoke_edge.py --revoked customer-pilot --client-cert customer-pilot
# the revoked probe passes (cert rejected); the valid-cert probe now fails —
# re-run gen-certs.sh + restart to reset the test PKI
```
