# infra — Entra ID provisioning

Automates the cloud identity setup for the MCP Auth Gateway demo. The demo stack
itself (gateway + Postgres upstream) runs **locally in Docker** — only Entra ID
lives in the cloud, and it's free (app registration, security groups, and users
are all in the Entra ID free tier; no Azure resources are deployed).

## Prerequisites

- Azure CLI (`az`) — installed.
- A **dev / personal** Entra tenant (the script creates test users and groups).

## Run

```powershell
az login
az account set --subscription "MCP_Gateway_Subscription"
./provision-entra.ps1
```

The script is **idempotent** — re-running reuses existing objects instead of
duplicating them.

## What it creates

| Object | Name | Purpose |
|---|---|---|
| App registration | `MCP Auth Gateway (dev)` | Device-code login; exposes API scope `access_as_user`; emits a `groups` claim; issues v2 access tokens |
| Security group | `mcp-analysts` | Allowed group (maps to read tools) |
| Security group | `mcp-readonly` | Denied group (no sensitive tools) |
| User | `mcp-analyst@<domain>` | Logs in as the allowed identity |
| User | `mcp-readonly-user@<domain>` | Logs in as the denied identity |

## Outputs

- `entra-output.json` — tenant/client/group IDs **and the generated test-user passwords**. Keep out of git.
- `../.env.generated` — gateway config (tenant, client, audience, issuer, JWKS URL, upstream URL).
- `../policy.generated.yaml` — starter RBAC map (group objectId → allowed tools); tool names are placeholders until the Postgres MCP container is running.

## Notes

- **v2 tokens:** the app is set to `requestedAccessTokenVersion = 2`, so the access-token `aud` is the app's client ID (GUID) and the issuer is `https://login.microsoftonline.com/<tenant>/v2.0`. The generated `.env` matches this.
- **Group claim = GUIDs:** the token carries group **object IDs**, so `policy.yaml` keys on GUIDs (the script fills in the real ones).
- **First device-code login** may show a one-time consent prompt for the `access_as_user` scope — expected.
