#Requires -Version 5.1
<#
.SYNOPSIS
  Idempotently provisions the Entra ID objects the MCP Auth Gateway demo needs:
    - one app registration (device-code enabled, exposes an API scope, emits a
      groups claim, issues v2 access tokens)
    - two security groups (allowed / denied)
    - two cloud-only test users
    - group memberships
  Writes entra-output.json, ../.env.generated, and ../policy.generated.yaml with
  the real tenant / client / group IDs so Phase 1 has concrete config.

.PREREQUISITES
  - Azure CLI installed and `az login` completed.
  - Run against a DEV / PERSONAL tenant only (this creates users and groups).

.USAGE
  az login
  az account set --subscription "MCP_Gateway_Subscription"
  ./provision-entra.ps1

  Safe to re-run: existing objects are reused, not duplicated.
#>
[CmdletBinding()]
param(
  [string]$AppName      = "MCP Auth Gateway (dev)",
  [string]$ScopeName    = "access_as_user",
  [string]$AnalystGroup = "mcp-analysts",
  [string]$DeniedGroup  = "mcp-readonly",
  [string]$AnalystNick  = "mcp-analyst",
  [string]$DeniedNick   = "mcp-readonly-user",
  [string]$OutDir       = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
function Say($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function New-Pass {
  $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%^*-_".ToCharArray()
  -join (1..20 | ForEach-Object { $chars | Get-Random })
}

# --- 0. Preconditions -------------------------------------------------------
Say "Checking az login..."
$acct = az account show -o json 2>$null | ConvertFrom-Json
if (-not $acct) { throw "Not logged in. Run 'az login' (and 'az account set --subscription ...') first." }
$tenantId = $acct.tenantId
Say "Tenant: $tenantId   Subscription: $($acct.name)"

Say "Resolving default verified domain (for test-user UPNs)..."
$domains = az rest --method GET --url 'https://graph.microsoft.com/v1.0/domains?$select=id,isDefault' -o json | ConvertFrom-Json
$domain  = ($domains.value | Where-Object { $_.isDefault }).id
if (-not $domain) { $domain = ($domains.value | Select-Object -First 1).id }
Say "Domain: $domain"

# --- 1. App registration ----------------------------------------------------
Say "Ensuring app registration '$AppName'..."
$apps = az ad app list --filter "displayName eq '$AppName'" -o json | ConvertFrom-Json
if (-not $apps -or $apps.Count -eq 0) {
  az ad app create --display-name $AppName --sign-in-audience AzureADMyOrg --is-fallback-public-client true -o none
  Start-Sleep -Seconds 6   # Graph eventual consistency
  $apps = az ad app list --filter "displayName eq '$AppName'" -o json | ConvertFrom-Json
}
$app      = $apps[0]
$appId    = $app.appId
$appObjId = $app.id
Say "App clientId: $appId"

# --- 2. API scope + groups claim + v2 tokens (Graph PATCH) ------------------
Say "Configuring API scope, groups claim, and v2 access tokens..."
$existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/applications/$appObjId" -o json | ConvertFrom-Json
$scopeId  = $null
if ($existing.api.oauth2PermissionScopes) {
  $match = $existing.api.oauth2PermissionScopes | Where-Object { $_.value -eq $ScopeName } | Select-Object -First 1
  if ($match) { $scopeId = $match.id }   # reuse existing id to stay idempotent
}
if (-not $scopeId) { $scopeId = [guid]::NewGuid().ToString() }

$patch = @{
  identifierUris        = @("api://$appId")
  groupMembershipClaims = "SecurityGroup"
  api = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes = @(@{
      id                      = $scopeId
      value                   = $ScopeName
      type                    = "User"
      isEnabled               = $true
      adminConsentDisplayName = "Access the MCP Auth Gateway as the signed-in user"
      adminConsentDescription = "Allows calling the MCP Auth Gateway on behalf of the signed-in user."
      userConsentDisplayName  = "Access the MCP Auth Gateway"
      userConsentDescription  = "Allow the app to call the MCP Auth Gateway on your behalf."
    })
  }
  optionalClaims = @{
    accessToken = @(@{ name = "groups"; essential = $false; additionalProperties = @() })
  }
} | ConvertTo-Json -Depth 12

$tmp = New-TemporaryFile
Set-Content -Path $tmp -Value $patch -Encoding utf8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$appObjId" --headers "Content-Type=application/json" --body "@$tmp" -o none
Remove-Item $tmp -Force

# --- 3. Security groups -----------------------------------------------------
function Ensure-Group($name){
  $g = az ad group list --filter "displayName eq '$name'" -o json | ConvertFrom-Json
  if (-not $g -or $g.Count -eq 0){
    az ad group create --display-name $name --mail-nickname $name -o none
    Start-Sleep -Seconds 4
    $g = az ad group list --filter "displayName eq '$name'" -o json | ConvertFrom-Json
  }
  return $g[0]
}
Say "Ensuring security groups..."
$gAnalyst = Ensure-Group $AnalystGroup
$gDenied  = Ensure-Group $DeniedGroup

# --- 4. Test users ----------------------------------------------------------
function Ensure-User($nick,$display,$domain){
  $upn  = "$nick@$domain"
  $u    = $null
  try { $u = az ad user show --id $upn -o json 2>$null | ConvertFrom-Json } catch {}
  $pass = $null
  if (-not $u){
    $pass = New-Pass
    az ad user create --display-name $display --user-principal-name $upn --password $pass --force-change-password-next-sign-in false -o none
    Start-Sleep -Seconds 4
    $u = az ad user show --id $upn -o json | ConvertFrom-Json
  }
  return [pscustomobject]@{ user=$u; password=$pass; upn=$upn }
}
Say "Ensuring test users..."
$uAnalyst = Ensure-User $AnalystNick "MCP Analyst (allowed)"   $domain
$uDenied  = Ensure-User $DeniedNick  "MCP Read-only (denied)"  $domain

# --- 5. Group memberships ---------------------------------------------------
function Ensure-Member($groupId,$userId){
  $chk = az ad group member check --group $groupId --member-id $userId -o json | ConvertFrom-Json
  if (-not $chk.value){ az ad group member add --group $groupId --member-id $userId -o none }
}
Say "Ensuring group memberships..."
Ensure-Member $gAnalyst.id $uAnalyst.user.id
Ensure-Member $gDenied.id  $uDenied.user.id

# --- 6. Outputs -------------------------------------------------------------
$summary = [ordered]@{
  tenantId     = $tenantId
  clientId     = $appId
  audience     = $appId                                   # v2 access-token aud = resource appId (GUID)
  resourceUrl  = "api://$appId"                           # Phase 1.5 canonical resource (PRM `resource`)
  apiScope     = "api://$appId/$ScopeName"                # what the demo client requests
  issuer       = "https://login.microsoftonline.com/$tenantId/v2.0"
  jwksUri      = "https://login.microsoftonline.com/$tenantId/discovery/v2.0/keys"
  analystGroup = @{ name=$AnalystGroup; objectId=$gAnalyst.id }
  deniedGroup  = @{ name=$DeniedGroup;  objectId=$gDenied.id }
  analystUser  = @{ upn=$uAnalyst.upn; password=$uAnalyst.password }
  deniedUser   = @{ upn=$uDenied.upn;  password=$uDenied.password }
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $OutDir "entra-output.json") -Encoding utf8

@"
# Generated by infra/provision-entra.ps1 — do NOT commit (contains no secret, but is environment-specific)
GATEWAY_TENANT_ID=$tenantId
GATEWAY_CLIENT_ID=$appId
GATEWAY_AUDIENCE=$appId
GATEWAY_RESOURCE_URL=api://$appId
GATEWAY_ISSUER=https://login.microsoftonline.com/$tenantId/v2.0
GATEWAY_JWKS_URL=https://login.microsoftonline.com/$tenantId/discovery/v2.0/keys
# Local containerized Postgres MCP upstream (Streamable HTTP)
UPSTREAM_MCP_URL=http://localhost:9000/mcp
"@ | Set-Content -Path (Join-Path $OutDir "..\.env.generated") -Encoding utf8

@"
# Generated by infra/provision-entra.ps1 — do NOT commit (environment-specific).
# Maps Entra group objectId -> allowed upstream tools (crystaldba/postgres-mcp).
groups:
  "$($gAnalyst.id)":        # $AnalystGroup (allowed)
    allow:
      - list_schemas
      - list_objects
      - get_object_details
      - explain_query
      - analyze_db_health
      - analyze_workload_indexes
      - analyze_query_indexes
      - get_top_queries
      - execute_sql
  "$($gDenied.id)":         # $DeniedGroup (denied — no tools)
    allow: []
# Phase 2 (step-up) hook — not enforced in Phase 1. execute_sql can run
# destructive statements; Phase 2 will inspect args and require step-up.
destructive:
  - execute_sql
"@ | Set-Content -Path (Join-Path $OutDir "..\policy.generated.yaml") -Encoding utf8

# --- 7. Summary -------------------------------------------------------------
Write-Host ""
Say "DONE. Provisioned Entra objects:"
Write-Host ("  tenantId      : {0}" -f $tenantId)
Write-Host ("  clientId      : {0}" -f $appId)
Write-Host ("  apiScope      : api://{0}/{1}" -f $appId, $ScopeName)
Write-Host ("  analysts grp  : {0}  ({1})" -f $AnalystGroup, $gAnalyst.id)
Write-Host ("  denied   grp  : {0}  ({1})" -f $DeniedGroup,  $gDenied.id)
Write-Host ("  analyst user  : {0}" -f $uAnalyst.upn)
Write-Host ("  denied  user  : {0}" -f $uDenied.upn)
Write-Host ""
Write-Host "Wrote: entra-output.json (incl. generated passwords), ../.env.generated, ../policy.generated.yaml" -ForegroundColor Green
Write-Host "Test-user passwords are in entra-output.json. Keep it out of git." -ForegroundColor Yellow
