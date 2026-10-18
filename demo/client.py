"""Demo client — Entra ID device-code login, then a real call through the gateway.

Run it twice for the 90-second demo:
  * sign in as the **analyst** user  -> the SELECT succeeds (real rows)
  * sign in as the **readonly** user -> the same call is rejected (403)

Both runs authenticate the same way; the gateway decides allow/deny from the
token's Entra group claim and writes an audit line either way. The token and the
query arguments never leave the gateway — only redacted audit metadata could.

Sign-in is cached (encrypted at rest where the OS supports it — DPAPI on
Windows), so you authenticate once and later runs refresh silently; the
device-code prompt only appears when there's no usable cached/refreshable token.

Config (from environment or .env.generated):
  GATEWAY_TENANT_ID, GATEWAY_CLIENT_ID   (+ optional GATEWAY_SCOPE)
  GATEWAY_URL          (default http://localhost:8080/mcp — the gateway, not the upstream)
  GATEWAY_LOGIN_HINT   (optional UPN — pick which cached user to reuse when several
                        are cached, e.g. switching analyst <-> readonly)
  GATEWAY_TOKEN_CACHE  (optional cache path; default <repo>/.msal_token_cache.bin, gitignored)

Run:
  uv run --extra demo python demo/client.py
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import sys
from pathlib import Path

import anyio
import msal
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from msal_extensions import (
    FilePersistence,
    PersistedTokenCache,
    build_encrypted_persistence,
)

# Print UTF-8 regardless of the host console codepage. On Windows the default
# cp1252 console can't encode the ✅/⛔ status glyphs below and would raise
# UnicodeEncodeError *after* the call already succeeded — making a passing run
# look failed. reconfigure() is a no-op where stdout is already UTF-8.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8")


def _load_env_files() -> None:
    """Load .env.generated (then .env) so `uv run python demo/client.py` works
    without the caller exporting GATEWAY_* by hand. Existing env vars win."""
    root = Path(__file__).resolve().parent.parent
    for name in (".env.generated", ".env"):
        path = root / name
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


_load_env_files()

TENANT = os.environ["GATEWAY_TENANT_ID"]
CLIENT = os.environ["GATEWAY_CLIENT_ID"]
SCOPE = os.environ.get("GATEWAY_SCOPE", f"api://{CLIENT}/access_as_user")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080/mcp")
LOGIN_HINT = os.environ.get("GATEWAY_LOGIN_HINT")  # optional UPN to target a cached user
TOKEN_CACHE_PATH = os.environ.get(
    "GATEWAY_TOKEN_CACHE",
    str(Path(__file__).resolve().parent.parent / ".msal_token_cache.bin"),
)

# A read against PII-shaped columns — the point of the demo is that the gateway
# audits *that this ran*, by whom, without ever recording the arguments or rows.
DEMO_TOOL = "execute_sql"
DEMO_ARGS = {"sql": "SELECT mrn, last_name, diagnosis FROM patients LIMIT 5"}


def _decode_jwt_payload(token: str) -> dict:
    """Decode (without verifying) the payload of a JWT for inspection only."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # pad base64url
    return json.loads(base64.urlsafe_b64decode(payload))


def _build_token_cache() -> PersistedTokenCache:
    """A persisted MSAL cache so a sign-in survives across runs. Encrypted at rest
    via the OS keystore (DPAPI on Windows) where available; degrades to a plaintext
    file otherwise (e.g. headless Linux), with a warning."""
    try:
        persistence = build_encrypted_persistence(TOKEN_CACHE_PATH)
    except Exception:  # noqa: BLE001 — no OS keystore available; degrade rather than fail
        print("  (token cache not OS-encrypted here — falling back to a plaintext file)")
        persistence = FilePersistence(TOKEN_CACHE_PATH)
    return PersistedTokenCache(persistence)


def build_claims_challenge(acr: str) -> str:
    """The Entra claims-challenge JSON that requests an authentication context.

    Passed to MSAL as ``claims_challenge``. It asks
    Entra to return a token whose ``acrs`` contains ``acr``, which Entra will
    only issue after the Conditional Access policy bound to that context (MFA /
    phishing-resistant / compliant device) is satisfied. This is the client
    half of the RFC 9470 round-trip; the gateway issued the challenge.
    """
    return json.dumps({"access_token": {"acrs": {"essential": True, "value": acr}}})


def _login(claims_challenge: str | None = None) -> str:
    """Return an Entra access token, reusing a cached or silently-refreshed one
    when possible and only prompting for a device-code login when necessary.

    ``claims_challenge`` (step-up): when set, a satisfied context is required, so
    the cache can't shortcut it — force a fresh interactive login carrying the
    challenge so Entra enforces the Conditional Access policy."""
    app = msal.PublicClientApplication(
        CLIENT,
        authority=f"https://login.microsoftonline.com/{TENANT}",
        token_cache=_build_token_cache(),
    )

    # 1. Silent: use a cached access token, or exchange a cached refresh token —
    #    no user interaction. A login hint targets one specific user; without a hint
    #    we only reuse a cache holding a single account, so we never guess identity
    #    (important for the analyst <-> readonly switch). Skipped for a step-up:
    #    a stronger auth can't be served from an ordinary cached token.
    accounts = app.get_accounts(username=LOGIN_HINT) if LOGIN_HINT else app.get_accounts()
    result = None
    if not claims_challenge and accounts and (LOGIN_HINT or len(accounts) == 1):
        result = app.acquire_token_silent([SCOPE], account=accounts[0])
        if result and "access_token" in result:
            print(f"Reused cached sign-in for: {accounts[0].get('username')} (no login needed)")

    # 2. Interactive device-code flow when silent didn't yield a token — carrying
    #    the claims challenge on a step-up so Entra prompts for the required context.
    if not result or "access_token" not in result:
        flow = app.initiate_device_flow(scopes=[SCOPE], claims_challenge=claims_challenge)
        if "user_code" not in flow:
            print("Failed to start device flow:\n" + json.dumps(flow, indent=2))
            sys.exit(1)
        print(flow["message"], flush=True)  # "To sign in, open ... and enter code ..."
        result = app.acquire_token_by_device_flow(flow)  # blocks until login completes

    if "access_token" not in result:
        print(f"\nToken error: {result.get('error')} — {result.get('error_description')}")
        sys.exit(1)

    claims = _decode_jwt_payload(result["access_token"])
    who = claims.get("preferred_username") or claims.get("name") or "<unknown>"
    print(f"\nSigned in as: {who}")
    print(f"groups claim: {claims.get('groups')}")
    return result["access_token"]


async def _call_through_gateway(token: str) -> None:
    """Call the demo tool through the gateway with the bearer token."""
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\nCalling {DEMO_TOOL} through the gateway at {GATEWAY_URL} ...")
    try:
        async with streamablehttp_client(GATEWAY_URL, headers=headers) as (read, write, _):  # noqa: SIM117 — inner cm depends on outer's unpacked values
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(DEMO_TOOL, DEMO_ARGS)
                print("\n✅ ALLOWED — real result from upstream:")
                for block in result.content:
                    print("  ", getattr(block, "text", block))
    except Exception as exc:  # noqa: BLE001 — demo: any failure means "rejected"
        print("\n⛔ REJECTED by the gateway — request never reached the database.")
        print(f"   ({type(exc).__name__}: {exc})")

    print("\nNow check the gateway's audit log: one structured line, arguments redacted.")


def main() -> None:
    token = _login()
    anyio.run(_call_through_gateway, token)


if __name__ == "__main__":
    main()
