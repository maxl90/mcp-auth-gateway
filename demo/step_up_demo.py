"""Step-up round trip: the "destructive call → MFA → proceeds" beat.

Demonstrates the full RFC 9470 loop end to end:

  1. Call a *destructive* tool with an ordinary token.
  2. The gateway answers 401 `insufficient_user_authentication` with an
     `acr_values`/`max_age` challenge — the call is NEVER forwarded.
  3. This client reads the challenge, re-authenticates to **Entra** requesting
     that authentication context (a fresh, stronger sign-in — the second factor
     happens between the client and Entra, off the gateway's data path).
  4. It retries the same call with the stepped-up token; the gateway sees the
     satisfied `acrs` claim and forwards it.

The token and the SQL arguments never leave the gateway in any step — the
trust boundary holds through the whole round-trip.

Uses a raw httpx POST (not the MCP SDK) so the 401 challenge and its
`WWW-Authenticate` header are directly observable.

  uv run --extra demo python demo/step_up_demo.py

PREREQUISITE: an Entra authentication context (e.g. `c1`)
bound to a Conditional Access policy in the tenant. Until that exists this
prints the challenge and the re-auth attempt, but Entra won't mint the `acrs`
claim, so step 4 will re-challenge rather than succeed. The gateway half is
fully exercised regardless.
"""

from __future__ import annotations

import contextlib
import uuid

import client  # reuse env-loading, login, config
import httpx

# A destructive tool per the demo policy — the gateway requires step-up for it.
DESTRUCTIVE_TOOL = "execute_sql"
DESTRUCTIVE_ARGS = {"sql": "DELETE FROM patients WHERE mrn = '12345'"}


def _tools_call(token: str) -> httpx.Response:
    return httpx.post(
        client.GATEWAY_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": "tools/call",
            "params": {"name": DESTRUCTIVE_TOOL, "arguments": DESTRUCTIVE_ARGS},
        },
    )


def _parse_challenge(resp: httpx.Response) -> dict:
    """Pull acr_values/max_age from the JSON-RPC error object."""
    with contextlib.suppress(Exception):
        data = resp.json()["error"]["data"]
        if data.get("error") == "insufficient_user_authentication":
            return {"acr": data["acr_values"], "max_age": data.get("max_age")}
    return {}


def main() -> None:
    token = client._login()

    print(f"\n[1] Calling destructive tool '{DESTRUCTIVE_TOOL}' with an ordinary token ...")
    resp = _tools_call(token)
    print(f"    → HTTP {resp.status_code}")
    print(f"    WWW-Authenticate: {resp.headers.get('www-authenticate')}")

    if resp.status_code != 401:
        print(
            "    (Expected a 401 step-up challenge. Is the tool marked destructive "
            "in the policy? Did the token already carry the context?)"
        )
        return

    challenge = _parse_challenge(resp)
    if not challenge:
        print("    Could not parse the step-up challenge; aborting.")
        return
    print(
        f"\n[2] Gateway demanded step-up: acr={challenge['acr']} "
        f"max_age={challenge['max_age']}s — call was NOT forwarded."
    )

    print("\n[3] Re-authenticating to Entra for that authentication context ...")
    stepped = client._login(claims_challenge=client.build_claims_challenge(challenge["acr"]))
    stepped_claims = client._decode_jwt_payload(stepped)
    print(f"    new token acrs claim: {stepped_claims.get('acrs')}")

    print("\n[4] Retrying the same destructive call with the stepped-up token ...")
    retry = _tools_call(stepped)
    print(f"    → HTTP {retry.status_code}")
    if retry.status_code == 200:
        print("    ✅ Forwarded — step-up satisfied; the gateway let it through.")
    else:
        print(
            "    ⛔ Still challenged. Expected until the Entra auth context + "
            "Conditional Access policy exist in the tenant."
        )


if __name__ == "__main__":
    main()
