"""What tools does *this* user see through the gateway?

Device-code login (reusing the demo client's flow), then a single MCP
``tools/list`` through the gateway. The gateway filters the response to the
caller's RBAC, so the printed list is exactly what their Entra groups permit:

  * analyst  -> the full allowed tool set
  * readonly -> an empty list (a 200 with zero tools, not a 403 — the request
                is forwarded and the *response* is filtered)

Run:
  uv run --extra demo python demo/list_tools.py
"""

from __future__ import annotations

import anyio

# Reuse the demo client's env-loading, device-code login, and config so this
# probe stays in lockstep with the real demo (same tenant, scope, gateway URL).
import client  # noqa: E402  (import after the module-level env load in client.py)
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def _list_tools(token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\nListing tools through the gateway at {client.GATEWAY_URL} ...")
    async with streamablehttp_client(client.GATEWAY_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            names = [t.name for t in result.tools]
            print(f"\n✅ Visible tools ({len(names)}):")
            for name in names:
                print("  -", name)
            if not names:
                print(
                    "  (none — this user's groups permit no tools; "
                    "the list was filtered to empty, not blocked)"
                )


def main() -> None:
    token = client._login()
    payload = client._decode_jwt_payload(token)
    print("groups claim:", payload.get("groups"))
    anyio.run(_list_tools, token)


if __name__ == "__main__":
    main()
