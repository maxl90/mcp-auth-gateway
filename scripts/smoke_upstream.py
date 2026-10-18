"""Smoke test: a raw MCP client hitting the containerized upstream
directly over Streamable HTTP (no gateway in the path yet).

Confirms the upstream serves Streamable HTTP and a real
MCP client can `initialize`, `tools/list`, and `tools/call` against it.

Usage:
    docker compose up -d --build
    pip install -e ".[demo]"          # pulls the `mcp` SDK
    python scripts/smoke_upstream.py  # or pass a URL: ... <url>
"""

import sys

import anyio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9000/mcp"


async def main() -> None:
    print(f"Connecting to {URL} ...")
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"\ntools/list -> {len(names)} tools:")
            for n in names:
                print(f"  - {n}")

            # One safe read-only call to prove tools/call round-trips.
            print("\ntools/call list_schemas ...")
            result = await session.call_tool("list_schemas", {})
            for block in result.content:
                text = getattr(block, "text", block)
                print(text)

    print("\nOK — upstream reachable over Streamable HTTP.")


if __name__ == "__main__":
    anyio.run(main)
