"""Fake upstream MCP servers for respx routes."""

from __future__ import annotations

import json

import httpx


class CutOffStream(httpx.AsyncByteStream):
    """A response body the peer drops partway through."""

    async def __aiter__(self):
        yield b'{"jsonrpc":"2.0","id":1,"result":{"tools":['
        raise httpx.RemoteProtocolError("peer closed connection mid-body")


def fake_upstream(name: str, tools: list[str], session_id: str, *, sse: bool = False):
    """A minimal Streamable HTTP MCP server as a respx side-effect."""

    def responder(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in {k.lower() for k in request.headers}, (
            "trust boundary violated: caller token reached an upstream"
        )
        if request.method == "DELETE":
            return httpx.Response(204)
        msg = json.loads(request.content)
        method = msg.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": name, "version": "1.0"},
                    },
                },
                headers={"mcp-session-id": session_id},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)

        assert request.headers.get("mcp-session-id") == session_id, (
            f"request to {name} without its upstream session id"
        )
        if method == "tools/list":
            payload = {
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {
                    "tools": [
                        {"name": t, "description": f"{name} tool", "inputSchema": {}} for t in tools
                    ]
                },
            }
            if sse:  # mcp-proxy answers POSTs as SSE — exercise that parse path
                body = f"event: message\ndata: {json.dumps(payload)}\n\n"
                return httpx.Response(
                    200, content=body.encode(), headers={"content-type": "text/event-stream"}
                )
            return httpx.Response(200, json=payload)
        if method == "tools/call":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "content": [{"type": "text", "text": f"{name} ran {msg['params']['name']}"}]
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32601, "message": f"unhandled: {method}"},
            },
        )

    return responder
