"""HTTP helpers shared by the proxy, the aggregator and the upstream client."""

from __future__ import annotations

from collections.abc import AsyncIterable

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .config import settings


class BodyTooLarge(Exception):
    """A request or upstream response body exceeded the buffering cap."""

    def __init__(self, cap: int) -> None:
        super().__init__(f"body exceeded {cap}-byte cap")


async def read_capped(chunks: AsyncIterable[bytes], cap: int) -> bytes:
    """Join a streamed body, raising :class:`BodyTooLarge` past ``cap`` bytes (``0``
    disables). Reading chunk by chunk is what bounds memory; the caller closes the
    stream."""
    parts: list[bytes] = []
    total = 0
    async for chunk in chunks:
        total += len(chunk)
        if cap and total > cap:
            raise BodyTooLarge(cap)
        parts.append(chunk)
    return b"".join(parts)


async def read_request_body(request: Request) -> bytes | Response:
    """The request body, or a 413 past ``MAX_UPSTREAM_RESPONSE_BYTES``. Every ``/mcp``
    route reads the body before it authenticates the caller, so this cap is what bounds
    the memory an unauthenticated client can make the gateway hold."""
    try:
        return await read_capped(request.stream(), settings.max_upstream_response_bytes)
    except BodyTooLarge:
        return JSONResponse(
            {
                "error": "request_too_large",
                "detail": "the request body exceeded the configured size cap",
            },
            status_code=413,
        )
