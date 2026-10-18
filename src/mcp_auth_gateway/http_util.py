"""HTTP helpers shared by the proxy and the upstream client."""

from __future__ import annotations

import httpx


class ResponseTooLarge(Exception):
    """An upstream response body exceeded the buffering cap."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        super().__init__(f"response exceeded {cap}-byte cap")


async def read_capped(response: httpx.Response, cap: int) -> bytes:
    """Read a streamed body, raising :class:`ResponseTooLarge` past ``cap`` bytes (``0``
    disables). The read timeout is per chunk, so this is what bounds memory; the
    caller closes the response."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if cap and total > cap:
            raise ResponseTooLarge(cap)
        chunks.append(chunk)
    return b"".join(chunks)
