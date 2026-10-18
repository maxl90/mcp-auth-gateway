"""Integration test: the upstream MCP server serves concurrent, isolated sessions.

Unlike the rest of the suite (respx-mocked, in-process), this drives a LIVE
upstream to verify a property that can't be mocked — that mcp-proxy + the stdio
MCP server handle many sessions *in parallel* without cross-talk. It underwrites
the multi-user story.

It SKIPS when no upstream is reachable, so `pytest` stays green with the stack
down. Targets the demo Postgres upstream (uses `execute_sql` / `pg_sleep`).

    docker compose up -d                 # bring the stack up, then run pytest
    UPSTREAM_PROBE_URL=http://h:p/mcp    # point elsewhere
"""

from __future__ import annotations

import asyncio
import os
import time

import httpx
import pytest

UPSTREAM = os.environ.get("UPSTREAM_PROBE_URL", "http://localhost:9000/mcp")
_H = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _run(coro):
    return asyncio.run(coro)


async def _open_session(client: httpx.AsyncClient) -> str:
    r = await client.post(
        UPSTREAM,
        headers=_H,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "0"},
            },
        },
    )
    r.raise_for_status()
    sid = r.headers["mcp-session-id"]
    await client.post(
        UPSTREAM,
        headers={**_H, "mcp-session-id": sid},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return sid


async def _sql(client: httpx.AsyncClient, sid: str | None, sql: str, rid: int) -> httpx.Response:
    headers = dict(_H)
    if sid:
        headers["mcp-session-id"] = sid
    return await client.post(
        UPSTREAM,
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": "execute_sql", "arguments": {"sql": sql}},
        },
    )


@pytest.fixture(scope="module")
def live_upstream() -> str:
    async def reachable() -> bool:
        try:
            async with httpx.AsyncClient(timeout=2) as c:
                await _open_session(c)
            return True
        except (httpx.HTTPError, KeyError):
            return False

    if not _run(reachable()):
        pytest.skip(f"no live MCP upstream at {UPSTREAM} (start it: docker compose up -d)")
    return UPSTREAM


def test_concurrent_sessions_are_isolated(live_upstream):
    """Two clients get distinct sessions; concurrent calls don't cross-contaminate."""

    async def go():
        async with httpx.AsyncClient(timeout=30) as c:
            a, b = await _open_session(c), await _open_session(c)
            assert a != b, "each client must get its own session id"
            ra, rb = await asyncio.gather(
                _sql(c, a, "SELECT 'MARKER_AAA' AS who", 10),
                _sql(c, b, "SELECT 'MARKER_BBB' AS who", 11),
            )
            assert "MARKER_AAA" in ra.text and "MARKER_BBB" not in ra.text
            assert "MARKER_BBB" in rb.text and "MARKER_AAA" not in rb.text

    _run(go())


def test_concurrent_sessions_run_in_parallel(live_upstream):
    """4 concurrent 1s sleeps finish well under the ~4s they'd take if serialized."""

    async def go():
        async with httpx.AsyncClient(timeout=30) as c:
            a, b = await _open_session(c), await _open_session(c)
            sids = [a, b, a, b]
            t0 = time.perf_counter()
            results = await asyncio.gather(
                *[_sql(c, s, "SELECT pg_sleep(1)", 20 + i) for i, s in enumerate(sids)]
            )
            elapsed = time.perf_counter() - t0
            assert all(r.status_code == 200 for r in results)
            assert elapsed < 3.0, (
                f"4 concurrent 1s sleeps took {elapsed:.2f}s — upstream appears to "
                "serialize sessions (expected ~1s parallel, ~4s serialized)"
            )

    _run(go())


def test_session_id_is_enforced(live_upstream):
    """A bogus or missing session id is rejected, not silently accepted."""

    async def go():
        async with httpx.AsyncClient(timeout=10) as c:
            bogus = await _sql(c, "0" * 32, "SELECT 1", 30)
            missing = await _sql(c, None, "SELECT 1", 31)
            assert bogus.status_code >= 400, "bogus session id should be rejected"
            assert missing.status_code >= 400, "missing session id should be rejected"

    _run(go())
