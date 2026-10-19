"""The aggregator's client side: every way an upstream can answer badly is an
``UpstreamError`` naming what went wrong, never a crash or a silent success."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from mcp_auth_gateway.aggregator import upstream_client
from mcp_auth_gateway.aggregator.registry import UpstreamSession
from mcp_auth_gateway.aggregator.upstream_client import UpstreamError, UpstreamRequest
from mcp_auth_gateway.upstreams import Upstream

from .conftest import PG_URL
from .fakes import CutOffStream

PG = Upstream("postgres", PG_URL)


def _failure(call) -> str:
    """The detail of the UpstreamError that ``call(client)`` raises."""

    async def go() -> str:
        async with httpx.AsyncClient() as client:
            with pytest.raises(UpstreamError) as info:
                await call(client)
            return info.value.detail

    return asyncio.run(go())


def _tools_list(client: httpx.AsyncClient):
    return upstream_client.rpc(UpstreamRequest(client, PG, UpstreamSession("s1")), "tools/list")


@pytest.mark.parametrize(
    ("answer", "detail"),
    [
        (httpx.Response(500), "HTTP 500 on tools/list"),
        (
            httpx.Response(200, text="hello", headers={"content-type": "text/plain"}),
            "unexpected content-type: 'text/plain'",
        ),
        (
            httpx.Response(200, text="{", headers={"content-type": "application/json"}),
            "unparseable response body, or no message in it",
        ),
        (
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 99, "result": {}}),
            "the response in the body answers a different request",
        ),
        (
            httpx.Response(
                200, headers={"content-type": "application/json"}, stream=CutOffStream()
            ),
            "transport failure while reading",
        ),
    ],
)
def test_a_bad_answer_to_an_rpc_is_an_upstream_error(answer, detail):
    with respx.mock:
        respx.post(PG_URL).mock(return_value=answer)
        assert detail in _failure(_tools_list)


def test_an_rpc_before_initialize_is_refused():
    def before_initialize(client):
        return upstream_client.rpc(UpstreamRequest(client, PG), "tools/list")

    assert _failure(before_initialize) == "tools/list before initialize"


def _handshake(initialize: httpx.Response, initialized: httpx.Response):
    def respond(request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content)["method"]
        return initialize if method == "initialize" else initialized

    return respond


_INITIALIZED = {"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18"}}


@pytest.mark.parametrize(
    ("initialize", "initialized", "detail"),
    [
        (httpx.Response(503), httpx.Response(202), "HTTP 503 on initialize"),
        (
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 0, "error": {"code": -1}}),
            httpx.Response(202),
            "initialize error: {'code': -1}",
        ),
        (
            httpx.Response(200, json=_INITIALIZED),
            httpx.Response(400),
            "HTTP 400 on notifications/initialized",
        ),
    ],
)
def test_a_failed_handshake_is_an_upstream_error(initialize, initialized, detail):
    with respx.mock:
        respx.post(PG_URL).mock(side_effect=_handshake(initialize, initialized))
        assert _failure(lambda client: upstream_client.initialize_session(client, PG)) == detail


def test_a_session_the_upstream_never_issued_is_not_deleted():
    async def go() -> None:
        async with httpx.AsyncClient() as client:
            await upstream_client.delete_session(client, PG, UpstreamSession(None))

    with respx.mock:
        route = respx.delete(PG_URL)
        asyncio.run(go())
    assert not route.called
