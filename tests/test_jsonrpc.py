"""JSON-RPC body parsing and SSE rewriting shared by the proxy and aggregator."""

from __future__ import annotations

import json

from mcp_auth_gateway import jsonrpc

_SSE = (
    "event: message\r\n"
    'data: {"jsonrpc":"2.0","method":"notifications/progress"}\r\n'
    "\r\n"
    "id: 7\n"
    'data: {"jsonrpc":"2.0",\n'
    'data: "id":1,"result":{"tools":[{"name":"a"}]}}\n'
    "\n"
    ": keep-alive comment\n"
    "\n"
    "data: not json at all\n"
    "\n"
    "   \n"
)


def test_iter_sse_frames_keeps_lines_and_joins_data():
    frames = list(jsonrpc.iter_sse_frames(_SSE))
    assert [f.lines[0] for f in frames] == [
        "event: message",
        "id: 7",
        ": keep-alive comment",
        "data: not json at all",
    ]
    assert frames[0].data == '{"jsonrpc":"2.0","method":"notifications/progress"}'
    assert frames[1].data == '{"jsonrpc":"2.0",\n"id":1,"result":{"tools":[{"name":"a"}]}}'
    assert frames[2].data is None
    assert frames[3].data == "not json at all"


def test_sse_payloads_skips_frames_without_json():
    payloads = jsonrpc.sse_payloads(_SSE)
    assert [p.get("id") for p in payloads] == [None, 1]
    assert payloads[1]["result"]["tools"] == [{"name": "a"}]


def test_parse_messages_json_object_and_batch():
    one = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
    assert jsonrpc.parse_messages(one, "application/json; charset=utf-8") == [
        {"jsonrpc": "2.0", "id": 1, "result": {}}
    ]
    batch = json.dumps([{"id": 1}, {"id": 2}]).encode()
    assert jsonrpc.parse_messages(batch, "application/json") == [{"id": 1}, {"id": 2}]


def test_parse_messages_sse():
    msgs = jsonrpc.parse_messages(_SSE.encode(), "text/event-stream")
    assert len(msgs) == 2 and msgs[1]["id"] == 1


def test_parse_messages_tolerates_garbage():
    assert jsonrpc.parse_messages(b"{not json", "application/json") == []
    assert jsonrpc.parse_messages(b"\xff\xfe", "text/event-stream") == []
    assert jsonrpc.parse_messages(b'{"id":1}', "text/plain") == []
    assert jsonrpc.parse_messages(b'{"id":1}', None) == []


def test_rewrite_sse_data_touches_only_json_data_lines():
    def drop_tools(msg):
        if isinstance(msg, dict) and "result" in msg:
            return {**msg, "result": {"tools": []}}
        return msg

    out = jsonrpc.rewrite_sse_data(_SSE.encode(), drop_tools).decode()
    frames = out.split("\n\n")
    assert out.endswith("\n\n") and frames[-1] == ""
    # Non-data lines survive; multi-line data collapses to one rewritten line.
    assert frames[0].split("\n") == [
        "event: message",
        'data: {"jsonrpc":"2.0","method":"notifications/progress"}',
    ]
    assert frames[1].split("\n") == [
        "id: 7",
        'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}',
    ]
    # Frames without JSON pass through byte-for-byte (CRLF normalized to LF).
    assert frames[2] == ": keep-alive comment"
    assert frames[3] == "data: not json at all"


def test_params_of_tolerates_every_shape():
    assert jsonrpc.params_of({"params": {"name": "t"}}) == {"name": "t"}
    assert jsonrpc.params_of({"params": ["not", "an", "object"]}) == {}
    assert jsonrpc.params_of({"params": None}) == {}
    assert jsonrpc.params_of({}) == {}
    assert jsonrpc.params_of("not a message") == {}
