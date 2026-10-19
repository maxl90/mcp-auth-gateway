"""``tools/list`` response filtering: a caller sees only the tools they may invoke.

Defense in depth on top of the ``tools/call`` RBAC (an unlisted tool is still
denied at call time): an agent never sees, plans around, or invents a tool it
cannot use. The filter is content-type aware (JSON body or SSE frames) and
rewrites ``result.tools`` in the original framing. It is visibility only, never
a security boundary: anything it cannot parse is returned unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from . import jsonrpc


def is_tools_list_request(body: bytes) -> bool:
    """True if the JSON-RPC request body is (or batches) a ``tools/list`` call."""
    if not body:
        return False
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    entries = doc if isinstance(doc, list) else [doc]
    return any(isinstance(e, dict) and e.get("method") == "tools/list" for e in entries)


def _filter_message(msg: object, allowed: set[str]) -> object:
    """``msg`` with ``result.tools`` entries outside ``allowed`` removed; other messages
    untouched. Entries without a string ``name`` are dropped: they cannot be invoked."""
    if not isinstance(msg, dict):
        return msg
    result = msg.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return msg
    kept = [
        tool
        for tool in result["tools"]
        if isinstance(tool, dict) and isinstance(tool.get("name"), str) and tool["name"] in allowed
    ]
    return {**msg, "result": {**result, "tools": kept}}


def _filter_json(raw: bytes, allowed: set[str]) -> bytes:
    """Filter a single ``application/json`` JSON-RPC body (object or batch)."""
    doc = json.loads(raw)
    if isinstance(doc, list):
        out: object = [_filter_message(m, allowed) for m in doc]
    else:
        out = _filter_message(doc, allowed)
    return json.dumps(out, separators=jsonrpc.COMPACT).encode("utf-8")


def _filter_sse(raw: bytes, allowed: set[str]) -> bytes:
    """Filter an SSE body, preserving frame structure; only JSON ``data:`` payloads
    carrying a ``tools/list`` result are rewritten."""
    return jsonrpc.rewrite_sse_data(raw, lambda msg: _filter_message(msg, allowed))


def extract_tools(raw: bytes, content_type: str | None) -> list[dict[str, Any]]:
    """The tool entries in a ``tools/list`` response body. Observation only (manifest
    pinning), never a boundary: a parse failure yields ``[]``."""
    tools: list[dict[str, Any]] = []
    for msg in jsonrpc.parse_messages(raw, content_type):
        if not isinstance(msg, dict):
            continue
        result = msg.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            tools.extend(t for t in result["tools"] if isinstance(t, dict))
    return tools


def filter_tools_list_response(
    raw: bytes, content_type: str | None, allowed: Iterable[str]
) -> bytes:
    """Filter a ``tools/list`` response body down to ``allowed``.

    Dispatches on content type (JSON or SSE); an unrecognized type or a parse
    failure returns ``raw`` unchanged, since filtering is visibility only.
    """
    allowed_set = set(allowed)
    ct = (content_type or "").lower()
    try:
        if "text/event-stream" in ct:
            return _filter_sse(raw, allowed_set)
        if "application/json" in ct:
            return _filter_json(raw, allowed_set)
    except ValueError:  # includes UnicodeDecodeError
        return raw
    return raw
