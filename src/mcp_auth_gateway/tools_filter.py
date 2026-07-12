"""Phase 2: ``tools/list`` response filtering.

After RBAC authorizes a request, the gateway hides the tools a caller cannot
invoke from the ``tools/list`` *response* — a user only sees what their groups
permit. This is defense-in-depth on top of the ``tools/call`` RBAC (an unlisted
tool is still hard-denied at call time); the value is that an agent never sees,
plans around, or hallucinates a tool it has no access to.

The filter is **content-type aware**. A Streamable HTTP MCP server may answer
``tools/list`` as a single ``application/json`` body *or* as one or more
``text/event-stream`` (SSE) frames. Both carry the same JSON-RPC envelope; we
parse it, drop disallowed entries from ``result.tools``, and re-serialize in the
original framing.

Filtering is **visibility only** — never a security boundary. If a response
can't be parsed for any reason we return it unchanged rather than break the
stream; the ``tools/call`` RBAC check (``main._enforce``) is what actually stops
an unauthorized invocation.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

# Compact separators so the re-serialized body matches typical MCP wire output
# (no spaces after ``,``/``:``) and stays as small as the original.
_COMPACT = (",", ":")


def is_tools_list_request(body: bytes) -> bool:
    """True if the JSON-RPC request body is (or batches) a ``tools/list`` call."""
    if not body:
        return False
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return False
    entries = doc if isinstance(doc, list) else [doc]
    return any(isinstance(e, dict) and e.get("method") == "tools/list" for e in entries)


def _filter_message(msg: object, allowed: set[str]) -> object:
    """Return ``msg`` with any ``result.tools`` entry not in ``allowed`` removed.

    A non-``tools/list``-result message (an error, a different result shape, a
    notification) is returned untouched. Tool entries without a string ``name``
    are dropped — they can't be invoked, so they shouldn't be advertised.
    """
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
    return json.dumps(out, separators=_COMPACT).encode("utf-8")


def _filter_sse(raw: bytes, allowed: set[str]) -> bytes:
    """Filter an SSE (``text/event-stream``) body, preserving frame structure.

    Per the SSE grammar, events are separated by a blank line and the event data
    is the concatenation of its ``data:`` lines. We rewrite only the data
    payload of frames that carry a ``tools/list`` result, leaving ``event:`` /
    ``id:`` lines — and any frame we can't parse as JSON — exactly as received.
    """
    text = raw.decode("utf-8")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")

    out_frames: list[str] = []
    for frame in normalized.split("\n\n"):
        if not frame.strip():
            continue
        lines = frame.split("\n")
        data_parts = [ln[len("data:"):].lstrip(" ") for ln in lines if ln.startswith("data:")]
        if not data_parts:
            out_frames.append(frame)
            continue
        try:
            msg = json.loads("\n".join(data_parts))
        except ValueError:
            out_frames.append(frame)  # not JSON — leave the frame untouched
            continue

        new_data = json.dumps(_filter_message(msg, allowed), separators=_COMPACT)
        rebuilt: list[str] = []
        data_done = False
        for ln in lines:
            if ln.startswith("data:"):
                if not data_done:  # collapse multi-line data into one rewritten line
                    rebuilt.append(f"data: {new_data}")
                    data_done = True
            else:
                rebuilt.append(ln)
        out_frames.append("\n".join(rebuilt))

    # Each SSE event is terminated by a blank line.
    return ("\n\n".join(out_frames) + "\n\n").encode("utf-8")


def _messages(raw: bytes, content_type: str | None) -> list[object]:
    """Parse a response body into its JSON-RPC messages (JSON object/batch, or
    the data payloads of SSE frames). Unparseable input yields ``[]``."""
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            doc = json.loads(raw)
            return doc if isinstance(doc, list) else [doc]
        if "text/event-stream" in ct:
            text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            out: list[object] = []
            for frame in text.split("\n\n"):
                data_parts = [
                    ln[len("data:"):].lstrip(" ")
                    for ln in frame.split("\n")
                    if ln.startswith("data:")
                ]
                if not data_parts:
                    continue
                try:
                    out.append(json.loads("\n".join(data_parts)))
                except ValueError:
                    continue
            return out
    except (ValueError, TypeError, UnicodeDecodeError):
        pass
    return []


def extract_tools(raw: bytes, content_type: str | None) -> list[dict]:
    """The tool entries carried in a ``tools/list`` response body.

    Observation only (manifest pinning — ``audit.manifest``), never a security
    boundary: best-effort, and any parse failure returns ``[]`` rather than
    interfere with the response."""
    tools: list[dict] = []
    for msg in _messages(raw, content_type):
        if not isinstance(msg, dict):
            continue
        result = msg.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            tools.extend(t for t in result["tools"] if isinstance(t, dict))
    return tools


def filter_tools_list_response(
    raw: bytes, content_type: str | None, allowed: Iterable[str]
) -> bytes:
    """Filter a ``tools/list`` response body down to the caller's ``allowed`` set.

    Dispatches on ``content_type`` (JSON vs SSE). Returns ``raw`` unchanged if the
    type is unrecognized or anything fails to parse — filtering is visibility
    only and must never corrupt the response.
    """
    allowed_set = set(allowed)
    ct = (content_type or "").lower()
    try:
        if "text/event-stream" in ct:
            return _filter_sse(raw, allowed_set)
        if "application/json" in ct:
            return _filter_json(raw, allowed_set)
    except (ValueError, TypeError, UnicodeDecodeError):
        return raw
    return raw
