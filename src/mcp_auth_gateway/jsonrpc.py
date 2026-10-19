"""JSON-RPC message framing shared by the proxy and the aggregator.

An MCP server answers a POST either with one ``application/json`` body (a
message or a batch) or with ``text/event-stream`` frames whose ``data:`` lines
carry one message each. These helpers parse both shapes and rewrite SSE
payloads without disturbing the frames around them.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

# Compact separators so a re-serialized body matches typical MCP wire output.
COMPACT = (",", ":")

_DATA_PREFIX = "data:"


@dataclass(frozen=True)
class SseFrame:
    """One SSE event: its lines as received, and the joined ``data:`` payload
    (``None`` when the frame carries no data line)."""

    lines: list[str]
    data: str | None


def iter_sse_frames(text: str) -> Iterator[SseFrame]:
    """Split an SSE body into frames: events separated by a blank line, CRLF and CR
    accepted, whitespace-only frames dropped. A frame's data is its ``data:`` lines joined."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for frame in normalized.split("\n\n"):
        if not frame.strip():
            continue
        lines = frame.split("\n")
        data_parts = [
            ln[len(_DATA_PREFIX) :].lstrip(" ") for ln in lines if ln.startswith(_DATA_PREFIX)
        ]
        yield SseFrame(lines, "\n".join(data_parts) if data_parts else None)


def sse_payloads(text: str) -> list[object]:
    """The JSON payload of every SSE frame that carries one. A frame whose data
    is not JSON is skipped."""
    out: list[object] = []
    for frame in iter_sse_frames(text):
        if frame.data is None:
            continue
        try:
            out.append(json.loads(frame.data))
        except ValueError:
            continue
    return out


def parse_messages(raw: bytes, content_type: str | None) -> list[object]:
    """The JSON-RPC messages in a response body: a JSON object or batch, or the
    data payloads of SSE frames. Unparseable input and unknown content types
    yield ``[]``."""
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            doc = json.loads(raw)
            return doc if isinstance(doc, list) else [doc]
        if "text/event-stream" in ct:
            return sse_payloads(raw.decode("utf-8"))
    except ValueError:  # includes UnicodeDecodeError
        pass
    return []


def params_of(message: object) -> dict[str, Any]:
    """The ``params`` object of a JSON-RPC message, or ``{}`` when absent or not an object."""
    params = message.get("params") if isinstance(message, dict) else None
    return params if isinstance(params, dict) else {}


def rewrite_sse_data(raw: bytes, rewrite: Callable[[object], object]) -> bytes:
    """Apply ``rewrite`` to each frame's JSON payload, keeping ``event:``/``id:`` lines as
    received. Frames without JSON data pass through; multi-line data collapses to one line."""
    out_frames: list[str] = []
    for frame in iter_sse_frames(raw.decode("utf-8")):
        if frame.data is None:
            out_frames.append("\n".join(frame.lines))
            continue
        try:
            msg = json.loads(frame.data)
        except ValueError:
            out_frames.append("\n".join(frame.lines))
            continue
        new_data = json.dumps(rewrite(msg), separators=COMPACT)
        rebuilt: list[str] = []
        data_done = False
        for ln in frame.lines:
            if not ln.startswith(_DATA_PREFIX):
                rebuilt.append(ln)
            elif not data_done:
                rebuilt.append(f"{_DATA_PREFIX} {new_data}")
                data_done = True
        out_frames.append("\n".join(rebuilt))
    return ("\n\n".join(out_frames) + "\n\n").encode("utf-8")
