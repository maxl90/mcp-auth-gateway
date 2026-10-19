"""Reading the JSONL audit log."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def as_object(value: object) -> dict[str, Any]:
    """``value`` if it is a JSON object, else ``{}``. Readers take a record's nested
    fields through this, so a field of another type reads as absent; a record can
    chain-verify without having the writer's shape."""
    return value if isinstance(value, dict) else {}


class CorruptRecord(ValueError):
    """A line of the audit log is not a JSON object."""

    def __init__(self, lineno: int, problem: str) -> None:
        self.lineno = lineno
        super().__init__(f"line {lineno}: {problem}")


def iter_records(
    path: str | Path, *, skip_corrupt: bool = True
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(line number, record)`` per non-blank line of the log; nothing for an absent file.

    A line that is not a JSON object is skipped, or raises :class:`CorruptRecord` with
    its number when ``skip_corrupt`` is false (the verifier reports the first bad line).
    """
    p = Path(path)
    if not p.exists():
        return
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError as exc:
            if skip_corrupt:
                continue
            raise CorruptRecord(lineno, f"not valid JSON ({exc})") from exc
        if not isinstance(rec, dict):
            if skip_corrupt:
                continue
            raise CorruptRecord(lineno, "not a JSON object")
        yield lineno, rec
