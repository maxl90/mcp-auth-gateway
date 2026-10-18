"""Reading the JSONL audit log."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path


class CorruptRecord(ValueError):
    """A line of the audit log is not valid JSON."""

    def __init__(self, lineno: int, cause: ValueError) -> None:
        self.lineno = lineno
        self.cause = cause
        super().__init__(f"line {lineno}: not valid JSON ({cause})")


def iter_records(path: str | Path, *, skip_corrupt: bool = True) -> Iterator[tuple[int, dict]]:
    """Yield ``(line number, record)`` per non-blank line of the log; nothing for an absent file.

    A line that is not JSON is skipped, or raises :class:`CorruptRecord` with its
    number when ``skip_corrupt`` is false (the verifier reports the first bad line).
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
            raise CorruptRecord(lineno, exc) from exc
        yield lineno, rec
