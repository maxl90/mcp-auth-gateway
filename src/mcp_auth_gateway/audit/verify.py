"""Verify the hash chain of an audit log.

Each record's ``integrity.record_hash`` must equal the SHA-256 of its content
plus the previous record's hash, and its ``prev_hash`` must equal that previous
hash. An edit, deletion, reordering, or truncation in the middle breaks the
chain at a detectable line.

    mcp-auth-gateway-verify-audit [path]   # exit 0 when intact, else 1 and the first broken line
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
from .log import CorruptRecord, iter_records
from .writer import GENESIS, compute_hash


@dataclass
class VerifyResult:
    ok: bool
    records: int
    broken_line: int | None = None  # 1-indexed line number of the first break
    detail: str | None = None


def verify_file(path: str | Path) -> VerifyResult:
    """Verify the chain in ``path``. An empty/absent file is vacuously intact."""
    p = Path(path)
    if not p.exists():
        return VerifyResult(ok=True, records=0, detail="file does not exist (no records)")

    prev_hash: str | None = None
    count = 0
    try:
        for i, rec in iter_records(p, skip_corrupt=False):
            integrity = rec.get("integrity")
            if not isinstance(integrity, dict):
                return VerifyResult(False, count, i, f"line {i}: missing integrity block")

            stored_hash = integrity.get("record_hash")
            stored_prev = integrity.get("prev_hash")

            # 1. Linkage: this record's prev_hash must match the previous record's hash.
            expected_prev = prev_hash if prev_hash is not None else GENESIS
            if stored_prev != expected_prev:
                return VerifyResult(
                    False,
                    count,
                    i,
                    f"line {i}: prev_hash {stored_prev!r} does not chain to the previous "
                    f"record's hash {expected_prev!r} — a record was inserted, removed, "
                    "or reordered",
                )

            # 2. Integrity: recompute the hash over the content (record minus integrity).
            content = {k: v for k, v in rec.items() if k != "integrity"}
            recomputed = compute_hash(content, stored_prev)
            if recomputed != stored_hash:
                return VerifyResult(
                    False,
                    count,
                    i,
                    f"line {i}: record_hash mismatch — this record was modified after it "
                    "was written",
                )

            prev_hash = stored_hash
            count += 1
    except CorruptRecord as exc:
        return VerifyResult(False, count, exc.lineno, str(exc))

    return VerifyResult(ok=True, records=count, detail="chain intact")


def main() -> None:
    """Console entry point."""
    ap = argparse.ArgumentParser(description="Verify the hash chain of an audit log")
    ap.add_argument("path", nargs="?", default=settings.audit_log_path)
    path = ap.parse_args().path
    result = verify_file(path)
    if result.ok:
        print(f"OK: {result.records} records, chain intact ({path})")
        raise SystemExit(0)
    print(f"TAMPER DETECTED: {result.detail}", file=sys.stderr)
    print(f"  ({result.records} records verified before the break, in {path})", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
