"""Verify the tamper-evidence of an audit log.

Walks the hash chain: each record's ``integrity.record_hash`` must equal the
SHA-256 of its content plus the previous record's hash, and its
``integrity.prev_hash`` must equal the previous record's ``record_hash``. Any
edit, deletion, reordering, or truncation in the middle breaks the chain at a
detectable line.

CLI (installed as ``mcp-auth-gateway-verify-audit``)::

    mcp-auth-gateway-verify-audit [path]   # defaults to AUDIT_LOG_PATH / audit.log
    → exit 0 and "OK: N records, chain intact"
    → exit 1 and the first broken line + why
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
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
    for i, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError as exc:
            return VerifyResult(False, count, i, f"line {i}: not valid JSON ({exc})")

        integrity = rec.get("integrity")
        if not isinstance(integrity, dict):
            return VerifyResult(False, count, i, f"line {i}: missing integrity block")

        stored_hash = integrity.get("record_hash")
        stored_prev = integrity.get("prev_hash")

        # 1. Linkage: this record's prev_hash must match the previous record's hash.
        expected_prev = prev_hash if prev_hash is not None else GENESIS
        if stored_prev != expected_prev:
            return VerifyResult(
                False, count, i,
                f"line {i}: prev_hash {stored_prev!r} does not chain to the previous "
                f"record's hash {expected_prev!r} — a record was inserted, removed, or reordered",
            )

        # 2. Integrity: recompute the hash over the content (record minus integrity).
        content = {k: v for k, v in rec.items() if k != "integrity"}
        recomputed = compute_hash(content, stored_prev)
        if recomputed != stored_hash:
            return VerifyResult(
                False, count, i,
                f"line {i}: record_hash mismatch — this record was modified after it was written",
            )

        prev_hash = stored_hash
        count += 1

    return VerifyResult(ok=True, records=count, detail="chain intact")


def main() -> None:
    """Console entry point."""
    path = sys.argv[1] if len(sys.argv) > 1 else settings.audit_log_path
    result = verify_file(path)
    if result.ok:
        print(f"OK: {result.records} records, chain intact ({path})")
        raise SystemExit(0)
    print(f"TAMPER DETECTED: {result.detail}", file=sys.stderr)
    print(f"  ({result.records} records verified before the break, in {path})", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
