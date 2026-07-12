"""Build and verify one-command attestation packs.

An attestation pack is a single ZIP an auditor can independently verify: the
**full** hash-chained audit log (a sliced log can never chain-verify — its
first ``prev_hash`` isn't genesis), framework evidence reports and SIEM exports
computed over a declared time window, the manifest baseline when present, and a
``pack-manifest.json`` listing the SHA-256 of every member plus the chain's
terminal record hash. Integrity needs no keys (sha256 + ``verify-audit``
suffice); authenticity is optional — configure an Ed25519 signing key and the
manifest gets a detached signature.

Evidence tooling only (ADR 007): the pack observes and attests, nothing more.
This is also the Evidence Console's engagement-bundle shape — a pack imports
directly.

CLI (installed as ``mcp-auth-gateway-attestation-pack``)::

    mcp-auth-gateway-attestation-pack [audit_path] [out.zip]
        [--from ISO] [--to ISO] [--framework NAME ...]
        [--baseline PATH] [--signing-key PEM] [--name LABEL]
    mcp-auth-gateway-attestation-pack --verify PACK.zip   # exit 0 ok / 1 fail
    mcp-auth-gateway-attestation-pack --generate-key PATH
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import sys
import zipfile
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

from ..audit.export import flatten_record, flatten_record_ocsf
from ..audit.verify import verify_file
from ..config import settings
from . import signals as signals_mod
from .report import build_bundle_from, render_markdown

PACK_FORMAT = "1"
DEFAULT_FRAMEWORKS = ("nist-ai-rmf", "eu-ai-act", "soc2")

# Members that carry the pack's evidence; pack-manifest.json/.sig describe the
# rest and therefore cannot list themselves.
_MANIFEST_NAME = "pack-manifest.json"
_SIGNATURE_NAME = "pack-manifest.sig"


def _tool_version() -> str:
    try:
        return metadata.version("mcp-auth-gateway")
    except metadata.PackageNotFoundError:  # editable/source runs
        return "unknown"


def _parse_bound(value: str | None, *, end: bool) -> datetime | None:
    """Parse a --from/--to bound. A bare date means start (or end) of that day."""
    if not value:
        return None
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if len(value) == 10 and end:  # date-only upper bound → inclusive whole day
        ts = ts.replace(hour=23, minute=59, second=59, microsecond=999999)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts


def _record_ts(rec: dict) -> datetime | None:
    raw = rec.get("ts")
    if not isinstance(raw, str):
        return None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _window(records: list[dict], lo: datetime | None, hi: datetime | None) -> list[dict]:
    if lo is None and hi is None:
        return records
    out = []
    for rec in records:
        ts = _record_ts(rec)
        if ts is None:
            continue  # un-timestamped records can't be placed in a window
        if (lo is None or ts >= lo) and (hi is None or ts <= hi):
            out.append(rec)
    return out


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- signing ------------------------------------------------------------------


def generate_key(path: str | Path) -> str:
    """Write a new Ed25519 private key PEM; return the public key hex."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    Path(path).write_bytes(pem)
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return pub.hex()


def _load_signer(path: str | Path):
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, pub.hex()


def _verify_signature(manifest_bytes: bytes, signature_b64: str, public_key_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            base64.b64decode(signature_b64), manifest_bytes
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# --- build ---------------------------------------------------------------------


def _verify_md(chain_ok: bool, signed: bool) -> str:
    lines = [
        "# Verifying this attestation pack",
        "",
        "1. **Member integrity** — every file listed in `pack-manifest.json`",
        "   carries its SHA-256. Recompute and compare (`sha256sum`, `Get-FileHash`).",
        "   The manifest cannot list itself; step 3 covers it when signed.",
        "2. **Chain integrity** — `audit.log` is the complete hash-chained log:",
        "   `mcp-auth-gateway-verify-audit audit.log` must report the chain state",
        "   recorded under `chain` in the manifest. Reports/exports cover the",
        "   declared `window`; the log is included in full because a sliced log",
        "   cannot chain-verify (its first prev_hash is not genesis).",
    ]
    if signed:
        lines += [
            "3. **Authenticity** — `pack-manifest.sig` is a detached Ed25519",
            "   signature (base64) over the exact bytes of `pack-manifest.json`,",
            "   by the public key recorded in the manifest's `signature` block.",
            "   Confirm that public key out-of-band with the pack's producer.",
        ]
    else:
        lines += [
            "3. **Authenticity** — this pack is unsigned (integrity only). The",
            "   producer can enable signing with `--signing-key`.",
        ]
    if not chain_ok:
        lines += [
            "",
            "> **NOTE:** the chain was already broken when this pack was built —",
            "> see `chain.detail` in the manifest. The pack faithfully preserves",
            "> that evidence; it does not repair or conceal it.",
        ]
    lines += [
        "",
        "One-command check: `mcp-auth-gateway-attestation-pack --verify <this zip>`",
        "",
    ]
    return "\n".join(lines)


def build_pack(
    audit_path: str | Path,
    out_zip: str | Path,
    *,
    frameworks: tuple[str, ...] = DEFAULT_FRAMEWORKS,
    from_ts: str | None = None,
    to_ts: str | None = None,
    baseline_path: str | Path | None = None,
    signing_key: str | Path | None = None,
    name: str | None = None,
) -> dict:
    """Build the pack; return the manifest that was written into it."""
    audit_path = Path(audit_path)
    lo = _parse_bound(from_ts, end=False)
    hi = _parse_bound(to_ts, end=True)

    chain = verify_file(audit_path)
    records = list(signals_mod.iter_records(audit_path))
    windowed = _window(records, lo, hi)
    terminal_hash = (records[-1].get("integrity") or {}).get("record_hash") if records else None

    # Windowed signals carry the FULL-log chain verdict (see signals.aggregate);
    # an absent log attests nothing, matching signals.compute semantics.
    sig = signals_mod.aggregate(windowed)
    sig.tamper_evident = chain.ok and audit_path.exists()
    sig.chain_detail = chain.detail

    members: dict[str, bytes] = {}
    members["audit.log"] = audit_path.read_bytes() if audit_path.exists() else b""

    baseline = Path(baseline_path) if baseline_path else Path(settings.manifest_baseline_path)
    if baseline.exists():
        members["manifest-baseline.json"] = baseline.read_bytes()

    for fw in frameworks:
        bundle = build_bundle_from(sig, fw, audit_path)
        bundle["coverage"]["window"] = {"from": from_ts, "to": to_ts}
        members[f"evidence-report.{fw}.json"] = json.dumps(bundle, indent=2).encode("utf-8")
        members[f"evidence-report.{fw}.md"] = render_markdown(bundle).encode("utf-8")

    for suffix, mapper in (("sentinel", flatten_record), ("ocsf", flatten_record_ocsf)):
        rows = "\n".join(
            json.dumps(mapper(rec), separators=(",", ":"), ensure_ascii=False)
            for rec in windowed
        )
        members[f"export.{suffix}.jsonl"] = (rows + "\n" if rows else "").encode("utf-8")

    signer = pub_hex = None
    if signing_key:
        signer, pub_hex = _load_signer(signing_key)

    members["VERIFY.md"] = _verify_md(chain.ok, signed=signer is not None).encode("utf-8")

    manifest = {
        "pack_format": PACK_FORMAT,
        "name": name or audit_path.stem,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": {"name": "mcp-auth-gateway-attestation-pack", "version": _tool_version()},
        "source": {"audit_path": str(audit_path), "total_records": len(records)},
        "window": {"from": from_ts, "to": to_ts, "records": len(windowed)},
        "chain": {
            "ok": chain.ok,
            "records": chain.records,
            "detail": chain.detail,
            "terminal_record_hash": terminal_hash,
        },
        "frameworks": list(frameworks),
        "files": [
            {"name": n, "sha256": _sha256(b), "bytes": len(b)} for n, b in sorted(members.items())
        ],
        "signature": {"algorithm": "ed25519", "public_key": pub_hex} if signer else None,
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    out_zip = Path(out_zip)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, data in sorted(members.items()):
            zf.writestr(member_name, data)
        zf.writestr(_MANIFEST_NAME, manifest_bytes)
        if signer:
            signature = base64.b64encode(signer.sign(manifest_bytes)).decode("ascii")
            zf.writestr(_SIGNATURE_NAME, signature)
    return manifest


# --- verify ---------------------------------------------------------------------


def verify_pack(zip_path: str | Path) -> tuple[bool, list[str]]:
    """Re-check a pack: member hashes, the contained chain, and any signature.

    Returns (ok, problems). Verifies against a temp-extracted audit.log so the
    chain check runs the real ``verify_file``.
    """
    import tempfile

    problems: list[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        if _MANIFEST_NAME not in names:
            return False, [f"missing {_MANIFEST_NAME}"]
        manifest_bytes = zf.read(_MANIFEST_NAME)
        try:
            manifest = json.loads(manifest_bytes)
        except ValueError as exc:
            return False, [f"{_MANIFEST_NAME} is not valid JSON ({exc})"]

        listed = {f["name"]: f for f in manifest.get("files", [])}
        for member_name, entry in listed.items():
            if member_name not in names:
                problems.append(f"listed member missing from zip: {member_name}")
                continue
            actual = _sha256(zf.read(member_name))
            if actual != entry.get("sha256"):
                problems.append(f"sha256 mismatch: {member_name}")
        extras = names - set(listed) - {_MANIFEST_NAME, _SIGNATURE_NAME}
        problems.extend(f"unlisted member in zip: {n}" for n in sorted(extras))

        sig_info = manifest.get("signature")
        if sig_info:
            if _SIGNATURE_NAME not in names:
                problems.append("manifest declares a signature but pack-manifest.sig is missing")
            elif not _verify_signature(
                manifest_bytes, zf.read(_SIGNATURE_NAME).decode("ascii"), sig_info["public_key"]
            ):
                problems.append("signature verification FAILED over pack-manifest.json")
        elif _SIGNATURE_NAME in names:
            problems.append("pack-manifest.sig present but manifest declares no signature")

        if "audit.log" in names:
            with tempfile.TemporaryDirectory() as td:
                log = Path(td) / "audit.log"
                log.write_bytes(zf.read("audit.log"))
                chain = verify_file(log)
            declared = manifest.get("chain", {})
            if chain.ok != declared.get("ok") or chain.records != declared.get("records"):
                problems.append(
                    f"chain state differs from manifest: now ok={chain.ok} "
                    f"records={chain.records}, declared ok={declared.get('ok')} "
                    f"records={declared.get('records')}"
                )
        else:
            problems.append("audit.log missing from pack")

    return not problems, problems


# --- CLI -------------------------------------------------------------------------


def main() -> None:
    """Console entry point."""
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser(
        description="Build or verify a signed, time-windowed evidence attestation pack"
    )
    ap.add_argument("audit_path", nargs="?", default=settings.audit_log_path)
    ap.add_argument("out_zip", nargs="?", default=None)
    ap.add_argument("--from", dest="from_ts", default=None, metavar="ISO")
    ap.add_argument("--to", dest="to_ts", default=None, metavar="ISO")
    ap.add_argument(
        "--framework",
        action="append",
        default=None,
        help=f"repeatable; defaults to all built-ins: {', '.join(DEFAULT_FRAMEWORKS)}",
    )
    ap.add_argument("--baseline", default=None, help="manifest-baseline.json to include")
    ap.add_argument("--signing-key", default=None, help="Ed25519 private key PEM (optional)")
    ap.add_argument("--name", default=None, help="pack label (defaults to the log's stem)")
    ap.add_argument("--verify", default=None, metavar="ZIP", help="verify a pack instead")
    ap.add_argument("--generate-key", default=None, metavar="PATH", help="write a new key PEM")
    args = ap.parse_args()

    if args.generate_key:
        pub = generate_key(args.generate_key)
        print(f"wrote Ed25519 private key → {args.generate_key}")
        print(f"public key (record this out-of-band): {pub}")
        raise SystemExit(0)

    if args.verify:
        ok, problems = verify_pack(args.verify)
        if ok:
            print(f"OK: pack verified ({args.verify})")
            raise SystemExit(0)
        print(f"PACK VERIFICATION FAILED: {args.verify}", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        raise SystemExit(1)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = args.out_zip or f"attestation-pack-{stamp}.zip"
    manifest = build_pack(
        args.audit_path,
        out,
        frameworks=tuple(args.framework) if args.framework else DEFAULT_FRAMEWORKS,
        from_ts=args.from_ts,
        to_ts=args.to_ts,
        baseline_path=args.baseline,
        signing_key=args.signing_key,
        name=args.name,
    )
    chain = manifest["chain"]
    state = "intact" if chain["ok"] else f"BROKEN ({chain['detail']})"
    signed = "signed" if manifest["signature"] else "unsigned"
    print(
        f"wrote {out}: {manifest['window']['records']} windowed of "
        f"{manifest['source']['total_records']} records, chain {state}, {signed}"
    )
    raise SystemExit(0)


if __name__ == "__main__":
    main()
