"""Build and verify attestation packs.

A pack is one ZIP an auditor can verify on their own: the full hash-chained audit
log (a slice can never chain-verify), framework reports and SIEM exports over a
declared window, the manifest baseline when present, and ``pack-manifest.json``
with every member's SHA-256 and the chain's terminal hash. Integrity needs no
keys; an optional Ed25519 signing key adds a detached signature over the manifest.

    mcp-auth-gateway-attestation-pack [audit_path] [out.zip] [--from ISO] [--to ISO]
        [--framework NAME ...] [--baseline PATH] [--signing-key PEM] [--name LABEL]
    mcp-auth-gateway-attestation-pack --verify PACK.zip [--public-key HEX]   # exit 0 / 1
    mcp-auth-gateway-attestation-pack --generate-key PATH
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..audit.export import flatten_record, flatten_record_ocsf
from ..audit.log import iter_records
from ..audit.verify import VerifyResult, verify_file
from ..config import settings
from . import signals as signals_mod
from .report import build_bundle_from, render_markdown

PACK_FORMAT = "1"
DEFAULT_FRAMEWORKS = ("nist-ai-rmf", "eu-ai-act", "soc2")

# Members that carry the pack's evidence; pack-manifest.json/.sig describe the
# rest and therefore cannot list themselves.
_MANIFEST_NAME = "pack-manifest.json"
_SIGNATURE_NAME = "pack-manifest.sig"


@dataclass(frozen=True)
class PackOptions:
    """What goes into a pack besides the log: the frameworks to report on, the time
    window, an optional baseline file and signing key, and a label."""

    frameworks: tuple[str, ...] = DEFAULT_FRAMEWORKS
    from_ts: str | None = None
    to_ts: str | None = None
    baseline_path: str | Path | None = None
    signing_key: str | Path | None = None
    name: str | None = None


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
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub.hex()


def _load_signer(path: str | Path):
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
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
            "   Confirm that public key out-of-band with the pack's producer, then pin",
            "   it: `mcp-auth-gateway-attestation-pack --verify <zip> --public-key HEX`.",
            "   Without the pin the check uses the embedded key and is self-attesting.",
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


@dataclass(frozen=True)
class _LogSnapshot:
    """The audit log as read once for a pack: its chain verdict, every record, and
    the records inside the requested window."""

    path: Path
    chain: VerifyResult
    records: list[dict]
    windowed: list[dict]

    @property
    def terminal_hash(self) -> str | None:
        if not self.records:
            return None
        return (self.records[-1].get("integrity") or {}).get("record_hash")


def _snapshot(audit_path: Path, options: PackOptions) -> _LogSnapshot:
    records = [rec for _, rec in iter_records(audit_path)]
    lo = _parse_bound(options.from_ts, end=False)
    hi = _parse_bound(options.to_ts, end=True)
    return _LogSnapshot(audit_path, verify_file(audit_path), records, _window(records, lo, hi))


def _collect_members(snap: _LogSnapshot, options: PackOptions, *, signed: bool) -> dict[str, bytes]:
    """The evidence files: the full log, the baseline when present, one report pair
    per framework, the two SIEM exports, and VERIFY.md."""
    # Windowed signals carry the FULL-log chain verdict (see signals.aggregate);
    # an absent log attests nothing, matching signals.compute semantics.
    sig = signals_mod.aggregate(snap.windowed)
    sig.tamper_evident = snap.chain.ok and snap.path.exists()
    sig.chain_detail = snap.chain.detail

    members: dict[str, bytes] = {}
    members["audit.log"] = snap.path.read_bytes() if snap.path.exists() else b""

    baseline = Path(options.baseline_path or settings.manifest_baseline_path)
    if baseline.exists():
        members["manifest-baseline.json"] = baseline.read_bytes()

    for fw in options.frameworks:
        bundle = build_bundle_from(sig, fw, snap.path)
        bundle["coverage"]["window"] = {"from": options.from_ts, "to": options.to_ts}
        members[f"evidence-report.{fw}.json"] = json.dumps(bundle, indent=2).encode("utf-8")
        members[f"evidence-report.{fw}.md"] = render_markdown(bundle).encode("utf-8")

    for suffix, mapper in (("sentinel", flatten_record), ("ocsf", flatten_record_ocsf)):
        rows = "\n".join(
            json.dumps(mapper(rec), separators=(",", ":"), ensure_ascii=False)
            for rec in snap.windowed
        )
        members[f"export.{suffix}.jsonl"] = (rows + "\n" if rows else "").encode("utf-8")

    members["VERIFY.md"] = _verify_md(snap.chain.ok, signed=signed).encode("utf-8")
    return members


def _build_manifest(
    snap: _LogSnapshot, options: PackOptions, members: dict[str, bytes], pub_hex: str | None
) -> dict:
    return {
        "pack_format": PACK_FORMAT,
        "name": options.name or snap.path.stem,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": {"name": "mcp-auth-gateway-attestation-pack", "version": __version__},
        "source": {"audit_path": str(snap.path), "total_records": len(snap.records)},
        "window": {"from": options.from_ts, "to": options.to_ts, "records": len(snap.windowed)},
        "chain": {
            "ok": snap.chain.ok,
            "records": snap.chain.records,
            "detail": snap.chain.detail,
            "terminal_record_hash": snap.terminal_hash,
        },
        "frameworks": list(options.frameworks),
        "files": [
            {"name": n, "sha256": _sha256(b), "bytes": len(b)} for n, b in sorted(members.items())
        ],
        "signature": {"algorithm": "ed25519", "public_key": pub_hex} if pub_hex else None,
    }


def _write_zip(out_zip: Path, members: dict[str, bytes], manifest: dict, signer) -> None:
    """Write the members, the manifest, and (when signing) the detached signature over
    the exact manifest bytes."""
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, data in sorted(members.items()):
            zf.writestr(member_name, data)
        zf.writestr(_MANIFEST_NAME, manifest_bytes)
        if signer:
            signature = base64.b64encode(signer.sign(manifest_bytes)).decode("ascii")
            zf.writestr(_SIGNATURE_NAME, signature)


def build_pack(
    audit_path: str | Path, out_zip: str | Path, options: PackOptions | None = None
) -> dict:
    """Build the pack; return the manifest that was written into it."""
    options = options or PackOptions()
    snap = _snapshot(Path(audit_path), options)
    signer, pub_hex = _load_signer(options.signing_key) if options.signing_key else (None, None)
    members = _collect_members(snap, options, signed=signer is not None)
    manifest = _build_manifest(snap, options, members, pub_hex)
    _write_zip(Path(out_zip), members, manifest, signer)
    return manifest


# --- verify ---------------------------------------------------------------------


def _check_members(zf: zipfile.ZipFile, names: set[str], manifest: dict) -> list[str]:
    """Every listed member is present with the listed hash, and nothing else rides along."""
    problems: list[str] = []
    listed = {f["name"]: f for f in manifest.get("files", [])}
    for member_name, entry in listed.items():
        if member_name not in names:
            problems.append(f"listed member missing from zip: {member_name}")
            continue
        if _sha256(zf.read(member_name)) != entry.get("sha256"):
            problems.append(f"sha256 mismatch: {member_name}")
    extras = names - set(listed) - {_MANIFEST_NAME, _SIGNATURE_NAME}
    problems.extend(f"unlisted member in zip: {n}" for n in sorted(extras))
    return problems


def _check_signature(
    zf: zipfile.ZipFile,
    names: set[str],
    manifest: dict,
    manifest_bytes: bytes,
    public_key: str | None,
) -> list[str]:
    """The detached signature verifies under the pinned key, or, unpinned, under the
    key the manifest itself declares."""
    sig_info = manifest.get("signature")
    if not sig_info:
        if public_key:
            return ["a public key was pinned but the pack declares no signature"]
        if _SIGNATURE_NAME in names:
            return ["pack-manifest.sig present but manifest declares no signature"]
        return []
    problems: list[str] = []
    embedded = sig_info.get("public_key")
    key = public_key or embedded
    if public_key and embedded != public_key:
        problems.append("the manifest's embedded public key is not the pinned key")
    if not isinstance(key, str):
        problems.append("manifest signature block carries no public key")
    elif _SIGNATURE_NAME not in names:
        problems.append("manifest declares a signature but pack-manifest.sig is missing")
    elif not _verify_signature(manifest_bytes, zf.read(_SIGNATURE_NAME).decode("ascii"), key):
        problems.append("signature verification FAILED over pack-manifest.json")
    return problems


def _check_chain(zf: zipfile.ZipFile, names: set[str], manifest: dict) -> list[str]:
    """The contained log still chain-verifies to the state the manifest declares."""
    if "audit.log" not in names:
        return ["audit.log missing from pack"]
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        log.write_bytes(zf.read("audit.log"))
        chain = verify_file(log)
    declared = manifest.get("chain", {})
    if chain.ok != declared.get("ok") or chain.records != declared.get("records"):
        return [
            f"chain state differs from manifest: now ok={chain.ok} "
            f"records={chain.records}, declared ok={declared.get('ok')} "
            f"records={declared.get('records')}"
        ]
    return []


def verify_pack(zip_path: str | Path, *, public_key: str | None = None) -> tuple[bool, list[str]]:
    """Re-check a pack: member hashes, the contained chain, and any signature.

    Returns ``(ok, problems)``. ``public_key`` (hex) pins the signer: the signature
    is checked against it and a manifest whose embedded key differs is a problem.
    Without it the embedded key is used, which only proves self-consistency.
    """
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        if _MANIFEST_NAME not in names:
            return False, [f"missing {_MANIFEST_NAME}"]
        manifest_bytes = zf.read(_MANIFEST_NAME)
        try:
            manifest = json.loads(manifest_bytes)
        except ValueError as exc:
            return False, [f"{_MANIFEST_NAME} is not valid JSON ({exc})"]
        problems = (
            _check_members(zf, names, manifest)
            + _check_signature(zf, names, manifest, manifest_bytes, public_key)
            + _check_chain(zf, names, manifest)
        )
    return not problems, problems


def _is_signed(zip_path: str | Path) -> bool:
    with zipfile.ZipFile(zip_path) as zf:
        return bool(json.loads(zf.read(_MANIFEST_NAME)).get("signature"))


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
    ap.add_argument(
        "--public-key",
        default=None,
        metavar="HEX",
        help="with --verify: the signer's public key; without it the embedded key is trusted",
    )
    ap.add_argument("--generate-key", default=None, metavar="PATH", help="write a new key PEM")
    args = ap.parse_args()

    if args.generate_key:
        pub = generate_key(args.generate_key)
        print(f"wrote Ed25519 private key → {args.generate_key}")
        print(f"public key (record this out-of-band): {pub}")
        raise SystemExit(0)

    if args.verify:
        ok, problems = verify_pack(args.verify, public_key=args.public_key)
        if ok:
            print(f"OK: pack verified ({args.verify})")
            if _is_signed(args.verify):
                which = "pinned key" if args.public_key else "embedded (unpinned) key"
                print(f"signature: valid for {which}")
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
        PackOptions(
            frameworks=tuple(args.framework) if args.framework else DEFAULT_FRAMEWORKS,
            from_ts=args.from_ts,
            to_ts=args.to_ts,
            baseline_path=args.baseline,
            signing_key=args.signing_key,
            name=args.name,
        ),
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
