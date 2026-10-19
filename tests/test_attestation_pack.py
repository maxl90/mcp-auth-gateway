"""Attestation pack: build, verify, window, sign, tamper."""

import base64
import json
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_auth_gateway.audit.writer import GENESIS, compute_hash
from mcp_auth_gateway.evidence.attestation import (
    DEFAULT_FRAMEWORKS,
    PackOptions,
    build_pack,
    generate_key,
    verify_pack,
)


def _rec(ts, outcome="allowed", tool="postgres__execute_sql"):
    return {
        "schema_version": "1.2",
        "ts": ts,
        "correlation_id": "c" * 32,
        "tenant_id": "t-1",
        "actor": {
            "agent": {"app_id": "app-1", "name": "analytics-agent"},
            "on_behalf_of": {"oid": "oid-1", "username": "sarah@contoso.com", "sub": "sub-1"},
        },
        "channel": None,
        "tool": tool,
        "upstream": "postgres",
        "outcome": outcome,
        "reason": None if outcome == "allowed" else "denied by policy",
        "manifest": {"sha256": "m" * 64},
        "arguments": {
            "redacted": True,
            "structure": {
                "kind": "sql",
                "statement_types": ["SELECT"],
                "tables": ["patients"],
                "columns": ["ssn"],
                "pii_columns": ["ssn"],
                "touches_pii": True,
            },
            "conformance": {"schema_conformant": True},
        },
    }


def _rewrite(zip_path, **members):
    """Rewrite the pack with each named member replaced (``None`` drops it)."""
    with zipfile.ZipFile(zip_path) as zf:
        current = {n: zf.read(n) for n in zf.namelist()}
    current.update(members)
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in current.items():
            if data is not None:
                zf.writestr(name, data)


def _write_chained_log(path, contents):
    prev = None
    lines = []
    for content in contents:
        h = compute_hash(content, prev or GENESIS)
        lines.append(
            json.dumps({**content, "integrity": {"prev_hash": prev or GENESIS, "record_hash": h}})
        )
        prev = h
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return prev  # terminal hash


@pytest.fixture
def log(tmp_path):
    p = tmp_path / "audit.log"
    terminal = _write_chained_log(
        p,
        [
            _rec("2026-07-01T10:00:00.000+00:00"),
            _rec("2026-07-02T11:00:00.000+00:00", outcome="denied"),
            _rec("2026-07-03T12:00:00.000+00:00"),
        ],
    )
    return p, terminal


def test_pack_builds_with_expected_members_and_manifest(log, tmp_path):
    p, terminal = log
    out = tmp_path / "pack.zip"
    manifest = build_pack(p, out)

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert "audit.log" in names and "VERIFY.md" in names and "pack-manifest.json" in names
    for fw in DEFAULT_FRAMEWORKS:
        assert f"evidence-report.{fw}.json" in names and f"evidence-report.{fw}.md" in names
    assert "export.sentinel.jsonl" in names and "export.ocsf.jsonl" in names
    assert "pack-manifest.sig" not in names  # unsigned by default

    assert manifest["chain"] == {
        "ok": True,
        "records": 3,
        "detail": "chain intact",
        "terminal_record_hash": terminal,
    }
    assert manifest["source"]["total_records"] == 3
    assert manifest["window"] == {"from": None, "to": None, "records": 3}
    assert manifest["signature"] is None


def test_fresh_pack_verifies(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    ok, problems = verify_pack(out)
    assert ok, problems


def test_tampered_member_fails_verification(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)

    with zipfile.ZipFile(out) as zf:
        rows = zf.read("export.sentinel.jsonl")
    _rewrite(out, **{"export.sentinel.jsonl": rows + b'{"forged":1}\n'})

    ok, problems = verify_pack(out)
    assert not ok
    assert any("sha256 mismatch: export.sentinel.jsonl" in x for x in problems)


def test_tampered_audit_log_fails_chain_recheck(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    with zipfile.ZipFile(out) as zf:
        audit_log = zf.read("audit.log")
    _rewrite(out, **{"audit.log": audit_log.replace(b'"allowed"', b'"denied"', 1)})

    ok, problems = verify_pack(out)
    assert not ok
    assert any("sha256 mismatch: audit.log" in x for x in problems)
    assert any("chain state differs" in x for x in problems)


def test_windowing_filters_reports_and_exports_but_keeps_full_log(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    manifest = build_pack(p, out, PackOptions(from_ts="2026-07-02", to_ts="2026-07-02"))
    assert manifest["source"]["total_records"] == 3
    assert manifest["window"]["records"] == 1

    with zipfile.ZipFile(out) as zf:
        sentinel = zf.read("export.sentinel.jsonl").decode("utf-8").strip().splitlines()
        full_log = zf.read("audit.log").decode("utf-8").strip().splitlines()
        bundle = json.loads(zf.read("evidence-report.soc2.json"))
    assert len(sentinel) == 1
    assert json.loads(sentinel[0])["Outcome"] == "denied"
    assert len(full_log) == 3  # full chain always ships
    assert bundle["signals"]["total_records"] == 1
    assert bundle["coverage"]["tamper_evident"] is True  # chain verdict from FULL log
    assert bundle["coverage"]["window"] == {"from": "2026-07-02", "to": "2026-07-02"}


def test_signature_roundtrip_and_manifest_tamper_detection(log, tmp_path):
    p, _ = log
    key = tmp_path / "signing.pem"
    pub_hex = generate_key(key)
    out = tmp_path / "pack.zip"
    manifest = build_pack(p, out, PackOptions(signing_key=key))
    assert manifest["signature"] == {"algorithm": "ed25519", "public_key": pub_hex}

    ok, problems = verify_pack(out)
    assert ok, problems

    # Alter the manifest inside the zip: signature must fail.
    with zipfile.ZipFile(out) as zf:
        doctored = json.loads(zf.read("pack-manifest.json"))
    doctored["window"]["from"] = "2026-01-01"
    _rewrite(out, **{"pack-manifest.json": json.dumps(doctored, indent=2).encode("utf-8")})
    ok, problems = verify_pack(out)
    assert not ok
    assert any("signature verification FAILED" in x for x in problems)


def test_broken_chain_still_packs_and_says_so(log, tmp_path):
    p, _ = log
    # Corrupt the middle record on disk (post-write edit).
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"denied by policy"', '"totally fine"')
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = tmp_path / "pack.zip"
    manifest = build_pack(p, out)
    assert manifest["chain"]["ok"] is False
    with zipfile.ZipFile(out) as zf:
        verify_md = zf.read("VERIFY.md").decode("utf-8")
        bundle = json.loads(zf.read("evidence-report.nist-ai-rmf.json"))
    assert "already broken" in verify_md
    assert bundle["coverage"]["tamper_evident"] is False
    # The pack itself is still internally consistent and verifies as a container.
    ok, problems = verify_pack(out)
    assert ok, problems


def test_a_log_line_that_is_not_an_object_packs_as_a_broken_chain(log, tmp_path):
    p, _ = log
    with p.open("a", encoding="utf-8") as fh:
        fh.write("[1]\n")
    manifest = build_pack(p, tmp_path / "pack.zip")
    assert manifest["chain"]["ok"] is False
    assert manifest["chain"]["detail"] == "line 4: not a JSON object"


def test_a_manifest_that_is_not_an_object_fails_verification(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    _rewrite(out, **{"pack-manifest.json": b"[]"})
    assert verify_pack(out) == (False, ["pack-manifest.json is not a JSON object"])


@pytest.mark.parametrize(
    ("field", "value", "problem"),
    [
        ("files", [1], "files must be a list of objects that each name a member"),
        ("files", 5, "files must be a list of objects that each name a member"),
        ("signature", "x", "signature must be an object or null"),
        ("chain", 5, "chain must be an object"),
    ],
)
def test_a_manifest_field_of_the_wrong_shape_fails_verification(
    log, tmp_path, field, value, problem
):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("pack-manifest.json"))
    manifest[field] = value
    _rewrite(out, **{"pack-manifest.json": json.dumps(manifest).encode("utf-8")})
    assert verify_pack(out) == (False, [f"pack-manifest.json: {problem}"])


def test_a_missing_member_and_a_missing_log_are_named(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    _rewrite(out, **{"VERIFY.md": None, "audit.log": None})
    ok, problems = verify_pack(out)
    assert not ok
    assert "listed member missing from zip: VERIFY.md" in problems
    assert "audit.log missing from pack" in problems


@pytest.mark.parametrize(
    ("manifest", "problem"),
    [(None, "missing pack-manifest.json"), (b"{", "pack-manifest.json is not valid JSON")],
)
def test_an_unreadable_manifest_fails_verification(log, tmp_path, manifest, problem):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    _rewrite(out, **{"pack-manifest.json": manifest})
    ok, problems = verify_pack(out)
    assert not ok
    assert len(problems) == 1
    assert problems[0].startswith(problem)


def test_a_stray_signature_on_an_unsigned_pack_is_a_problem(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    _rewrite(out, **{"pack-manifest.sig": b"AAAA"})
    assert verify_pack(out) == (
        False,
        ["pack-manifest.sig present but manifest declares no signature"],
    )


def test_a_signed_pack_missing_its_signature_or_its_key_fails(log, tmp_path):
    p, _ = log
    key = tmp_path / "signing.pem"
    generate_key(key)
    out = tmp_path / "pack.zip"
    build_pack(p, out, PackOptions(signing_key=key))
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("pack-manifest.json"))

    _rewrite(out, **{"pack-manifest.sig": None})
    assert verify_pack(out) == (
        False,
        ["manifest declares a signature but pack-manifest.sig is missing"],
    )
    manifest["signature"] = {"algorithm": "ed25519"}
    _rewrite(out, **{"pack-manifest.json": json.dumps(manifest).encode("utf-8")})
    assert verify_pack(out) == (False, ["manifest signature block carries no public key"])


def test_a_window_leaves_out_records_it_cannot_place_in_time(tmp_path):
    p = tmp_path / "audit.log"
    _write_chained_log(
        p,
        [_rec("2026-07-01T10:00:00.000+00:00"), {**_rec("x"), "ts": None}, _rec("not-a-time")],
    )
    manifest = build_pack(p, tmp_path / "pack.zip", PackOptions(from_ts="2026-07-01"))
    assert (manifest["window"]["records"], manifest["source"]["total_records"]) == (1, 3)


def test_a_record_whose_fields_have_the_wrong_type_still_packs(tmp_path):
    p = tmp_path / "audit.log"
    odd = {**_rec("2026-07-02T10:00:00.000+00:00"), "actor": "x", "arguments": 5}
    _write_chained_log(p, [_rec("2026-07-01T10:00:00.000+00:00"), odd])
    manifest = build_pack(p, tmp_path / "pack.zip")
    assert manifest["chain"]["ok"] is True
    assert manifest["window"]["records"] == 2


def test_an_empty_log_packs_with_no_terminal_hash(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text("", encoding="utf-8")
    manifest = build_pack(p, tmp_path / "pack.zip")
    assert manifest["chain"]["terminal_record_hash"] is None
    assert manifest["window"]["records"] == 0


def test_pack_includes_the_baseline_and_report_bundles(log, tmp_path):
    p, _ = log
    baseline = tmp_path / "manifest-baseline.json"
    baseline.write_text(json.dumps({"version": "1", "tools": {}}), encoding="utf-8")
    out = tmp_path / "pack.zip"
    build_pack(p, out, PackOptions(baseline_path=baseline))

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        report = json.loads(zf.read("evidence-report.eu-ai-act.json"))
    # The full log, the baseline when one exists, and each report bundle's top-level keys.
    assert "audit.log" in names and "manifest-baseline.json" in names
    assert {"framework", "coverage", "signals", "controls"} <= set(report)


def _resign(members: dict[str, bytes], manifest: dict, key_path) -> None:
    """Rewrite the manifest and its detached signature with the key at ``key_path``."""
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    members["pack-manifest.json"] = manifest_bytes
    members["pack-manifest.sig"] = base64.b64encode(key.sign(manifest_bytes))


def test_pinned_public_key_must_match_the_signer(log, tmp_path):
    p, _ = log
    key = tmp_path / "signing.pem"
    pub = generate_key(key)
    other_pub = generate_key(tmp_path / "other.pem")
    out = tmp_path / "pack.zip"
    build_pack(p, out, PackOptions(signing_key=key))

    ok, problems = verify_pack(out, public_key=pub)
    assert ok, problems
    ok, problems = verify_pack(out, public_key=other_pub)
    assert not ok
    assert any("pinned" in x for x in problems)


def test_resigned_tamper_is_caught_only_by_a_pinned_key(log, tmp_path):
    """An attacker who alters the manifest can re-sign it with their own key and
    embed that key: the unpinned check is self-attesting and passes; the pinned
    check fails."""
    p, _ = log
    key = tmp_path / "signing.pem"
    pub = generate_key(key)
    attacker = tmp_path / "attacker.pem"
    attacker_pub = generate_key(attacker)
    out = tmp_path / "pack.zip"
    build_pack(p, out, PackOptions(signing_key=key))

    with zipfile.ZipFile(out) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    doctored = json.loads(members["pack-manifest.json"])
    doctored["window"]["from"] = "2026-01-01"
    doctored["signature"]["public_key"] = attacker_pub
    _resign(members, doctored, attacker)
    with zipfile.ZipFile(out, "w") as zf:
        for n, b in members.items():
            zf.writestr(n, b)

    ok, _ = verify_pack(out)
    assert ok  # self-attesting: the pack vouches for its own key
    ok, problems = verify_pack(out, public_key=pub)
    assert not ok
    assert any("pinned" in x for x in problems)


def test_pinning_an_unsigned_pack_is_a_problem(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    ok, problems = verify_pack(out, public_key="00" * 32)
    assert not ok
    assert any("no signature" in x for x in problems)


def test_a_signing_key_that_is_not_ed25519_is_refused(log, tmp_path):
    p, _ = log
    key = tmp_path / "rsa.pem"
    key.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="must be an Ed25519 private key"):
        build_pack(p, tmp_path / "pack.zip", PackOptions(signing_key=key))
