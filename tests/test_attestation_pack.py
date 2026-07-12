"""Attestation pack: build, verify, window, sign, tamper."""

import json
import zipfile

import pytest

from mcp_auth_gateway.audit.writer import GENESIS, compute_hash
from mcp_auth_gateway.evidence.attestation import (
    DEFAULT_FRAMEWORKS,
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
            "structure": {"kind": "sql", "statement_types": ["SELECT"], "tables": ["patients"],
                          "columns": ["ssn"], "pii_columns": ["ssn"], "touches_pii": True},
            "conformance": {"schema_conformant": True},
        },
    }


def _write_chained_log(path, contents):
    prev = None
    lines = []
    for content in contents:
        h = compute_hash(content, prev or GENESIS)
        lines.append(json.dumps({**content, "integrity": {"prev_hash": prev or GENESIS, "record_hash": h}}))
        prev = h
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return prev  # terminal hash


@pytest.fixture
def log(tmp_path):
    p = tmp_path / "audit.log"
    terminal = _write_chained_log(p, [
        _rec("2026-07-01T10:00:00.000+00:00"),
        _rec("2026-07-02T11:00:00.000+00:00", outcome="denied"),
        _rec("2026-07-03T12:00:00.000+00:00"),
    ])
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
        "ok": True, "records": 3, "detail": "chain intact", "terminal_record_hash": terminal,
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

    # Rewrite the zip with one member altered.
    with zipfile.ZipFile(out) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    members["export.sentinel.jsonl"] = members["export.sentinel.jsonl"] + b'{"forged":1}\n'
    with zipfile.ZipFile(out, "w") as zf:
        for n, b in members.items():
            zf.writestr(n, b)

    ok, problems = verify_pack(out)
    assert not ok
    assert any("sha256 mismatch: export.sentinel.jsonl" in x for x in problems)


def test_tampered_audit_log_fails_chain_recheck(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    build_pack(p, out)
    with zipfile.ZipFile(out) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    tampered = members["audit.log"].replace(b'"allowed"', b'"denied"', 1)
    members["audit.log"] = tampered
    with zipfile.ZipFile(out, "w") as zf:
        for n, b in members.items():
            zf.writestr(n, b)

    ok, problems = verify_pack(out)
    assert not ok
    assert any("sha256 mismatch: audit.log" in x for x in problems)
    assert any("chain state differs" in x for x in problems)


def test_windowing_filters_reports_and_exports_but_keeps_full_log(log, tmp_path):
    p, _ = log
    out = tmp_path / "pack.zip"
    manifest = build_pack(p, out, from_ts="2026-07-02", to_ts="2026-07-02")
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
    manifest = build_pack(p, out, signing_key=key)
    assert manifest["signature"] == {"algorithm": "ed25519", "public_key": pub_hex}

    ok, problems = verify_pack(out)
    assert ok, problems

    # Alter the manifest inside the zip: signature must fail.
    with zipfile.ZipFile(out) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    doctored = json.loads(members["pack-manifest.json"])
    doctored["window"]["from"] = "2026-01-01"
    members["pack-manifest.json"] = json.dumps(doctored, indent=2).encode("utf-8")
    with zipfile.ZipFile(out, "w") as zf:
        for n, b in members.items():
            zf.writestr(n, b)
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


def test_console_bundle_shape_and_baseline_inclusion(log, tmp_path):
    p, _ = log
    baseline = tmp_path / "manifest-baseline.json"
    baseline.write_text(json.dumps({"version": "1", "tools": {}}), encoding="utf-8")
    out = tmp_path / "pack.zip"
    build_pack(p, out, baseline_path=baseline)

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        report = json.loads(zf.read("evidence-report.eu-ai-act.json"))
    # The Evidence Console's import contract: an audit*.log, an optional
    # manifest-baseline*.json, and report bundles carrying these four keys.
    assert "audit.log" in names and "manifest-baseline.json" in names
    assert {"framework", "coverage", "signals", "controls"} <= set(report)
