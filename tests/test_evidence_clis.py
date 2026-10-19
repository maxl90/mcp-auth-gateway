"""The evidence console scripts as an operator runs them: arguments, output, exit codes."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable

import pytest

from mcp_auth_gateway.audit import export, verify, writer
from mcp_auth_gateway.evidence import attestation, frameworks, report

_CLAIMS = {"oid": "human-1", "preferred_username": "a@b.com", "azp": "agent-1", "tid": "t1"}


@pytest.fixture
def log(tmp_path):
    """A three-record chained log: allowed, denied, step-up challenged."""
    path = tmp_path / "audit.log"
    audit_log = writer.AuditLog(path)
    for i, outcome in enumerate(("allowed", "denied", "step_up_required")):
        audit_log.record(
            writer.AuditEvent(
                outcome=outcome,
                tool=f"postgres__tool_{i}",
                correlation_id=f"c{i}",
                upstream="postgres",
                claims=_CLAIMS,
            )
        )
    return path


@pytest.fixture
def run(monkeypatch, capsys) -> Callable[..., tuple[int, str, str]]:
    """Run a console script's ``main`` with ``args`` as its command line and return
    ``(exit code, stdout, stderr)``."""

    def _run(main: Callable[[], None], *args: object) -> tuple[int, str, str]:
        capsys.readouterr()  # drop what the fixtures printed
        monkeypatch.setattr(sys, "argv", ["prog", *map(str, args)])
        try:
            main()
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


def _tamper_second_record(log) -> None:
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"denied"', '"allowed"')
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- mcp-auth-gateway-verify-audit ------------------------------------------------


def test_verify_passes_an_intact_log(run, log):
    assert run(verify.main, log) == (0, f"OK: 3 records, chain intact ({log})\n", "")


def test_verify_names_the_first_tampered_line(run, log):
    _tamper_second_record(log)
    code, _, err = run(verify.main, log)
    assert code == 1
    assert err.startswith("TAMPER DETECTED: line 2: record_hash mismatch")
    assert f"(1 records verified before the break, in {log})" in err


def test_verify_fails_a_record_without_an_integrity_block(run, log):
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"tool": "unchained"}\n')
    code, _, err = run(verify.main, log)
    assert code == 1
    assert "line 4: missing integrity block" in err


def test_verify_reads_the_configured_log_by_default(run, log, monkeypatch):
    monkeypatch.setattr(verify.settings, "audit_log_path", str(log))
    code, out, _ = run(verify.main)
    assert code == 0
    assert str(log) in out


def test_verify_treats_a_missing_log_as_empty(run, tmp_path):
    code, out, _ = run(verify.main, tmp_path / "none.log")
    assert code == 0
    assert out.startswith("OK: 0 records")


# --- mcp-auth-gateway-export-audit ------------------------------------------------


def test_export_writes_sentinel_rows_to_stdout(run, log):
    code, out, _ = run(export.main, log)
    rows = [json.loads(line) for line in out.splitlines()]
    assert code == 0
    assert [r["Outcome"] for r in rows] == ["allowed", "denied", "step_up_required"]
    assert {r["AgentAppId"] for r in rows} == {"agent-1"}


def test_export_writes_ocsf_rows_to_a_file(run, log, tmp_path):
    out_path = tmp_path / "ocsf.jsonl"
    code, out, _ = run(export.main, log, out_path, "--format", "ocsf")
    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    assert code == 0
    assert out == f"exported ocsf audit rows → {out_path}\n"
    assert len(rows) == 3
    assert {r["class_uid"] for r in rows} == {6003}


# --- mcp-auth-gateway-evidence-report ---------------------------------------------


def test_report_prints_markdown(run, log):
    code, out, _ = run(report.main, log)
    assert code == 0
    assert out.startswith("# Agent Governance Evidence Report — NIST AI RMF 1.0")


def test_report_writes_markdown_and_its_json_bundle(run, log, tmp_path):
    md = tmp_path / "soc2.md"
    code, out, _ = run(report.main, log, "soc2", md)
    bundle = json.loads(md.with_suffix(".json").read_text(encoding="utf-8"))
    assert code == 0
    assert out == f"wrote {md} and {md.with_suffix('.json')}\n"
    assert md.read_text(encoding="utf-8").startswith("# Agent Governance Evidence Report")
    assert bundle["framework"] == frameworks.SOC2["framework"]
    assert bundle["coverage"]["records"] == 3


def test_report_maps_a_custom_framework_file(run, log, tmp_path):
    custom = tmp_path / "house.yaml"
    custom.write_text(
        "framework: House controls\n"
        "controls:\n"
        "  - id: HC-1\n"
        "    title: Every agent action is logged\n"
        "    signals: [actions_logged]\n",
        encoding="utf-8",
    )
    code, out, _ = run(report.main, log, custom)
    assert code == 0
    assert out.startswith("# Agent Governance Evidence Report — House controls")
    assert "HC-1" in out


def test_a_framework_file_without_controls_is_refused(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("framework: nothing here\n", encoding="utf-8")
    with pytest.raises(ValueError, match="'controls' list"):
        frameworks.load(str(bad))


# --- mcp-auth-gateway-attestation-pack --------------------------------------------


def test_attestation_pack_generate_build_and_verify(run, log, tmp_path):
    key = tmp_path / "signing.pem"
    code, out, _ = run(attestation.main, "--generate-key", key)
    pub = out.splitlines()[1].rsplit(" ", 1)[1]
    assert code == 0
    assert key.exists()
    assert len(pub) == 64

    pack = tmp_path / "pack.zip"
    code, out, _ = run(attestation.main, log, pack, "--signing-key", key, "--framework", "soc2")
    assert code == 0
    assert out == f"wrote {pack}: 3 windowed of 3 records, chain intact, signed\n"

    code, out, _ = run(attestation.main, "--verify", pack)
    assert code == 0
    assert out.splitlines() == [
        f"OK: pack verified ({pack})",
        "signature: valid for embedded (unpinned) key",
    ]
    code, out, _ = run(attestation.main, "--verify", pack, "--public-key", pub)
    assert code == 0
    assert out.splitlines()[1] == "signature: valid for pinned key"


def test_attestation_verify_lists_the_problems(run, log, tmp_path):
    pack = tmp_path / "pack.zip"
    run(attestation.main, log, pack)
    assert run(attestation.main, "--verify", pack) == (0, f"OK: pack verified ({pack})\n", "")

    code, _, err = run(attestation.main, "--verify", pack, "--public-key", "00" * 32)
    assert code == 1
    assert err.splitlines() == [
        f"PACK VERIFICATION FAILED: {pack}",
        "  - a public key was pinned but the pack declares no signature",
    ]


def test_attestation_pack_names_itself_and_reports_a_broken_chain(run, log, tmp_path, monkeypatch):
    _tamper_second_record(log)
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(attestation.main, log, "--from", "2000-01-01", "--name", "q3")
    assert code == 0
    assert out.startswith("wrote attestation-pack-")
    assert "chain BROKEN (line 2: record_hash mismatch" in out
    assert len(list(tmp_path.glob("attestation-pack-*.zip"))) == 1
