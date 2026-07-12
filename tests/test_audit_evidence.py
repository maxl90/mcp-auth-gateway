"""Phase 4 audit evidence: tamper-evidence, structural metadata, SIEM export."""

from __future__ import annotations

import json

import pytest

from mcp_auth_gateway.audit import export, structure, verify, writer


@pytest.fixture(autouse=True)
def _reset_chain():
    writer._chain["path"] = None
    writer._chain["last_hash"] = None
    yield


# --- tamper-evidence (hash chain) ------------------------------------------


def _write_n(path, n):
    for i in range(n):
        writer.record(outcome="allowed", tool=f"tool_{i}", correlation_id=f"c{i}")


def test_intact_chain_verifies(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    _write_n(log, 5)
    result = verify.verify_file(log)
    assert result.ok and result.records == 5


def test_edited_record_breaks_chain(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    _write_n(log, 5)

    # Tamper: flip a field in record 2 (0-indexed) without fixing its hash.
    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["outcome"] = "denied"  # someone doctoring the evidence
    lines[2] = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify.verify_file(log)
    assert not result.ok
    assert result.broken_line == 3  # 1-indexed
    assert "modified" in result.detail


def test_deleted_record_breaks_chain(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    _write_n(log, 5)

    lines = log.read_text(encoding="utf-8").splitlines()
    del lines[2]  # excise a record to hide it
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify.verify_file(log)
    assert not result.ok
    assert "chain" in result.detail  # prev_hash linkage break


def test_chain_survives_restart(tmp_path, monkeypatch):
    """A new process (simulated by resetting in-memory chain state) continues the
    existing chain by seeding from the log tail, rather than forking it."""
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    _write_n(log, 3)

    writer._chain["path"] = None  # simulate a restart
    writer._chain["last_hash"] = None
    writer.record(outcome="allowed", tool="after_restart", correlation_id="c99")

    result = verify.verify_file(log)
    assert result.ok and result.records == 4


# --- structural metadata (leak-safe) ---------------------------------------


def test_sql_structure_extracts_tables_columns_pii():
    desc = structure.describe(
        "execute_sql", {"sql": "SELECT mrn, last_name, diagnosis FROM patients WHERE id = 5"}
    )
    assert desc["kind"] == "sql"
    assert desc["statement_types"] == ["SELECT"]
    assert "patients" in desc["tables"]
    assert set(desc["columns"]) >= {"mrn", "last_name", "diagnosis", "id"}
    assert desc["touches_pii"] is True
    assert set(desc["pii_columns"]) >= {"mrn", "last_name", "diagnosis"}


def test_sql_structure_never_contains_values():
    """The adversarial invariant: a literal value must never appear in the
    structural metadata."""
    secret = "123-45-6789"
    desc = structure.describe(
        "execute_sql",
        {"sql": f"INSERT INTO patients (ssn, note) VALUES ('{secret}', 'topsecret')"},
    )
    blob = json.dumps(desc)
    assert secret not in blob
    assert "topsecret" not in blob
    # But it still captured the shape.
    assert "patients" in desc["tables"]
    assert desc["statement_types"] == ["INSERT"]


def test_namespaced_sql_tool_still_recognized():
    desc = structure.describe("postgres__execute_sql", {"sql": "DELETE FROM audit_log"})
    assert desc["statement_types"] == ["DELETE"]
    assert "audit_log" in desc["tables"]


def test_unparseable_sql_degrades_without_leaking():
    desc = structure.describe("execute_sql", {"sql": ")))not valid sql((("})
    # Either parse_error or a best-effort partial — but never the raw text.
    assert ")))" not in json.dumps(desc)


def test_generic_tool_records_only_arg_keys():
    desc = structure.describe(
        "merge_pull_request", {"owner": "acme", "repo": "secret-repo", "pr": 42}
    )
    assert desc["kind"] == "generic"
    assert desc["arg_keys"] == ["owner", "pr", "repo"]  # keys only
    assert "acme" not in json.dumps(desc)  # never the values
    assert "secret-repo" not in json.dumps(desc)


def test_no_arguments_returns_none():
    assert structure.describe("execute_sql", None) is None


# --- SIEM export ------------------------------------------------------------


def test_export_flattens_attribution_and_structure(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    writer.record(
        outcome="allowed",
        tool="postgres__execute_sql",
        correlation_id="c1",
        upstream="postgres",
        claims={"oid": "user-1", "preferred_username": "a@b.com", "tid": "t1", "azp": "agent-1"},
        structure={"kind": "sql", "tables": ["patients"], "columns": ["mrn"],
                   "pii_columns": ["mrn"], "touches_pii": True, "statement_types": ["SELECT"]},
    )
    rows = [json.loads(line) for line in export.export_lines(log)]
    assert len(rows) == 1
    row = rows[0]
    assert row["AgentAppId"] == "agent-1"
    assert row["OnBehalfOfUsername"] == "a@b.com"
    assert row["TenantId"] == "t1"
    assert row["Tool"] == "postgres__execute_sql"
    assert row["ArgTables"] == "patients"
    assert row["ArgPiiColumns"] == "mrn"
    assert row["TouchesPii"] is True
    assert row["RecordHash"]  # tamper-evidence carried into the export
