"""Audit evidence: tamper-evidence, structural metadata, SIEM export."""

from __future__ import annotations

import json

import pytest

from mcp_auth_gateway.audit import export, structure, verify, writer
from mcp_auth_gateway.evidence import signals

# --- tamper-evidence (hash chain) ------------------------------------------


def _write_n(log, n):
    audit_log = writer.AuditLog(log)
    for i in range(n):
        audit_log.record(
            writer.AuditEvent(outcome="allowed", tool=f"tool_{i}", correlation_id=f"c{i}")
        )


def test_intact_chain_verifies(tmp_path):
    log = tmp_path / "audit.log"
    _write_n(log, 5)
    result = verify.verify_file(log)
    assert result.ok and result.records == 5


def test_edited_record_breaks_chain(tmp_path):
    log = tmp_path / "audit.log"
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


def test_deleted_record_breaks_chain(tmp_path):
    log = tmp_path / "audit.log"
    _write_n(log, 5)

    lines = log.read_text(encoding="utf-8").splitlines()
    del lines[2]  # excise a record to hide it
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify.verify_file(log)
    assert not result.ok
    assert "chain" in result.detail  # prev_hash linkage break


def test_swapped_records_break_chain(tmp_path):
    log = tmp_path / "audit.log"
    _write_n(log, 5)

    lines = log.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # reorder to change what happened first
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify.verify_file(log)
    assert not result.ok
    assert result.broken_line == 2


def test_tail_truncation_is_invisible_to_the_chain_alone(tmp_path):
    """Dropping the last records leaves a valid prefix. Only an anchor kept elsewhere
    (an attestation pack's terminal_record_hash) shows that records are missing."""
    log = tmp_path / "audit.log"
    _write_n(log, 5)
    terminal = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])["integrity"]

    lines = log.read_text(encoding="utf-8").splitlines()[:3]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify.verify_file(log)
    assert result.ok and result.records == 3
    assert json.loads(lines[-1])["integrity"]["record_hash"] != terminal["record_hash"]


def test_chain_survives_restart(tmp_path):
    """A new process (simulated by resetting in-memory chain state) continues the
    existing chain by seeding from the log tail, rather than forking it."""
    log = tmp_path / "audit.log"
    _write_n(log, 3)

    restarted = writer.AuditLog(log)  # a new process, same log
    restarted.record(
        writer.AuditEvent(outcome="allowed", tool="after_restart", correlation_id="c99")
    )

    result = verify.verify_file(log)
    assert result.ok and result.records == 4


def test_corrupt_tail_starts_a_new_chain(tmp_path):
    # A tail that is not a record, or whose record_hash is not a string, seeds
    # genesis rather than crashing the writer or chaining to a non-hash.
    log = tmp_path / "audit.log"
    for tail in ('{"integrity": {"record_hash": 5}}', "not json"):
        log.write_text(tail + "\n", encoding="utf-8")
        rec = writer.AuditLog(log).record(
            writer.AuditEvent(outcome="allowed", tool="t", correlation_id="c")
        )
        assert rec["integrity"]["prev_hash"] == writer.GENESIS


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


@pytest.mark.parametrize(
    "rec",
    [
        {"actor": "x"},
        {"actor": {"agent": "y", "on_behalf_of": 5}},
        {"actor": {"agent": {"app_id": ["a"]}, "on_behalf_of": {"oid": {"x": 1}}}},
        {"arguments": 5},
        {"arguments": {"structure": "s", "conformance": {"violations": 5}}},
        {"manifest": [], "channel": "c", "integrity": 1},
    ],
)
def test_a_field_of_the_wrong_type_reads_as_absent(rec):
    # A record can chain-verify and still not have the writer's shape (another
    # writer, an old schema). Every reader still produces its row and its counts.
    sentinel = export.flatten_record(rec)
    ocsf = export.flatten_record_ocsf(rec)
    sig = signals.aggregate([rec])
    json.dumps([sentinel, ocsf])
    assert sentinel["ArgKind"] is None
    assert sentinel["SchemaViolationKeywords"] is None
    assert (sig.total_records, sig.records_with_agent, sig.records_with_human) == (1, 0, 0)
    assert sig.structured_records == 0


def test_export_flattens_attribution_and_structure(tmp_path):
    log = tmp_path / "audit.log"
    writer.AuditLog(log).record(
        writer.AuditEvent(
            outcome="allowed",
            tool="postgres__execute_sql",
            correlation_id="c1",
            upstream="postgres",
            claims={
                "oid": "user-1",
                "preferred_username": "a@b.com",
                "tid": "t1",
                "azp": "agent-1",
            },
            structure={
                "kind": "sql",
                "tables": ["patients"],
                "columns": ["mrn"],
                "pii_columns": ["mrn"],
                "touches_pii": True,
                "statement_types": ["SELECT"],
            },
        )
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
