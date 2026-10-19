"""Audit records — structured, attributed, redacted by default, hash-chained."""

from __future__ import annotations

import json

from mcp_auth_gateway.audit import writer

_CLAIMS = {
    "sub": "subject-123",
    "oid": "object-id-123",
    "preferred_username": "analyst@example.com",
    "groups": ["g1"],
    "tid": "tenant-abc",
    "azp": "agent-app-id-999",
    "app_displayname": "Demo Agent",
}


def test_record_captures_action_and_outcome():
    rec = writer.build_record(
        writer.AuditEvent(
            outcome="allowed", tool="execute_sql", correlation_id="abc", claims=_CLAIMS
        )
    )
    assert rec["outcome"] == "allowed"
    assert rec["tool"] == "execute_sql"
    assert rec["correlation_id"] == "abc"
    assert rec["schema_version"] == writer.SCHEMA_VERSION
    assert rec["tenant_id"] == "tenant-abc"
    assert "ts" in rec


def test_attribution_splits_agent_from_human():
    """The attribution problem, made explicit: the acting agent (app) is distinct
    from the human it acted on behalf of."""
    rec = writer.build_record(
        writer.AuditEvent(
            outcome="allowed", tool="execute_sql", correlation_id="abc", claims=_CLAIMS
        )
    )
    actor = rec["actor"]
    assert actor["agent"] == {"app_id": "agent-app-id-999", "name": "Demo Agent"}
    assert actor["on_behalf_of"]["oid"] == "object-id-123"
    assert actor["on_behalf_of"]["username"] == "analyst@example.com"


def test_app_only_token_has_no_human():
    rec = writer.build_record(
        writer.AuditEvent(
            outcome="allowed",
            tool="execute_sql",
            correlation_id="abc",
            claims={"azp": "app-1", "idtyp": "app", "oid": "sp-oid"},
        )
    )
    assert rec["actor"]["agent"]["app_id"] == "app-1"
    assert rec["actor"]["on_behalf_of"] is None


def test_arguments_values_never_recorded():
    """No argument values, ever — even when structural metadata is attached."""
    rec = writer.build_record(
        writer.AuditEvent(
            outcome="allowed",
            tool="execute_sql",
            correlation_id="abc",
            claims=_CLAIMS,
            structure={"kind": "sql", "tables": ["patients"], "columns": ["ssn"]},
        )
    )
    assert rec["arguments"]["redacted"] is True
    serialized = json.dumps(rec)
    assert "SELECT" not in serialized
    assert "123-45-6789" not in serialized  # a value would look like this


def test_denied_record_carries_reason():
    rec = writer.build_record(
        writer.AuditEvent(
            outcome="denied",
            tool="execute_sql",
            correlation_id="abc",
            claims=_CLAIMS,
            reason="tool not permitted",
        )
    )
    assert rec["outcome"] == "denied"
    assert rec["reason"] == "tool not permitted"


def test_write_appends_chained_json_line(tmp_path, capsys):
    log = tmp_path / "audit.log"
    audit_log = writer.AuditLog(log)
    audit_log.record(
        writer.AuditEvent(outcome="allowed", tool="list_schemas", correlation_id="cid1")
    )
    audit_log.record(writer.AuditEvent(outcome="denied", tool="execute_sql", correlation_id="cid2"))

    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    r0, r1 = json.loads(lines[0]), json.loads(lines[1])
    assert r0["tool"] == "list_schemas"
    assert r1["outcome"] == "denied"
    # Chain: record 0 is genesis; record 1 links to record 0.
    assert r0["integrity"]["prev_hash"] == writer.GENESIS
    assert r1["integrity"]["prev_hash"] == r0["integrity"]["record_hash"]
    assert "list_schemas" in capsys.readouterr().out


def test_sink_failure_is_logged_and_never_raises(tmp_path, caplog):
    with caplog.at_level("ERROR", logger="mcp_auth_gateway.audit"):
        rec = writer.AuditLog(tmp_path).record(  # a directory
            writer.AuditEvent(outcome="allowed", tool="t", correlation_id="c")
        )
    assert rec["integrity"]["record_hash"]
    assert "audit log write failed" in caplog.text
