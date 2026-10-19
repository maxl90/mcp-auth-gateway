"""GRC evidence report: signals → control mapping → rendered report."""

from __future__ import annotations

import json

from mcp_auth_gateway.audit import writer
from mcp_auth_gateway.evidence import report, signals


def _seed_log(path) -> writer.AuditLog:
    """Write a small mix of records: an attributed allowed SQL call touching PII,
    a denial, and a step-up challenge."""
    audit_log = writer.AuditLog(path)
    agent_human = {"oid": "human-1", "preferred_username": "a@b.com", "azp": "agent-1", "tid": "t1"}
    audit_log.record(
        writer.AuditEvent(
            outcome="allowed",
            tool="postgres__list_schemas",
            correlation_id="c1",
            upstream="postgres",
            claims=agent_human,
            structure={"kind": "generic", "arg_keys": []},
        )
    )
    audit_log.record(
        writer.AuditEvent(
            outcome="denied",
            tool="github__delete_file",
            correlation_id="c2",
            upstream="github",
            claims=agent_human,
            reason="not permitted",
        )
    )
    audit_log.record(
        writer.AuditEvent(
            outcome="step_up_required",
            tool="postgres__execute_sql",
            correlation_id="c3",
            upstream="postgres",
            claims=agent_human,
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
    return audit_log


def test_signals_computed(tmp_path):
    log = tmp_path / "audit.log"
    _seed_log(log)
    s = signals.compute(log)
    assert s.total_records == 3
    assert s.outcomes == {"allowed": 1, "denied": 1, "step_up_required": 1}
    assert s.distinct_agents == 1
    assert s.distinct_humans == 1
    assert s.records_fully_attributed == 3
    assert s.pii_touch_records == 1
    assert s.tamper_evident is True
    flags = s.flags()
    assert flags["attribution_present"]
    assert flags["access_denials_logged"]
    assert flags["stepup_enforced"]
    assert flags["data_sensitivity_tracked"]
    assert flags["tamper_evident"]


def test_bundle_attests_controls(tmp_path):
    log = tmp_path / "audit.log"
    _seed_log(log)
    bundle = report.build_bundle(log, "nist-ai-rmf")
    assert bundle["framework"] == "NIST AI RMF 1.0"
    by_id = {c["id"]: c for c in bundle["controls"]}
    # All signals present for these → ATTESTED.
    assert by_id["GOVERN 1.5"]["status"] == "ATTESTED"
    assert by_id["MEASURE 2.7"]["status"] == "ATTESTED"  # denials + stepup both present
    assert by_id["MEASURE 2.10"]["status"] == "ATTESTED"  # PII tracked


def test_empty_log_gives_no_evidence(tmp_path):
    bundle = report.build_bundle(tmp_path / "nope.log", "nist-ai-rmf")
    assert bundle["coverage"]["records"] == 0
    assert all(c["status"] == "NO EVIDENCE" for c in bundle["controls"])


def test_broken_chain_surfaces_in_report(tmp_path):
    log = tmp_path / "audit.log"
    _seed_log(log)
    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["tool"] = "tampered"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    bundle = report.build_bundle(log, "nist-ai-rmf")
    assert bundle["coverage"]["tamper_evident"] is False
    # GOVERN 4.3 requires tamper_evident → drops from ATTESTED.
    govern43 = next(c for c in bundle["controls"] if c["id"] == "GOVERN 4.3")
    assert govern43["status"] != "ATTESTED"


def test_markdown_renders(tmp_path):
    log = tmp_path / "audit.log"
    _seed_log(log)
    md = report.render_markdown(report.build_bundle(log, "nist-ai-rmf"))
    assert "# Agent Governance Evidence Report" in md
    assert "GOVERN 1.5" in md
    assert "Tamper-evidence:" in md


def test_bundle_carries_attribution_conformance_and_chain_detail(tmp_path):
    log = tmp_path / "audit.log"
    audit_log = _seed_log(log)
    audit_log.record(
        writer.AuditEvent(
            outcome="allowed",
            tool="postgres__execute_sql",
            correlation_id="c4",
            claims={"azp": "agent-1", "idtyp": "app"},  # app-only: an agent, no human
            conformance={"schema_conformant": False, "violations": []},
        )
    )
    bundle = report.build_bundle(log, "nist-ai-rmf")
    sig = bundle["signals"]
    assert (sig["records_with_agent"], sig["records_with_human"]) == (4, 3)
    assert (sig["schema_checked_records"], sig["schema_violation_records"]) == (1, 1)
    assert bundle["coverage"]["chain_detail"] == "chain intact"

    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["outcome"] = "allowed"
    lines[1] = json.dumps(rec, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    broken = report.build_bundle(log, "nist-ai-rmf")
    assert broken["coverage"]["chain_detail"].startswith("line 2:")
