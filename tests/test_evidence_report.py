"""GRC evidence report: signals → control mapping → rendered report."""

from __future__ import annotations

import json

import pytest

from mcp_auth_gateway.audit import writer
from mcp_auth_gateway.evidence import report, signals


@pytest.fixture(autouse=True)
def _reset_chain():
    writer._chain["path"] = None
    writer._chain["last_hash"] = None
    yield


def _seed_log(path, monkeypatch):
    """Write a small mix of records: an attributed allowed SQL call touching PII,
    a denial, and a step-up challenge."""
    monkeypatch.setattr(writer.settings, "audit_log_path", str(path))
    agent_human = {"oid": "human-1", "preferred_username": "a@b.com", "azp": "agent-1", "tid": "t1"}
    writer.record(
        writer.AuditEvent(
            outcome="allowed",
            tool="postgres__list_schemas",
            correlation_id="c1",
            upstream="postgres",
            claims=agent_human,
            structure={"kind": "generic", "arg_keys": []},
        )
    )
    writer.record(
        writer.AuditEvent(
            outcome="denied",
            tool="github__delete_file",
            correlation_id="c2",
            upstream="github",
            claims=agent_human,
            reason="not permitted",
        )
    )
    writer.record(
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


def test_signals_computed(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    _seed_log(log, monkeypatch)
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


def test_bundle_attests_controls(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    _seed_log(log, monkeypatch)
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


def test_broken_chain_surfaces_in_report(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    _seed_log(log, monkeypatch)
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


def test_markdown_renders(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    _seed_log(log, monkeypatch)
    md = report.render_markdown(report.build_bundle(log, "nist-ai-rmf"))
    assert "# Agent Governance Evidence Report" in md
    assert "GOVERN 1.5" in md
    assert "Tamper-evidence:" in md
