"""OCSF export format (backlog C3) + EU AI Act / SOC 2 framework maps (C2)."""

from __future__ import annotations

import json

import pytest

from mcp_auth_gateway.audit import export, writer
from mcp_auth_gateway.evidence import frameworks, report


@pytest.fixture(autouse=True)
def _reset_chain():
    writer._chain["path"] = None
    writer._chain["last_hash"] = None
    yield


def _seed(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setattr(writer.settings, "audit_log_path", str(log))
    claims = {"oid": "u1", "preferred_username": "a@b.com", "tid": "t1",
              "azp": "agent-1", "app_displayname": "Agent One"}
    writer.record(
        outcome="allowed", tool="postgres__execute_sql", correlation_id="c1",
        upstream="postgres", claims=claims,
        structure={"kind": "sql", "tables": ["patients"], "touches_pii": True,
                   "pii_columns": ["mrn"], "columns": ["mrn"], "statement_types": ["SELECT"]},
        manifest={"sha256": "aa" * 32},
        conformance={"schema_conformant": True},
        channel={"dpop_jkt": "jkt-1", "edge_client_cert_serial": "01"},
    )
    writer.record(
        outcome="denied", tool="postgres__delete_table", correlation_id="c2",
        upstream="postgres", claims=claims, reason="tool not permitted",
    )
    writer.record(
        outcome="manifest_drift", tool="postgres__execute_sql", correlation_id="c3",
        upstream="postgres", claims=claims,
        reason="tool manifest changed since the pinned baseline",
        manifest={"sha256": "bb" * 32, "previous_sha256": "aa" * 32},
    )
    writer.record(
        outcome="step_up_required", tool="postgres__execute_sql", correlation_id="c4",
        upstream="postgres", claims=claims, reason="step-up not satisfied: missing",
    )
    return log


# --- OCSF export --------------------------------------------------------------


def test_ocsf_shape_and_attribution(tmp_path, monkeypatch):
    log = _seed(tmp_path, monkeypatch)
    events = [json.loads(ln) for ln in export.export_lines(log, "ocsf")]
    assert len(events) == 4
    e = events[0]
    assert (e["class_uid"], e["category_uid"], e["type_uid"]) == (6003, 6, 600399)
    assert isinstance(e["time"], int) and e["time"] > 1_500_000_000_000  # epoch ms
    # The attribution split maps to OCSF: agent = actor app, human = actor.user.
    assert e["actor"]["app_uid"] == "agent-1"
    assert e["actor"]["app_name"] == "Agent One"
    assert e["actor"]["user"] == {"uid": "u1", "name": "a@b.com"}
    assert e["api"]["operation"] == "postgres__execute_sql"
    assert e["api"]["service"]["name"] == "postgres"
    assert e["metadata"]["correlation_uid"] == "c1"


def test_ocsf_status_mapping(tmp_path, monkeypatch):
    log = _seed(tmp_path, monkeypatch)
    events = [json.loads(ln) for ln in export.export_lines(log, "ocsf")]
    by_corr = {e["metadata"]["correlation_uid"]: e for e in events}
    assert (by_corr["c1"]["status_id"], by_corr["c1"]["status"]) == (1, "Success")
    assert by_corr["c2"]["status_id"] == 2  # denied
    assert by_corr["c4"]["status_id"] == 2  # step_up_required
    assert by_corr["c3"]["status_id"] == 99  # manifest_drift: observation, not outcome
    assert by_corr["c2"]["status_detail"] == "tool not permitted"


def test_ocsf_evidence_survives_in_unmapped(tmp_path, monkeypatch):
    """Nothing the audit record carries may be dropped by the format change."""
    log = _seed(tmp_path, monkeypatch)
    e = json.loads(next(iter(export.export_lines(log, "ocsf"))))
    u = e["unmapped"]
    assert u["manifest"] == {"sha256": "aa" * 32}
    assert u["channel"] == {"dpop_jkt": "jkt-1", "edge_client_cert_serial": "01"}
    assert u["arguments_structure"]["touches_pii"] is True
    assert u["arguments_conformance"] == {"schema_conformant": True}
    assert u["integrity"]["record_hash"]
    assert u["tenant_id"] == "t1"
    assert u["arguments_redacted"] is True


def test_sentinel_remains_the_default(tmp_path, monkeypatch):
    log = _seed(tmp_path, monkeypatch)
    row = json.loads(next(iter(export.export_lines(log))))
    assert "TimeGenerated" in row and "class_uid" not in row


# --- framework maps -----------------------------------------------------------


def test_new_frameworks_load_and_reference_real_flags():
    from mcp_auth_gateway.evidence.signals import Signals

    known_flags = set(Signals().flags())
    for name in ("eu-ai-act", "soc2", "nist-ai-rmf"):
        fw = frameworks.load(name)
        assert fw["controls"], name
        for control in fw["controls"]:
            unknown = set(control["signals"]) - known_flags
            assert not unknown, f"{name} {control['id']} names unknown signals: {unknown}"


@pytest.mark.parametrize("name", ["eu-ai-act", "soc2"])
def test_bundle_attests_from_seeded_log(tmp_path, monkeypatch, name):
    log = _seed(tmp_path, monkeypatch)
    bundle = report.build_bundle(log, name)
    statuses = {c["id"]: c["status"] for c in bundle["controls"]}
    assert all(s in ("ATTESTED", "PARTIAL", "NO EVIDENCE") for s in statuses.values())
    # The seeded log carries drift + denials + attribution, so change-detection
    # and access-control controls must not come back empty.
    if name == "soc2":
        assert statuses["CC8.1"] == "ATTESTED"  # manifest_drift_monitored
        assert statuses["CC6.3"] == "ATTESTED"  # access_denials_logged
    if name == "eu-ai-act":
        assert statuses["Art. 12(1)"] == "ATTESTED"  # logged + tamper-evident
    assert bundle["disclaimer"]  # never ship a framework map without one


def test_markdown_renders_for_new_frameworks(tmp_path, monkeypatch):
    log = _seed(tmp_path, monkeypatch)
    for name in ("eu-ai-act", "soc2"):
        md = report.render_markdown(report.build_bundle(log, name))
        assert "Control coverage" in md and "| **" in md
