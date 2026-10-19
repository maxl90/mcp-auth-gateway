"""Compute evidence signals from an audit log.

A signal is a fact the log can attest: actions are attributed to a distinct agent
and human, access denials are logged, the trail is tamper-evident. Framework
controls (see ``report``) are attested by the presence of signals. Everything
here is derived from the record shape and never inspects argument values.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit.log import as_object, iter_records
from ..audit.verify import verify_file


@dataclass
class Signals:
    """Aggregate facts computed over an audit log."""

    total_records: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    distinct_agents: int = 0
    distinct_humans: int = 0
    records_with_agent: int = 0
    records_with_human: int = 0
    records_fully_attributed: int = 0  # both agent AND human present
    pii_touch_records: int = 0
    structured_records: int = 0  # records carrying any argument structure
    schema_checked_records: int = 0  # records carrying a conformance verdict
    schema_violation_records: int = 0  # ...where the verdict was non-conformant
    tamper_evident: bool = False
    chain_detail: str | None = None
    first_ts: str | None = None
    last_ts: str | None = None

    # Derived booleans the control map references by name.
    def flags(self) -> dict[str, bool]:
        return {
            "actions_logged": self.total_records > 0,
            "attribution_present": self.records_fully_attributed > 0,
            "agent_identity_captured": self.records_with_agent > 0,
            "access_denials_logged": self.outcomes.get("denied", 0) > 0,
            "stepup_enforced": self.outcomes.get("step_up_required", 0) > 0,
            "availability_degradation_logged": self.outcomes.get("degraded", 0) > 0,
            "data_sensitivity_tracked": self.pii_touch_records > 0 or self.structured_records > 0,
            "manifest_drift_monitored": self.outcomes.get("manifest_drift", 0) > 0,
            "schema_conformance_tracked": self.schema_checked_records > 0,
            "tamper_evident": self.tamper_evident,
        }


def _count_outcome(s: Signals, rec: dict[str, Any]) -> None:
    outcome = rec.get("outcome")
    if isinstance(outcome, str):
        s.outcomes[outcome] = s.outcomes.get(outcome, 0) + 1


def _count_actor(s: Signals, rec: dict[str, Any], agents: set[str], humans: set[str]) -> None:
    actor = as_object(rec.get("actor"))
    agent = as_object(actor.get("agent"))
    human = as_object(actor.get("on_behalf_of"))
    app_id, oid = agent.get("app_id"), human.get("oid")
    if isinstance(app_id, str) and app_id:
        s.records_with_agent += 1
        agents.add(app_id)
    if isinstance(oid, str) and oid:
        s.records_with_human += 1
        humans.add(oid)
    if agent and human:
        s.records_fully_attributed += 1


def _count_structure(s: Signals, rec: dict[str, Any]) -> None:
    structure = as_object(as_object(rec.get("arguments")).get("structure"))
    if structure:
        s.structured_records += 1
        if structure.get("touches_pii"):
            s.pii_touch_records += 1


def _count_conformance(s: Signals, rec: dict[str, Any]) -> None:
    conformance = as_object(rec.get("arguments")).get("conformance")
    if isinstance(conformance, dict) and "schema_conformant" in conformance:
        s.schema_checked_records += 1
        if conformance.get("schema_conformant") is False:
            s.schema_violation_records += 1


def _track_window(s: Signals, rec: dict[str, Any]) -> None:
    ts = rec.get("ts")
    if isinstance(ts, str):
        if s.first_ts is None or ts < s.first_ts:
            s.first_ts = ts
        if s.last_ts is None or ts > s.last_ts:
            s.last_ts = ts


def aggregate(records: Iterable[dict[str, Any]]) -> Signals:
    """Aggregate signals over already-parsed records; no file I/O and no chain check.

    The seam exists so an attestation pack can aggregate a windowed subset while the
    chain verdict is computed over the full log (a slice can never chain-verify).
    """
    s = Signals()
    agents: set[str] = set()
    humans: set[str] = set()
    for rec in records:
        s.total_records += 1
        _count_outcome(s, rec)
        _count_actor(s, rec, agents, humans)
        _count_structure(s, rec)
        _count_conformance(s, rec)
        _track_window(s, rec)
    s.distinct_agents = len(agents)
    s.distinct_humans = len(humans)
    return s


def compute(path: str | Path) -> Signals:
    """Walk the audit log once, aggregate the signals, and verify the chain."""
    p = Path(path)
    s = aggregate(rec for _, rec in iter_records(p))
    if not p.exists():
        # An absent log attests nothing: vacuous chain intactness must not light the flag.
        return s
    chain = verify_file(p)
    s.tamper_evident = chain.ok
    s.chain_detail = chain.detail
    return s
