"""Compute evidence *signals* from an audit log.

A signal is a fact the audit log can attest — "actions are attributed to a
distinct agent and human", "access denials are logged", "the trail is
tamper-evident". Framework controls (see ``report``) are attested by the
presence of one or more signals. Everything here is derived from the locked
v1.0 record and never inspects argument values.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

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


def iter_records(path: str | Path) -> Iterator[dict]:
    """Yield parsed records from a JSONL audit log, skipping blank/corrupt lines
    (same tolerance as the exporters)."""
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except ValueError:
            continue


def aggregate(records: Iterable[dict]) -> Signals:
    """Aggregate signals over already-parsed records.

    No file I/O and no chain check — the caller owns those. This seam exists so
    a *windowed* view (attestation packs) can aggregate a record subset while
    the chain verdict is still computed over the full log; a sliced log can
    never chain-verify on its own (its first ``prev_hash`` isn't genesis).
    """
    s = Signals()
    agents: set[str] = set()
    humans: set[str] = set()
    for rec in records:
        s.total_records += 1

        outcome = rec.get("outcome")
        if isinstance(outcome, str):
            s.outcomes[outcome] = s.outcomes.get(outcome, 0) + 1

        actor = rec.get("actor") or {}
        agent = actor.get("agent") or None
        human = actor.get("on_behalf_of") or None
        if agent and agent.get("app_id"):
            s.records_with_agent += 1
            agents.add(agent["app_id"])
        if human and human.get("oid"):
            s.records_with_human += 1
            humans.add(human["oid"])
        if agent and human:
            s.records_fully_attributed += 1

        structure = (rec.get("arguments") or {}).get("structure")
        if structure:
            s.structured_records += 1
            if structure.get("touches_pii"):
                s.pii_touch_records += 1

        conformance = (rec.get("arguments") or {}).get("conformance")
        if isinstance(conformance, dict) and "schema_conformant" in conformance:
            s.schema_checked_records += 1
            if conformance.get("schema_conformant") is False:
                s.schema_violation_records += 1

        ts = rec.get("ts")
        if isinstance(ts, str):
            if s.first_ts is None or ts < s.first_ts:
                s.first_ts = ts
            if s.last_ts is None or ts > s.last_ts:
                s.last_ts = ts

    s.distinct_agents = len(agents)
    s.distinct_humans = len(humans)
    return s


def compute(path: str | Path) -> Signals:
    """Walk the audit log once, aggregate the signals, and verify the chain."""
    p = Path(path)
    s = aggregate(iter_records(p))
    if not p.exists():
        # An absent log attests nothing — vacuous chain "intactness" must not
        # light the tamper_evident flag (preserves pre-refactor semantics).
        return s
    chain = verify_file(p)
    s.tamper_evident = chain.ok
    s.chain_detail = chain.detail
    return s
