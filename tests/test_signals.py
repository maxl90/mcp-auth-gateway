"""Evidence signals over a mixed six-record log: every ``Signals`` field is pinned."""

from __future__ import annotations

from mcp_auth_gateway.evidence import signals

_AGENT_1 = {"app_id": "app-1", "name": "analytics-agent"}
_AGENT_2 = {"app_id": "app-2", "name": "ops-agent"}
_HUMAN_1 = {"oid": "h1", "username": "a@example.com", "sub": "s1"}
_HUMAN_2 = {"oid": "h2", "username": "b@example.com", "sub": "s2"}

RECORDS = [
    {  # fully attributed, PII-shaped SQL, conformant
        "outcome": "allowed",
        "ts": "2026-07-01T10:00:00+00:00",
        "actor": {"agent": _AGENT_1, "on_behalf_of": _HUMAN_1},
        "arguments": {
            "redacted": True,
            "structure": {"kind": "sql", "tables": ["patients"], "touches_pii": True},
            "conformance": {"schema_conformant": True},
        },
    },
    {  # agent only, structured but no PII, no verdict; the earliest timestamp
        "outcome": "denied",
        "ts": "2026-07-01T09:00:00+00:00",
        "actor": {"agent": _AGENT_1, "on_behalf_of": None},
        "arguments": {"redacted": True, "structure": {"kind": "generic", "arg_keys": ["q"]}},
    },
    {  # human only, no arguments block at all
        "outcome": "step_up_required",
        "ts": "2026-07-02T08:00:00+00:00",
        "actor": {"agent": None, "on_behalf_of": _HUMAN_2},
    },
    {  # no actor, no timestamp string
        "outcome": "degraded",
        "ts": None,
        "actor": {"agent": None, "on_behalf_of": None},
        "arguments": {"redacted": True, "structure": None, "conformance": None},
    },
    {  # second agent, same first human, non-conformant; the latest timestamp
        "outcome": "manifest_drift",
        "ts": "2026-07-03T12:00:00+00:00",
        "actor": {"agent": _AGENT_2, "on_behalf_of": _HUMAN_1},
        "arguments": {"redacted": True, "conformance": {"schema_conformant": False}},
    },
    {  # fully attributed; a schema error is not a verdict
        "outcome": "allowed",
        "ts": "2026-07-02T09:00:00+00:00",
        "actor": {"agent": _AGENT_1, "on_behalf_of": _HUMAN_1},
        "arguments": {"redacted": True, "structure": None, "conformance": {"schema_error": True}},
    },
]


def test_aggregate_pins_every_field():
    s = signals.aggregate(RECORDS)
    assert s.total_records == 6
    assert s.outcomes == {
        "allowed": 2,
        "denied": 1,
        "step_up_required": 1,
        "degraded": 1,
        "manifest_drift": 1,
    }
    assert s.records_with_agent == 4
    assert s.records_with_human == 4
    assert s.records_fully_attributed == 3
    assert s.distinct_agents == 2
    assert s.distinct_humans == 2
    assert s.structured_records == 2
    assert s.pii_touch_records == 1
    assert s.schema_checked_records == 2
    assert s.schema_violation_records == 1
    assert s.first_ts == "2026-07-01T09:00:00+00:00"
    assert s.last_ts == "2026-07-03T12:00:00+00:00"
    # aggregate() never inspects a file, so the chain verdict stays unset.
    assert s.tamper_evident is False
    assert s.chain_detail is None


def test_flags_follow_the_counts():
    flags = signals.aggregate(RECORDS).flags()
    assert flags["actions_logged"] and flags["attribution_present"]
    assert flags["access_denials_logged"] and flags["stepup_enforced"]
    assert flags["availability_degradation_logged"] and flags["manifest_drift_monitored"]
    assert flags["data_sensitivity_tracked"] and flags["schema_conformance_tracked"]
    assert flags["tamper_evident"] is False


def test_empty_log_has_no_signals():
    s = signals.aggregate([])
    assert s.total_records == 0 and s.first_ts is None and s.last_ts is None
    assert not any(s.flags().values())
