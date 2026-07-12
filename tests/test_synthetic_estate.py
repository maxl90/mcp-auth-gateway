"""The synthetic estate generator (demo/synthetic_estate.py) must produce logs
indistinguishable in shape from real gateway output: chains that the real
verifier accepts (except the deliberate tamper), locked-schema records, a
coherent manifest-drift story, and — the invariant that never relaxes — no
argument values anywhere."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_auth_gateway.audit.verify import verify_file
from mcp_auth_gateway.audit.writer import SCHEMA_VERSION

SCRIPT = Path(__file__).resolve().parent.parent / "demo" / "synthetic_estate.py"
END = "2026-07-07T00:00:00+00:00"
OUTCOMES = {"allowed", "denied", "degraded", "step_up_required", "manifest_drift"}


def _generate(out: Path, *extra: str) -> dict:
    subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(out), "--seed", "7", "--end", END,
         "--scale", "0.2", *extra],
        check=True, capture_output=True, text=True,
    )
    return json.loads((out / "estate.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def estate(tmp_path_factory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("estate")
    return out, _generate(out)


def _records(out: Path, label: str) -> list[dict]:
    log = out / label / "audit.log"
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_chains_verify_with_real_cli_logic(estate):
    out, summary = estate
    by_label = {s["label"]: s for s in summary["sources"]}

    for label in ("prod-us", "prod-eu"):
        result = verify_file(out / label / "audit.log")
        assert result.ok, f"{label}: {result.detail}"
        assert result.records == by_label[label]["records"]

    # dev carries the deliberate break, exactly where the summary says.
    result = verify_file(out / "dev" / "audit.log")
    assert not result.ok
    assert result.broken_line == by_label["dev"]["tampered_line"]


def test_no_tamper_leaves_every_chain_intact(tmp_path):
    summary = _generate(tmp_path, "--no-tamper")
    for source in summary["sources"]:
        assert source["tampered_line"] is None
        assert verify_file(tmp_path / source["label"] / "audit.log").ok


def test_deterministic_for_same_seed(estate, tmp_path):
    out, _ = estate
    _generate(tmp_path)
    for label in ("prod-us", "prod-eu", "dev"):
        assert (tmp_path / label / "audit.log").read_bytes() == (out / label / "audit.log").read_bytes()


def test_records_match_the_locked_schema(estate):
    out, summary = estate
    saw_app_only = saw_channel = saw_step_up = saw_denied = False
    for source in summary["sources"]:
        for rec in _records(out, source["label"]):
            assert rec["schema_version"] == SCHEMA_VERSION
            assert rec["outcome"] in OUTCOMES
            assert rec["tenant_id"] == summary["tenant_id"]
            assert rec["arguments"]["redacted"] is True
            agent = rec["actor"]["agent"]
            assert agent and agent["app_id"]
            if rec["actor"]["on_behalf_of"] is None:
                saw_app_only = True
            if rec["channel"]:
                assert set(rec["channel"]) == {"edge_client_cert_serial", "edge_client_cert_dn", "dpop_jkt"}
                saw_channel = True
            saw_step_up = saw_step_up or rec["outcome"] == "step_up_required"
            saw_denied = saw_denied or rec["outcome"] == "denied"
            # Aggregation-mode records namespace the tool and set upstream;
            # single-upstream (dev) records do neither.
            if rec["outcome"] not in ("degraded",) and rec["tool"]:
                if source["mode"] == "aggregate":
                    assert rec["upstream"] and rec["tool"].startswith(f"{rec['upstream']}__")
                else:
                    assert rec["upstream"] is None and "__" not in rec["tool"]
    assert saw_app_only and saw_channel and saw_step_up and saw_denied


def test_manifest_drift_story_is_coherent(estate):
    out, _ = estate
    for label, tool in (("prod-eu", "jira__transition_issue"), ("dev", "execute_sql")):
        recs = _records(out, label)
        drift_idx = [i for i, r in enumerate(recs) if r["outcome"] == "manifest_drift"]
        assert len(drift_idx) == 1
        drift = recs[drift_idx[0]]
        assert drift["tool"] == tool
        assert drift["manifest"]["previous_sha256"] != drift["manifest"]["sha256"]

        stamps_before = {r["manifest"]["sha256"] for r in recs[: drift_idx[0]]
                         if r.get("tool") == tool and r.get("manifest")}
        stamps_after = {r["manifest"]["sha256"] for r in recs[drift_idx[0] + 1:]
                        if r.get("tool") == tool and r["outcome"] != "manifest_drift" and r.get("manifest")}
        assert stamps_before <= {drift["manifest"]["previous_sha256"]}
        assert stamps_after <= {drift["manifest"]["sha256"]}

        baseline = json.loads((out / label / "manifest-baseline.json").read_text(encoding="utf-8"))
        assert baseline["tools"][tool]["sha256"] == drift["manifest"]["sha256"]


def test_no_argument_values_anywhere(estate):
    """The generator has no values to leak by construction — assert it stays
    that way: no SQL text, no argument payloads, only the value-free shapes."""
    out, summary = estate
    for source in summary["sources"]:
        raw = (out / source["label"] / "audit.log").read_text(encoding="utf-8")
        for marker in ("FROM ", "WHERE ", "INSERT INTO", "values"):
            assert marker not in raw
        for rec in _records(out, source["label"]):
            structure = rec["arguments"]["structure"]
            if structure and structure["kind"] == "sql" and not structure.get("parse_error"):
                assert set(structure) == {"kind", "statement_types", "tables", "columns", "pii_columns", "touches_pii"}
            if structure and structure["kind"] == "generic":
                assert set(structure) == {"kind", "arg_keys"}
