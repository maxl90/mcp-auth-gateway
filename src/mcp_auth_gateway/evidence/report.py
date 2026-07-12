"""Generate a GRC-framework-mapped evidence report from the audit log.

Reads the locked v1.0 audit log, computes evidence signals, maps them to a
framework's controls, and renders a human-readable Markdown report plus a
machine-readable JSON bundle. This is the audit-engagement deliverable in
miniature and a preview of the Governance Cloud's output (ADR 007).

CLI (installed as ``mcp-auth-gateway-evidence-report``)::

    mcp-auth-gateway-evidence-report [audit_path] [framework] [out.md]
    # audit_path defaults to AUDIT_LOG_PATH; framework defaults to nist-ai-rmf
    # (a built-in name or a path to a custom YAML map); out.md → stdout if omitted.
    # A JSON bundle is written next to out.md (out.json) when out is given.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

from ..config import settings
from . import frameworks
from . import signals as signals_mod

# A control is ATTESTED when all its signals are present, PARTIAL when some are,
# NO EVIDENCE when none are.
_ATTESTED, _PARTIAL, _NONE = "ATTESTED", "PARTIAL", "NO EVIDENCE"


def _status(control_signals: list[str], flags: dict[str, bool]) -> tuple[str, list[str], list[str]]:
    present = [s for s in control_signals if flags.get(s)]
    missing = [s for s in control_signals if not flags.get(s)]
    if not present:
        return _NONE, present, missing
    if not missing:
        return _ATTESTED, present, missing
    return _PARTIAL, present, missing


def build_bundle_from(
    sig: signals_mod.Signals, framework: str, audit_path: str | Path
) -> dict:
    """Assemble the evidence bundle from already-computed signals.

    Seam for callers that aggregate a *windowed* record subset (attestation
    packs) while carrying the full-log chain verdict on ``sig``.
    """
    fw = frameworks.load(framework)
    flags = sig.flags()

    controls = []
    for c in fw["controls"]:
        status, present, missing = _status(c.get("signals", []), flags)
        controls.append(
            {
                "id": c["id"],
                "title": c["title"],
                "status": status,
                "evidence": c.get("evidence"),
                "signals_present": present,
                "signals_missing": missing,
            }
        )

    return {
        "framework": fw.get("framework", framework),
        "disclaimer": fw.get("disclaimer"),
        "coverage": {
            "audit_path": str(audit_path),
            "records": sig.total_records,
            "from": sig.first_ts,
            "to": sig.last_ts,
            "tamper_evident": sig.tamper_evident,
        },
        "signals": {
            "total_records": sig.total_records,
            "outcomes": sig.outcomes,
            "distinct_agents": sig.distinct_agents,
            "distinct_humans": sig.distinct_humans,
            "records_fully_attributed": sig.records_fully_attributed,
            "pii_touch_records": sig.pii_touch_records,
            "flags": flags,
        },
        "controls": controls,
    }


def build_bundle(audit_path: str | Path, framework: str = "nist-ai-rmf") -> dict:
    """Compute the machine-readable evidence bundle (signals + per-control status)."""
    return build_bundle_from(signals_mod.compute(audit_path), framework, audit_path)


def render_markdown(bundle: dict) -> str:
    """Render the evidence bundle as a Markdown report."""
    cov = bundle["coverage"]
    sig = bundle["signals"]
    lines: list[str] = []
    lines.append(f"# Agent Governance Evidence Report — {bundle['framework']}")
    lines.append("")
    tamper = (
        "OK - intact (hash-chain verified)"
        if cov["tamper_evident"]
        else "BROKEN - see verify-audit"
    )
    lines.append(f"- **Audit source:** `{cov['audit_path']}`")
    lines.append(f"- **Records:** {cov['records']}  |  **Window:** {cov['from']} -> {cov['to']}")
    lines.append(f"- **Tamper-evidence:** {tamper}")
    lines.append("")
    if bundle.get("disclaimer"):
        lines.append(f"> {bundle['disclaimer']}")
        lines.append("")

    lines.append("## Signals observed")
    lines.append("")
    lines.append(f"- Total agent actions logged: **{sig['total_records']}**")
    lines.append(f"- Outcomes: {sig['outcomes']}")
    lines.append(
        f"- Distinct agents: **{sig['distinct_agents']}**  ·  "
        f"distinct humans: **{sig['distinct_humans']}**  ·  "
        f"fully attributed (agent + human): **{sig['records_fully_attributed']}**"
    )
    lines.append(f"- Actions touching PII-shaped columns: **{sig['pii_touch_records']}**")
    lines.append("")

    lines.append("## Control coverage")
    lines.append("")
    lines.append("| Control | Status | Evidence |")
    lines.append("|---|---|---|")
    for c in bundle["controls"]:
        lines.append(f"| **{c['id']}** — {c['title']} | {c['status']} | {c['evidence']} |")
    lines.append("")

    attested = sum(1 for c in bundle["controls"] if c["status"] == _ATTESTED)
    lines.append(
        f"_{attested} of {len(bundle['controls'])} controls fully attested by the "
        "current audit evidence._"
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Console entry point."""
    # The report contains typographic unicode (em dashes); make stdout UTF-8 so a
    # cp1252 Windows console doesn't mangle or crash on it. No-op where already UTF-8.
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")

    audit_path = sys.argv[1] if len(sys.argv) > 1 else settings.audit_log_path
    framework = sys.argv[2] if len(sys.argv) > 2 else "nist-ai-rmf"
    out = sys.argv[3] if len(sys.argv) > 3 else None

    bundle = build_bundle(audit_path, framework)
    md = render_markdown(bundle)

    if out:
        Path(out).write_text(md, encoding="utf-8")
        json_out = Path(out).with_suffix(".json")
        json_out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"wrote {out} and {json_out}")
    else:
        print(md)


if __name__ == "__main__":
    main()
