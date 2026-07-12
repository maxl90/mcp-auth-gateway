"""Framework control maps: which audit *signals* attest which GRC control.

A control map is data, not code — each control names the ``signals`` (see
``signals.Signals.flags``) whose presence in the audit log provides evidence
toward it. Built-in **starters** ship for NIST AI RMF 1.0, the EU AI Act
(Regulation (EU) 2024/1689, high-risk lens), and SOC 2 (2017 TSC); the exact
control text and sufficiency must be refined with counsel per engagement.
``report`` can also load a custom map (same shape) so the consulting
engagement tailors it per client — the rich multi-framework engine remains the
paid control plane's job; these starters stay deliberately basic (ADR 003/007).

Framing note: a control is *attested by evidence* here, not *complied with* —
the audit trail is one input to a control's assessment, not the whole judgment.
"""

from __future__ import annotations

# Each control: id, title, the signal flags that evidence it, and a short note
# on what the audit log actually shows for that control.
NIST_AI_RMF: dict = {
    "framework": "NIST AI RMF 1.0",
    "disclaimer": (
        "Starter mapping. Subcategory intent is paraphrased; validate control "
        "IDs/text and sufficiency with your compliance function. The audit trail "
        "is one evidence input, not a compliance determination."
    ),
    "controls": [
        {
            "id": "GOVERN 1.5",
            "title": "Roles, responsibilities, and ongoing monitoring are defined",
            "signals": ["actions_logged", "attribution_present"],
            "evidence": (
                "Every agent tool invocation is logged and attributed to a specific "
                "agent identity acting on behalf of a specific human — establishing "
                "the accountability record monitoring depends on."
            ),
        },
        {
            "id": "GOVERN 4.3",
            "title": "Practices enable incident identification and information sharing",
            "signals": ["actions_logged", "access_denials_logged", "tamper_evident"],
            "evidence": (
                "Denied and challenged actions are recorded with correlation IDs; the "
                "trail is hash-chained (tamper-evident), so incident forensics rest on "
                "an integrity-verifiable record."
            ),
        },
        {
            "id": "MEASURE 2.7",
            "title": "AI system security and resilience are evaluated and documented",
            "signals": ["access_denials_logged", "stepup_enforced"],
            "evidence": (
                "Access-control denials and step-up (RFC 9470) challenges on "
                "destructive actions are logged, documenting that authorization and "
                "strong-auth controls are exercised, not just configured."
            ),
        },
        {
            "id": "MEASURE 2.10",
            "title": "Privacy risk of the AI system is examined and documented",
            "signals": ["data_sensitivity_tracked"],
            "evidence": (
                "Each call records value-free structural metadata — which tables and "
                "columns were touched and whether a PII-shaped column was involved — "
                "so privacy exposure is evidenced without the data itself leaving the "
                "boundary."
            ),
        },
        {
            "id": "MANAGE 4.1",
            "title": "Post-deployment monitoring is implemented",
            "signals": ["actions_logged", "agent_identity_captured", "tamper_evident"],
            "evidence": (
                "A continuous, agent-attributed, tamper-evident action log is the "
                "post-deployment monitoring substrate for deployed agents."
            ),
        },
    ],
}


EU_AI_ACT: dict = {
    "framework": "EU AI Act (Regulation (EU) 2024/1689) — high-risk lens",
    "disclaimer": (
        "Starter mapping, not legal advice. Article intent is paraphrased; "
        "applicability (is the system high-risk?), retention periods, and "
        "sufficiency must be determined with counsel. The audit trail is one "
        "evidence input, not a compliance determination."
    ),
    "controls": [
        {
            "id": "Art. 12(1)",
            "title": "Record-keeping — automatic recording of events (logs) over "
            "the system lifetime",
            "signals": ["actions_logged", "tamper_evident"],
            "evidence": (
                "Every agent tool invocation is automatically recorded as a "
                "structured event, and the log is hash-chained — the record's own "
                "integrity is verifiable, not asserted."
            ),
        },
        {
            "id": "Art. 14(4)",
            "title": "Human oversight — persons can understand, monitor, and "
            "intervene in operation",
            "signals": ["attribution_present", "stepup_enforced"],
            "evidence": (
                "Each action names the agent AND the human it acted on behalf of "
                "(oversight requires knowing who is behind an action), and "
                "destructive operations demand fresh strong human authentication "
                "before proceeding (RFC 9470 step-up)."
            ),
        },
        {
            "id": "Art. 15(5)",
            "title": "Cybersecurity — resilience against attempts to alter use, "
            "outputs, or performance",
            "signals": ["manifest_drift_monitored", "tamper_evident", "schema_conformance_tracked"],
            "evidence": (
                "Tool-definition drift (the poisoning/rug-pull vector) raises a "
                "first-class audit event with before/after hashes; call arguments "
                "are checked against the published contract; the evidence trail "
                "itself is tamper-evident."
            ),
        },
        {
            "id": "Art. 26(5)",
            "title": "Deployer obligations — monitor operation and keep the "
            "automatically generated logs",
            "signals": ["actions_logged", "agent_identity_captured"],
            "evidence": (
                "A continuous, agent-identified action log exists in a locked, "
                "SIEM-exportable schema — the artifact a deployer must retain and "
                "produce."
            ),
        },
        {
            "id": "Art. 72",
            "title": "Post-market monitoring — systematically collect and review operation data",
            "signals": [
                "actions_logged",
                "access_denials_logged",
                "availability_degradation_logged",
            ],
            "evidence": (
                "Allowed, denied, challenged, and degraded outcomes are all "
                "recorded with correlation IDs — the operational dataset "
                "post-market monitoring reviews."
            ),
        },
    ],
}


SOC2: dict = {
    "framework": "SOC 2 — 2017 Trust Services Criteria (Security)",
    "disclaimer": (
        "Starter mapping, not an attestation. Criteria are paraphrased; a SOC 2 "
        "examination weighs many evidence sources — this shows what the agent "
        "audit trail contributes, determined with your auditor."
    ),
    "controls": [
        {
            "id": "CC6.1",
            "title": "Logical access security — identities are authenticated and "
            "access is authorized",
            "signals": ["actions_logged", "agent_identity_captured", "access_denials_logged"],
            "evidence": (
                "Every call is tied to a validated identity (agent + human), and "
                "unauthorized attempts are denied and logged — authentication and "
                "authorization demonstrably operate, not just exist."
            ),
        },
        {
            "id": "CC6.3",
            "title": "Access is role-based and least-privilege",
            "signals": ["access_denials_logged"],
            "evidence": (
                "Tool-level RBAC denials in the log evidence that group-based "
                "least-privilege boundaries are enforced at call time."
            ),
        },
        {
            "id": "CC7.2",
            "title": "Systems are monitored for anomalies and security events",
            "signals": ["actions_logged", "manifest_drift_monitored", "schema_conformance_tracked"],
            "evidence": (
                "The trail captures anomaly signals no platform logs natively: "
                "tool-definition drift events and per-call schema-conformance "
                "verdicts, alongside the full action stream."
            ),
        },
        {
            "id": "CC7.3",
            "title": "Security events are evaluated to determine impact",
            "signals": ["tamper_evident", "attribution_present"],
            "evidence": (
                "Incident evaluation rests on an integrity-verifiable record that "
                "attributes each action to the correct actor (agent vs. human) — "
                "forensics point at the right principal."
            ),
        },
        {
            "id": "CC8.1",
            "title": "Changes are authorized, tracked, and detected",
            "signals": ["manifest_drift_monitored"],
            "evidence": (
                "Unauthorized change to a tool's definition (name/description/"
                "schema) is detected against a pinned baseline and logged with "
                "old/new hashes — change detection for the agent tool surface."
            ),
        },
    ],
}


BUILT_IN = {"nist-ai-rmf": NIST_AI_RMF, "eu-ai-act": EU_AI_ACT, "soc2": SOC2}


def load(name_or_path: str) -> dict:
    """Return a built-in control map by name, or load one from a YAML path."""
    key = name_or_path.lower()
    if key in BUILT_IN:
        return BUILT_IN[key]
    from pathlib import Path

    import yaml  # local import: only needed for custom maps

    doc = yaml.safe_load(Path(name_or_path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "controls" not in doc:
        raise ValueError("framework map must be a mapping with a 'controls' list")
    return doc
