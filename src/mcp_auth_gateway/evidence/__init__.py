"""Evidence: map what the audit log attests to compliance-framework controls.

The gateway is a sensor; this package reads its records (never argument values),
computes signals such as "actions are attributed" or "denials are logged", maps
them to NIST AI RMF, EU AI Act and SOC 2 controls, and renders reports and
signed attestation packs.
"""
