"""Evidence generation — turn the audit log into GRC-framework-mapped evidence.

This is the pivot's product surface in miniature (ADR 007): the gateway is an
evidence *sensor*; this package maps what it captured to compliance-framework
controls, the way the audit consulting engagement and (later) the Governance
Cloud do. It reads the locked v1.0 audit record (see
``docs/architecture/audit-schema.md``) and never touches argument values.
"""
